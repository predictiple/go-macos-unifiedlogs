// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

type formatAndMessage struct {
	formatter string
	message   string
}

// firehoseMessageRegex matches C/printf format specifiers (from unified_log.rs).
var firehoseMessageRegex = regexp.MustCompile(`(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*)?)?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*)?)?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))`)

var (
	floatTypes  = []string{"f", "F", "e", "E", "g", "G"}
	intTypes    = []string{"d", "D", "i", "u"}
	hexTypes    = []string{"x", "X", "a", "A", "p"}
	octalTypes  = []string{"o", "O"}
	errorTypes  = []string{"m"}
	stringTypes = []string{"c", "s", "@", "S", "C", "P"}
)

type padding int

const (
	paddingZero padding = iota
	paddingSpace
)

type alignment int

const (
	alignmentLeft alignment = iota
	alignmentRight
)

type numberFormat int

const (
	numberFormatNone numberFormat = iota
	numberFormatOctal
	numberFormatHex
	numberFormatDecimal
)

type messageFormatters struct {
	// If non-nil then message item is a string
	itemString *string
	// If non-nil then message item is an integer
	itemNumber *int64
	// If non-nil then message item is a float
	itemFloat  *float64
	precision  *int
	width      int
	itemFormat string
	plusMinus  bool
	hashtag    bool
	// Determines direction padding will be applied to
	alignment alignment
	message   string
	// Determines itemNumber format (Decimal, Octal, or Hex)
	numberFormat numberFormat
	// If width value is not 0. Then padding of Spaces or Zeros will be added (if required)
	padding padding
}

// FormatFirehoseLogMessage formats the Unified Log message entry based on the parsed log items.
// Formatting follows the C lang printf formatting process.
func FormatFirehoseLogMessage(formatString string, itemMessage []FirehoseItemType, messageRe *regexp.Regexp) string {
	logMessage := formatString
	famVec := []formatAndMessage{}

	// Some log entries may be completely empty (no format string or message data)
	if logMessage == "" && len(itemMessage) == 0 {
		return ""
	}
	if logMessage == "" {
		return itemMessage[0].MessageStrings
	}

	results := messageRe.FindAllString(logMessage, -1)

	itemIndex := 0
	for _, formatter := range results {
		// Skip literal "% " values
		if strings.HasPrefix(formatter, "% ") {
			continue
		}

		formatAndMessage := formatAndMessage{}

		// %% is literal %
		if formatter == "%%" {
			formatAndMessage.formatter = formatter
			formatAndMessage.message = "%"
			famVec = append(famVec, formatAndMessage)
			continue
		}

		// Sometimes the log message does not have all of the message strings
		// Apple labels them: "<decode: missing data>"
		if itemIndex >= len(itemMessage) {
			formatAndMessage.formatter = formatter
			formatAndMessage.message = "<Missing message data>"
			famVec = append(famVec, formatAndMessage)
			continue
		}

		formattedLogMessage := itemMessage[itemIndex].MessageStrings
		formatterString := formatter

		// If the formatter does not have a type then the entry is the literal format
		if strings.HasPrefix(formatterString, "%{") && strings.HasSuffix(formatterString, "}") {
			formatAndMessage.formatter = formatterString
			formatAndMessage.message = formatterString
			famVec = append(famVec, formatAndMessage)
			continue
		}

		precisionItems := []uint8{0x10, 0x12}
		// If the item message was a precision type increment to actual value
		if itemIndex < len(itemMessage) && slices.Contains(precisionItems, itemMessage[itemIndex].ItemType) {
			itemIndex++
		}
		// Also seen number type value 0 also used for dynamic width/precision value
		dynamicPrecisionValue := uint8(0x0)
		if itemIndex < len(itemMessage) && itemMessage[itemIndex].ItemType == dynamicPrecisionValue &&
			itemMessage[itemIndex].ItemSize == 0 &&
			strings.Contains(formatterString, "%*") {
			itemIndex++
		}

		if itemIndex >= len(itemMessage) {
			formatAndMessage.formatter = formatter
			formatAndMessage.message = "<Missing message data>"
			famVec = append(famVec, formatAndMessage)
			continue
		}

		privateStrings := []uint8{0x1, 0x21, 0x31, 0x41}
		privateNumber := uint8(0x1)
		privateMessage := uint16(0x8000)
		if strings.HasPrefix(formatterString, "%{") {
			// If item type is [0x1, 0x21, 0x31, 0x41] and the value is zero. Its appears to be
			// a private string
			if (slices.Contains(privateStrings, itemMessage[itemIndex].ItemType) &&
				itemMessage[itemIndex].MessageStrings == "" &&
				itemMessage[itemIndex].ItemSize == 0) ||
				(itemMessage[itemIndex].ItemType == privateNumber &&
					itemMessage[itemIndex].ItemSize == privateMessage) {
				formattedLogMessage = "<private>"
			} else {
				formatted, err := parseTypeFormatter(formatterString, itemMessage, itemMessage[itemIndex].ItemType, itemIndex)
				if err != nil {
					logger.Printf("[macos-unifiedlogs] Failed to format message type ex: public/private: %v", err)
				} else {
					formattedLogMessage = formatted
				}
			}
		} else {
			// If item type is [0x1, 0x21, 0x31, 0x41] and the size is zero (or 0x8000 for 0x1).
			// Its appears to be a literal <private> string
			if (slices.Contains(privateStrings, itemMessage[itemIndex].ItemType) &&
				itemMessage[itemIndex].MessageStrings == "" &&
				itemMessage[itemIndex].ItemSize == 0) ||
				(itemMessage[itemIndex].ItemType == privateNumber &&
					itemMessage[itemIndex].ItemSize == privateMessage) {
				formattedLogMessage = "<private>"
			} else {
				formatted, err := parseFormatter(formatterString, itemMessage, itemMessage[itemIndex].ItemType, itemIndex)
				if err != nil {
					logger.Printf("[macos-unifiedlogs] Failed to format message: %v", err)
				} else {
					formattedLogMessage = formatted
				}
			}
		}

		itemIndex++
		formatAndMessage.formatter = formatter
		formatAndMessage.message = formattedLogMessage
		famVec = append(famVec, formatAndMessage)
	}

	logMessageVec := []string{}
	for _, values := range famVec {
		// Split the values by printf formatter
		// We have to do this instead of using replace because our replacement string may also
		// contain a printf formatter
		idx := strings.Index(logMessage, values.formatter)
		if idx >= 0 {
			messagePart := logMessage[:idx]
			remainingMessage := logMessage[idx+len(values.formatter):]
			logMessageVec = append(logMessageVec, messagePart)
			logMessageVec = append(logMessageVec, values.message)
			logMessage = remainingMessage
		} else {
			logger.Printf("Failed to split log message (%s) by printf formatter: %s", logMessage, values.formatter)
		}
	}
	logMessageVec = append(logMessageVec, logMessage)
	return strings.Join(logMessageVec, "")
}

// parseFormatter formats strings based on C printf formats. Parse format specification.
// parse_formatter in the Rust source.
func parseFormatter(formatter string, messageValue []FirehoseItemType, itemType uint8, itemIndex int) (string, error) {
	index := itemIndex
	message := ""

	if index < len(messageValue) {
		message = messageValue[index].MessageStrings
	}

	precisionItems := []uint8{0x10, 0x12}
	precisionValue := 0
	if slices.Contains(precisionItems, itemType) {
		if index >= len(messageValue) {
			return "", ErrFail
		}
		precisionValue = int(messageValue[index].ItemSize)
		index++

		if index >= len(messageValue) {
			logger.Printf("[macos-unifiedlogs] Index now greater than messages array. This should not have happened. Index: %d. Message Array len: %d", index, len(messageValue))
			return "Failed to format string due index length", nil
		}
	}

	if index < len(messageValue) {
		message = messageValue[index].MessageStrings
	}

	numberItemType := []uint8{0x0, 0x1, 0x2}

	// If the message formatter is expects a string/character and the message string is a
	// number type. Try to convert to a character/string
	if index < len(messageValue) && strings.HasSuffix(strings.ToLower(formatter), "c") &&
		slices.Contains(numberItemType, messageValue[index].ItemType) {
		charResults, err := strconv.ParseUint(messageValue[index].MessageStrings, 10, 32)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse number item to char string: %v", err)
			return "Failed to parse number item to char string", nil
		}
		message = string(rune(uint8(charResults)))
	}

	leftJustify := false
	hashtag := false
	padZero := false
	plusMinus := false
	widthIndex := 1
loop:
	for i, formatValues := range formatter {
		if i == 0 {
			continue
		}

		switch formatValues {
		case '-':
			leftJustify = true
		case '+':
			plusMinus = true
		case '#':
			hashtag = true
		case '0':
			padZero = true
		default:
			widthIndex = i
			break loop
		}
	}

	formatterMessage := ""
	if widthIndex <= len(formatter) {
		formatterMessage = formatter[widthIndex:]
	}
	width, rest := digit0(formatterMessage)
	formatterMessage = rest
	widthValue := ""

	if strings.HasPrefix(formatterMessage, "*") {
		// Also seen number type value 0 used for dynamic width/precision value
		const dynamicPrecisionValue uint8 = 0x0
		if itemType == dynamicPrecisionValue && index < len(messageValue) && messageValue[index].ItemSize == 0 {
			precisionValue = int(messageValue[index].ItemSize)
			index++
			if index >= len(messageValue) {
				logger.Printf("[macos-unifiedlogs] Index now greater than messages array. This should not have happened. Index: %d. Message Array len: %d", index, len(messageValue))
				return "Failed to format precision/dynamic string due index length", nil
			}
			message = messageValue[index].MessageStrings
		}

		widthValue = strconv.Itoa(precisionValue)
		width = widthValue
		// take(size_of::<u8>()) consumes a single byte (the '*')
		if len(formatterMessage) > 0 {
			formatterMessage = formatterMessage[1:]
		}
	}

	if strings.HasPrefix(formatterMessage, ".") {
		input := formatterMessage[1:]

		// Precision may not have an additional value
		// Example: %.f or %.lf is valid precision. The precision value is 0
		if len(input) == 1 || (len(input) > 0 && isAlphabetic(rune(input[0]))) {
			precisionValue = 0
			formatterMessage = input
		} else {
			precisionData, rest := isNot(input, "hljzZtqLdDiuUoOcCxXfFeEgGaASspPn%@")
			if precisionData != "*" {
				precisionResults, err := strconv.Atoi(precisionData)
				if err == nil {
					precisionValue = precisionResults
				} else {
					logger.Printf("[macos-unifiedlogs] Failed to parse format precision value: %v", err)
				}
			} else if precisionValue != 0 {
				// For dynamic length use the length of the message string
				precisionValue = len(messageValue)
			}
			formatterMessage = rest
		}
	}

	// Get Length data if it exists or get the type format
	lengthData := ""
	if len(formatterMessage) > 0 && strings.ContainsRune("hlwIztq", rune(formatterMessage[0])) {
		lengthData, formatterMessage = isA(formatterMessage, "hlwIztq")
	} else if len(formatterMessage) > 0 && strings.ContainsRune("cmCdiouxXeEfgGaAnpsSZP@", rune(formatterMessage[0])) {
		lengthData, formatterMessage = isA(formatterMessage, "cmCdiouxXeEfgGaAnpsSZP@")
	} else {
		return "", ErrFail
	}

	typeData := lengthData
	lengthValues := []string{"h", "hh", "l", "ll", "w", "I", "z", "t", "q"}
	if slices.Contains(lengthValues, lengthData) {
		if len(formatterMessage) > 0 && strings.ContainsRune("cmCdiouxXeEfgGaAnpsSZP@", rune(formatterMessage[0])) {
			typeData, _ = isA(formatterMessage, "cmCdiouxXeEfgGaAnpsSZP@")
		} else {
			return "", ErrFail
		}
	}

	// Error types map error code to error message string. Currently not mapping to error
	// message string
	if slices.Contains(errorTypes, typeData) {
		return errnoCodes(message), nil
	}

	align := alignmentRight
	if leftJustify {
		align = alignmentLeft
	}

	pad := paddingSpace
	if padZero {
		pad = paddingZero
	}

	messageData := messageFormatters{
		precision:    &precisionValue,
		width:        0,
		itemFormat:   typeData,
		plusMinus:    plusMinus,
		hashtag:      hashtag,
		alignment:    align,
		message:      message,
		numberFormat: numberFormatNone,
		padding:      pad,
	}
	determineMessageItem(&messageData)

	if width != "" {
		widthResults, err := strconv.Atoi(width)
		if err == nil {
			messageData.width = widthResults
		} else {
			logger.Printf("[macos-unifiedlogs] Failed to parse format width value: %v", err)
		}

		formatMessagePadding(&messageData)
		return messageData.message, nil
	}

	formatMessage(&messageData)
	return messageData.message, nil
}

// parseTypeFormatter parses formatters containing types.
// Ex: %{errno}d, %{public}s, %{private}s, %{sensitive}
// parse_type_formatter in the Rust source.
func parseTypeFormatter(formatter string, messageValue []FirehoseItemType, itemType uint8, itemIndex int) (string, error) {
	idx := strings.Index(formatter, "}")
	if idx < 0 {
		return "", ErrFail
	}

	// Rust nom take_until("}"): (remaining, output) => format starts at '}', format_type is before
	format := formatter[idx:]
	formatType := formatter[:idx]

	appleObject := checkObjects(formatType, messageValue, itemType, itemIndex)

	// If we successfully decoded an apple object, then there is nothing to format.
	// Signpost entries have not been seen with custom objects
	if appleObject != "" {
		return appleObject, nil
	}

	message, err := parseFormatter(format, messageValue, itemType, itemIndex)
	if err != nil {
		return "", err
	}
	if strings.Contains(formatType, "signpost") {
		signpostMessage := parseSignpostFormat(formatType)
		message = message + " (" + signpostMessage + ")"
	}
	return message, nil
}

// parseSignpostFormat tries to parse additional signpost metadata.
// Ex: %{public,signpost.description:attribute}@
//
//	%{public,signpost.telemetry:number1,name=SOSSignpostNameSOSCCCopyApplicantPeerInfo}d
func parseSignpostFormat(signpostFormat string) string {
	// Rust is_a("%{"): (remaining, output) => signpost_value is what remains after the
	// leading run of '%' and '{' characters.
	i := 0
	for i < len(signpostFormat) && (signpostFormat[i] == '%' || signpostFormat[i] == '{') {
		i++
	}
	signpostValue := signpostFormat[i:]

	var signpostMessage string
	if strings.HasPrefix(signpostFormat, "%{sign") {
		signpostVec := strings.Split(signpostValue, ",")
		signpostMessage = signpostVec[0]
	} else {
		signpostVec := strings.Split(signpostValue, ",")
		if len(signpostVec) < 2 {
			return ""
		}
		signpostMessage = strings.TrimSpace(signpostVec[1])
	}
	return signpostMessage
}

// determineMessageItem determines how the message item should be formatted.
func determineMessageItem(message *messageFormatters) {
	switch {
	case slices.Contains(floatTypes, message.itemFormat):
		v := parseFloat(message.message)
		message.itemFloat = &v
	case slices.Contains(intTypes, message.itemFormat):
		v := parseInt(message.message)
		message.itemNumber = &v
		message.numberFormat = numberFormatDecimal
	case slices.Contains(octalTypes, message.itemFormat):
		v := parseInt(message.message)
		message.itemNumber = &v
		message.numberFormat = numberFormatOctal
	case slices.Contains(hexTypes, message.itemFormat):
		v := parseInt(message.message)
		message.itemNumber = &v
		message.numberFormat = numberFormatHex
	case slices.Contains(stringTypes, message.itemFormat):
		v := message.message
		message.itemString = &v
	}
}

// formatMessage formats the event message with no padding.
func formatMessage(message *messageFormatters) {
	precisionValue := 0
	plusOption := ""

	if message.precision != nil {
		precisionValue = *message.precision
	}
	if message.plusMinus {
		plusOption = "+"
	}

	switch {
	case message.itemFloat != nil:
		item := *message.itemFloat
		if precisionValue == 0 {
			messageFloat := formatFloatShortest(item)
			floatPrecision := strings.Split(messageFloat, ".")
			if len(floatPrecision) == 2 {
				precisionValue = len(floatPrecision[1])
			}
		}
		message.message = plusOption + strconv.FormatFloat(item, 'f', precisionValue, 64)
	case message.itemNumber != nil:
		message.message = plusOption + formatNumber(*message.itemNumber, message.numberFormat, message.hashtag)
	case message.itemString != nil:
		item := *message.itemString
		if precisionValue == 0 {
			precisionValue = utf8.RuneCountInString(item)
		}
		message.message = plusOption + truncateRunes(item, precisionValue)
	}
}

// formatMessagePadding formats the event message using zeros or spaces as padding. All messages
// have alignment to left or right with padding if needed. Message values can also have width and
// precision requirements.
func formatMessagePadding(message *messageFormatters) {
	precisionValue := 0
	plusOption := ""
	adjustWidth := 0

	if message.precision != nil {
		precisionValue = *message.precision
	}
	if message.plusMinus {
		plusOption = "+"
		adjustWidth = 1
	}

	width := message.width - adjustWidth
	if width < 0 {
		width = 0
	}

	fill := byte(' ')
	if message.padding == paddingZero {
		fill = '0'
	}
	left := message.alignment == alignmentLeft

	switch {
	case message.itemFloat != nil:
		item := *message.itemFloat
		if precisionValue == 0 {
			messageFloat := formatFloatShortest(item)
			floatPrecision := strings.Split(messageFloat, ".")
			if len(floatPrecision) == 2 {
				precisionValue = len(floatPrecision[1])
			}
		}
		value := strconv.FormatFloat(item, 'f', precisionValue, 64)
		message.message = plusOption + padRunes(value, width, fill, left)
	case message.itemNumber != nil:
		value := formatNumber(*message.itemNumber, message.numberFormat, message.hashtag)
		message.message = plusOption + padRunes(value, width, fill, left)
	case message.itemString != nil:
		item := *message.itemString
		if precisionValue == 0 {
			precisionValue = utf8.RuneCountInString(item)
		}
		value := truncateRunes(item, precisionValue)
		message.message = plusOption + padRunes(value, width, fill, left)
	}
}

// parseFloat parses the float string log message to float value.
func parseFloat(message string) float64 {
	byteResults, err := strconv.ParseInt(message, 10, 64)
	if err == nil {
		return math.Float64frombits(uint64(byteResults))
	}
	logger.Printf("[macos-unifiedlogs] Failed to parse float log message value: %s, err: %v. Log message possibly incorrectly formatted ex: printf(%%u, \"message\") instead of printf(%%u, 10). Apple may record message as '<decode: mismatch for [%%u] got [STRING sz:10]>'", message, err)
	return math.Float64frombits(0)
}

// parseInt parses the int string log message to int value.
func parseInt(message string) int64 {
	intResults, err := strconv.ParseInt(message, 10, 64)
	if err == nil {
		return intResults
	}
	logger.Printf("[macos-unifiedlogs] Failed to parse int log message value: %s, err: %v. Log message possibly incorrectly formatted ex: printf(%%u, \"message\") instead of printf(%%u, 10). Apple may record message as '<decode: mismatch for [%%u] got [STRING sz:10]>'", message, err)
	return 0
}

func formatNumber(n int64, nf numberFormat, hashtag bool) string {
	switch nf {
	case numberFormatOctal:
		value := strconv.FormatInt(n, 8)
		if hashtag {
			value = "0o" + value
		}
		return value
	case numberFormatHex:
		value := strings.ToUpper(strconv.FormatUint(uint64(n), 16))
		if hashtag {
			value = "0x" + value
		}
		return value
	case numberFormatDecimal:
		return strconv.FormatInt(n, 10)
	default:
		logger.Printf("[macos-unifiedlogs] Got NumberFormat None for %v", nf)
		return ""
	}
}

// formatFloatShortest mirrors Rust's f64 Display (shortest round-trip, no exponent).
func formatFloatShortest(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func padRunes(s string, width int, fill byte, left bool) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	pad := strings.Repeat(string(fill), width-n)
	if left {
		return s + pad
	}
	return pad + s
}

func truncateRunes(s string, n int) string {
	if n <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// digit0 consumes zero or more leading ASCII digits, returning (digits, rest).
func digit0(s string) (string, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// isA greedily consumes a run of leading bytes that are members of set, returning
// (consumed, rest).
func isA(s string, set string) (string, string) {
	i := 0
	for i < len(s) && strings.IndexByte(set, s[i]) >= 0 {
		i++
	}
	return s[:i], s[i:]
}

// isNot consumes a run of leading bytes that are NOT members of set, returning
// (consumed, rest).
func isNot(s string, set string) (string, string) {
	i := 0
	for i < len(s) && strings.IndexByte(set, s[i]) < 0 {
		i++
	}
	return s[:i], s[i:]
}

func isAlphabetic(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
