// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
)

// openDirectoryErrors converts Open Directory error codes to a message.
func openDirectoryErrors(errorsData string) string {
	messages := map[string]string{
		"5301":  "ODErrorCredentialsAccountDisabled",
		"5302":  "ODErrorCredentialsAccountExpired",
		"5303":  "ODErrorCredentialsAccountInactive",
		"5300":  "ODErrorCredentialsAccountNotFound",
		"5000":  "ODErrorCredentialsInvalid",
		"5001":  "ODErrorCredentialsInvalidComputer",
		"5500":  "ODErrorCredentialsInvalidLogonHours",
		"5100":  "ODErrorCredentialsMethodNotSupported",
		"5101":  "ODErrorCredentialsNotAuthorized",
		"5103":  "ODErrorCredentialsOperationFailed",
		"5102":  "ODErrorCredentialsParameterError",
		"5401":  "ODErrorCredentialsPasswordChangeRequired",
		"5407":  "ODErrorCredentialsPasswordChangeTooSoon",
		"5400":  "ODErrorCredentialsPasswordExpired",
		"5406":  "ODErrorCredentialsPasswordNeedsDigit",
		"5405":  "ODErrorCredentialsPasswordNeedsLetter",
		"5402":  "ODErrorCredentialsPasswordQualityFailed",
		"5403":  "ODErrorCredentialsPasswordTooShort",
		"5404":  "ODErrorCredentialsPasswordTooLong",
		"5408":  "ODErrorCredentialsPasswordUnrecoverable",
		"5205":  "ODErrorCredentialsServerCommunicationError",
		"5202":  "ODErrorCredentialsServerError",
		"5201":  "ODErrorCredentialsServerNotFound",
		"5203":  "ODErrorCredentialsServerTimeout",
		"5200":  "ODErrorCredentialsServerUnreachable",
		"10002": "ODErrorDaemonError",
		"2100":  "ODErrorNodeConnectionFailed",
		"2002":  "ODErrorNodeDisabled",
		"2200":  "ODErrorNodeUnknownHost",
		"2000":  "ODErrorNodeUnknownName",
		"2001":  "ODErrorNodeUnknownType",
		"10001": "ODErrorPluginError",
		"10000": "ODErrorPluginOperationNotSupported",
		"10003": "ODErrorPluginOperationTimeout",
		"6001":  "ODErrorPolicyOutOfRange",
		"6000":  "ODErrorPolicyUnsupported",
		"3100":  "ODErrorQueryInvalidMatchType",
		"3000":  "ODErrorQuerySynchronize",
		"3102":  "ODErrorQueryTimeout",
		"3101":  "ODErrorQueryUnsupportedMatchType",
		"4102":  "ODErrorRecordAlreadyExists",
		"4201":  "ODErrorRecordAttributeNotFound",
		"4200":  "ODErrorRecordAttributeUnknownType",
		"4203":  "ODErrorRecordAttributeValueNotFound",
		"4202":  "ODErrorRecordAttributeValueSchemaError",
		"4101":  "ODErrorRecordInvalidType",
		"4104":  "ODErrorRecordNoLongerExists",
		"4100":  "ODErrorRecordParameterError",
		"4001":  "ODErrorRecordPermissionError",
		"4000":  "ODErrorRecordReadOnlyNode",
		"4103":  "ODErrorRecordTypeDisabled",
		"1002":  "ODErrorSessionDaemonNotRunning",
		"1003":  "ODErrorSessionDaemonRefused",
		"1000":  "ODErrorSessionLocalOnlyDaemonInUse",
		"1001":  "ODErrorSessionNormalDaemonInUse",
		"1100":  "ODErrorSessionProxyCommunicationError",
		"1102":  "ODErrorSessionProxyIPUnreachable",
		"1103":  "ODErrorSessionProxyUnknownHost",
		"1101":  "ODErrorSessionProxyVersionMismatch",
		"0":     "ODErrorSuccess",
		"5305":  "ODErrorCredentialsAccountLocked",
		"5304":  "ODErrorCredentialsAccountTemporarilyLocked",
		"5204":  "ODErrorCredentialsContactPrimary",
		"2":     "Not Found",
	}

	message, ok := messages[errorsData]
	if !ok {
		logger.Printf("[macos-unifiedlogs] Unknown open directory error code: %s", errorsData)
		return errorsData
	}
	return message
}

// memberIDType converts Open Directory member ids to a string.
func memberIDType(memberData string) string {
	messages := map[string]string{
		"0":  "UID",
		"1":  "GID",
		"3":  "SID",
		"4":  "USERNAME",
		"5":  "GROUPNAME",
		"6":  "UUID",
		"7":  "GROUP NFS",
		"8":  "USER NFS",
		"10": "GSS EXPORT NAME",
		"11": "X509 DN",
		"12": "KERBEROS",
	}

	message, ok := messages[memberData]
	if !ok {
		logger.Printf("[macos-unifiedlogs] Unknown open directory member id type: %s", memberData)
		return memberData
	}
	return message
}

// memberDetails converts Open Directory member details to a string.
func memberDetails(memberData string) (string, error) {
	decodedData, err := decodeStandard(memberData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(memberData),
			ParserName: "member details",
			Message:    "Failed to base64 decode open directory member details data",
		}
	}

	_, result, err := getMemberData(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(memberData),
			ParserName: "member details",
			Message:    "Failed to get open directory member details",
		}
	}
	return result, nil
}

// sidDetails parses SID log data to a SID string.
func sidDetails(sidData string) (string, error) {
	decodedData, err := decodeStandard(sidData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(sidData),
			ParserName: "sid details",
			Message:    "Failed to base64 decode open directory SID details data",
		}
	}

	_, result, err := getSIDData(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(sidData),
			ParserName: "sid details",
			Message:    "Failed to get open directory sid details",
		}
	}
	return result, nil
}

// getMemberData parses Open Directory membership details data.
func getMemberData(memberData []byte) ([]byte, string, error) {
	c := newCursor(memberData)
	memberType, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	var memberMessage string
	switch memberType {
	case 35, 163: // UID
		uid, err := c.i32()
		if err != nil {
			return nil, "", err
		}
		memberMessage = fmt.Sprintf("user: %d", uid)
	case 36, 160, 164: // USER
		name, err := nonEmptyCString(c)
		if err != nil {
			return nil, "", err
		}
		memberMessage = fmt.Sprintf("user: %s", name)
	case 68: // GROUP
		name, err := nonEmptyCString(c)
		if err != nil {
			return nil, "", err
		}
		memberMessage = fmt.Sprintf("group: %s", name)
	case 195: // GID
		gid, err := c.i32()
		if err != nil {
			return nil, "", err
		}
		memberMessage = fmt.Sprintf("group: %d", gid)
	default:
		logger.Printf("[macos-unifiedlogs] Unknown open directory member type: %d", memberType)
		memberMessage = fmt.Sprintf("Unknown Member type %d: @", memberType)
	}

	// source path
	sourcePathPos := c.pos
	sourcePathData, err := nonEmptyCString(c)
	var sourcePath string
	if err != nil {
		c.pos = sourcePathPos
		sourcePath = " <not found>"
	} else {
		sourcePath = fmt.Sprintf("@%s", sourcePathData)
	}

	return c.rest(), fmt.Sprintf("%s%s", memberMessage, sourcePath), nil
}

// getSIDData parses the SID data from a SID log object.
func getSIDData(sidData []byte) ([]byte, string, error) {
	c := newCursor(sidData)

	revision, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	unknownSize, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	if _, err := c.take(int(unknownSize)); err != nil {
		return nil, "", err
	}

	authority, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	subauthority, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	if _, err := c.take(3); err != nil {
		return nil, "", err
	}

	sid := fmt.Sprintf("S-%d-%d-%d", revision, authority, subauthority)
	// fold_many0(le_u32) - append each additional subauthority
	for !c.isEmpty() {
		additional, err := c.u32()
		if err != nil {
			break
		}
		sid = fmt.Sprintf("%s-%d", sid, additional)
	}

	return c.rest(), sid, nil
}
