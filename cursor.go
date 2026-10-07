// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors mirroring the nom error kinds used by the original Rust crate.
// ErrIncomplete corresponds to nom::Err::Incomplete (used for bad signatures),
// ErrEof corresponds to nom's ErrorKind::Eof (truncated input),
// ErrFail corresponds to nom's ErrorKind::Fail (general parse failure).
var (
	ErrIncomplete = errors.New("Incomplete")
	ErrEof        = errors.New("Eof")
	ErrFail       = errors.New("Fail")
	ErrTooLarge   = errors.New("TooLarge")
)

// cursor is a replacement for nom's &[u8] slicing parsers. It tracks a read
// position over a byte slice and yields little/big-endian scalars and slices.
type cursor struct {
	data []byte
	pos  int
}

func newCursor(data []byte) *cursor {
	return &cursor{data: data, pos: 0}
}

func (c *cursor) remaining() int {
	return len(c.data) - c.pos
}

func (c *cursor) isEmpty() bool {
	return c.pos >= len(c.data)
}

// rest returns the unconsumed portion of the buffer.
func (c *cursor) rest() []byte {
	return c.data[c.pos:]
}

// reset restarts the cursor over a new buffer (mirrors reassigning input in Rust).
func (c *cursor) reset(data []byte) {
	c.data = data
	c.pos = 0
}

func (c *cursor) need(n int) error {
	if n < 0 || c.remaining() < n {
		return fmt.Errorf("needed %d bytes, got %d: %w", n, c.remaining(), ErrEof)
	}
	return nil
}

// take returns the next n bytes without copying and advances the position.
func (c *cursor) take(n int) ([]byte, error) {
	if err := c.need(n); err != nil {
		return nil, err
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}

// skip advances the position by n bytes.
func (c *cursor) skip(n int) error {
	if err := c.need(n); err != nil {
		return err
	}
	c.pos += n
	return nil
}

// takeWhile consumes bytes while fn returns true and returns them.
func (c *cursor) takeWhile(fn func(byte) bool) []byte {
	start := c.pos
	for c.pos < len(c.data) && fn(c.data[c.pos]) {
		c.pos++
	}
	return c.data[start:c.pos]
}

func (c *cursor) u8() (uint8, error) {
	if err := c.need(1); err != nil {
		return 0, err
	}
	v := c.data[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	if err := c.need(2); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(c.data[c.pos:])
	c.pos += 2
	return v, nil
}

func (c *cursor) u32() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, nil
}

func (c *cursor) i32() (int32, error) {
	v, err := c.u32()
	return int32(v), err
}

func (c *cursor) i8() (int8, error) {
	v, err := c.u8()
	return int8(v), err
}

func (c *cursor) i16() (int16, error) {
	v, err := c.u16()
	return int16(v), err
}

func (c *cursor) u64() (uint64, error) {
	if err := c.need(8); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint64(c.data[c.pos:])
	c.pos += 8
	return v, nil
}

func (c *cursor) i64() (int64, error) {
	v, err := c.u64()
	return int64(v), err
}

// u32be reads a big-endian u32 (nom's be_u32).
func (c *cursor) u32be() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, nil
}

// u64be reads a big-endian u64 (nom's be_u64).
func (c *cursor) u64be() (uint64, error) {
	if err := c.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(c.data[c.pos:])
	c.pos += 8
	return v, nil
}

// u128be reads a big-endian 128-bit value (nom's be_u128).
func (c *cursor) u128be() ([16]byte, error) {
	var out [16]byte
	b, err := c.take(16)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// peekU32 reads a little-endian u32 at the current position without consuming it.
func (c *cursor) peekU32() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(c.data[c.pos:]), nil
}

// u128Hex formats a big-endian 128-bit value as 32 uppercase hex digits
// (equivalent to Rust's format!("{value:032X}")).
func u128Hex(v [16]byte) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 32)
	for i, b := range v {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}
