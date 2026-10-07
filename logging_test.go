// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestSetLogOutput(t *testing.T) {
	defer SetLogOutput(io.Discard)

	var buf bytes.Buffer
	SetLogOutput(&buf)
	logger.Printf("[macos-unifiedlogs] test %d", 42)
	if !strings.Contains(buf.String(), "[macos-unifiedlogs] test 42") {
		t.Fatalf("SetLogOutput did not capture output: %q", buf.String())
	}

	SetLogOutput(io.Discard)
	buf.Reset()
	logger.Printf("[macos-unifiedlogs] silent")
	if buf.Len() != 0 {
		t.Fatalf("expected no output when discarded, got %q", buf.String())
	}
}
