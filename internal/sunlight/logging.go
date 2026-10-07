// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package sunlight

import (
	"io"
	"log"
)

// logger holds diagnostic messages ported from the Rust crate's debug!/warn!/
// error! macros. It discards output by default so the library is silent unless
// the caller opts in via SetLogOutput.
var logger = log.New(io.Discard, "", 0)

// SetLogOutput directs the package's diagnostic log messages to w. Pass
// os.Stderr (or os.Stdout) to restore verbose output, or io.Discard to silence.
func SetLogOutput(w io.Writer) {
	logger.SetOutput(w)
}
