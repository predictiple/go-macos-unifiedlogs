// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"bytes"
	"testing"
)

func TestDecompressLzbitmap(t *testing.T) {
	buffer := requireTestData(t, "lzbitmap/lzbitmap_zbm.raw")

	results, err := lzbitmapDecompress(buffer)
	if err != nil {
		t.Fatalf("lzbitmapDecompress returned error: %v", err)
	}

	expected := []byte{1, 96, 0, 0, 0, 0, 0, 0, 6, 16, 0, 0, 0, 0, 0, 0, 80, 2, 0}
	if !bytes.HasPrefix(results, expected) {
		t.Fatalf("unexpected lzbitmap prefix: %v", results[:19])
	}
	if len(results) != 65424 {
		t.Fatalf("unexpected lzbitmap length: %d", len(results))
	}
}
