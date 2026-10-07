// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// requireTestData reads a file under tests/test_data and skips the test when the
// reference logarchive data (test_data.zip from the GitHub release) is not present.
func requireTestData(t *testing.T, rel string) []byte {
	t.Helper()
	path := filepath.Join("tests", "test_data", filepath.FromSlash(rel))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("test data %q not available (download test_data.zip from the GitHub release): %v", path, err)
	}
	return data
}

// requireTestDataFile returns a path under tests/test_data, skipping when absent.
func requireTestDataFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("tests", "test_data", filepath.FromSlash(rel))
	if _, err := os.Stat(path); err != nil {
		t.Skipf("test data %q not available (download test_data.zip from the GitHub release): %v", path, err)
	}
	return path
}

// requireErrIncomplete asserts an error wrapping ErrIncomplete (the Rust crate's
// nom::Err::Incomplete(Needed::Unknown)).
func requireErrIncomplete(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("expected ErrIncomplete, got: %v", err)
	}
}
