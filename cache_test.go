// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"errors"
	"testing"
)

type fakeProvider struct {
	uuidTextCalls int
	dscCalls      int
	uuidErr       error
	dscErr        error
}

func (f *fakeProvider) Tracev3Files() []SourceFile  { return nil }
func (f *fakeProvider) UUIDTextFiles() []SourceFile { return nil }
func (f *fakeProvider) DSCFiles() []SourceFile      { return nil }
func (f *fakeProvider) TimesyncFiles() []SourceFile { return nil }
func (f *fakeProvider) ReadUUIDText(uuid string) (*UUIDText, error) {
	f.uuidTextCalls++
	if f.uuidErr != nil {
		return nil, f.uuidErr
	}
	return &UUIDText{UUID: uuid, Signature: 1}, nil
}
func (f *fakeProvider) ReadDSCUUID(uuid string) (*SharedCacheStrings, error) {
	f.dscCalls++
	if f.dscErr != nil {
		return nil, f.dscErr
	}
	return &SharedCacheStrings{DSCUUID: uuid, Signature: 2}, nil
}

func TestMemoryStringCacheUUIDText(t *testing.T) {
	cache := NewMemoryStringCache()
	provider := &fakeProvider{}

	first, err := cache.GetOrLoadUUIDText("ABCD", provider)
	if err != nil {
		t.Fatalf("first GetOrLoadUUIDText: %v", err)
	}
	second, err := cache.GetOrLoadUUIDText("ABCD", provider)
	if err != nil {
		t.Fatalf("second GetOrLoadUUIDText: %v", err)
	}
	if first != second {
		t.Error("expected cached pointer identity")
	}
	if provider.uuidTextCalls != 1 {
		t.Errorf("provider calls = %d, want 1", provider.uuidTextCalls)
	}
}

func TestMemoryStringCacheDSC(t *testing.T) {
	cache := NewMemoryStringCache()
	provider := &fakeProvider{}

	if _, err := cache.GetOrLoadDSC("ABCD", provider); err != nil {
		t.Fatalf("first GetOrLoadDSC: %v", err)
	}
	if _, err := cache.GetOrLoadDSC("ABCD", provider); err != nil {
		t.Fatalf("second GetOrLoadDSC: %v", err)
	}
	if provider.dscCalls != 1 {
		t.Errorf("provider calls = %d, want 1", provider.dscCalls)
	}
}

func TestMemoryStringCacheError(t *testing.T) {
	cache := NewMemoryStringCache()
	provider := &fakeProvider{uuidErr: errors.New("boom")}

	if _, err := cache.GetOrLoadUUIDText("ABCD", provider); err == nil {
		t.Error("expected error, got nil")
	}
	if provider.uuidTextCalls != 1 {
		t.Errorf("provider calls = %d, want 1", provider.uuidTextCalls)
	}
}
