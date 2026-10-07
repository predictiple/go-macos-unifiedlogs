// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "sync"

// MemoryStringCache is a thread-safe cache for UUIDText and SharedCacheStrings data shared
// during log parsing.
//
// The default implementation (NewMemoryStringCache) uses unbounded maps guarded by a
// sync.RWMutex. Copies of the cache share the same underlying maps. Concurrent reads proceed
// without blocking each other, while a cache miss takes an exclusive write lock only for the
// duration of the insert.
//
// The default implementation grows without bound. For long-running processes or large log
// collections, provide your own StringCache implementation.
type MemoryStringCache struct {
	mu       sync.RWMutex
	uuidtext map[string]*UUIDText
	dsc      map[string]*SharedCacheStrings
}

// NewMemoryStringCache returns an empty MemoryStringCache.
func NewMemoryStringCache() *MemoryStringCache {
	return &MemoryStringCache{
		uuidtext: make(map[string]*UUIDText),
		dsc:      make(map[string]*SharedCacheStrings),
	}
}

// GetOrLoadUUIDText returns the cached UUIDText for uuid, loading it via provider if absent.
func (c *MemoryStringCache) GetOrLoadUUIDText(uuid string, provider FileProvider) (*UUIDText, error) {
	c.mu.RLock()
	if v, ok := c.uuidtext[uuid]; ok {
		c.mu.RUnlock()
		return v, nil
	}
	c.mu.RUnlock()

	value, err := provider.ReadUUIDText(uuid)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.uuidtext[uuid] = value
	c.mu.Unlock()
	return value, nil
}

// GetOrLoadDSC returns the cached SharedCacheStrings for uuid, loading it via provider if
// absent.
//
// DSC files are large (~30 MB-150 MB each). The default implementation grows without bound;
// supply a bounded StringCache if eviction is required.
func (c *MemoryStringCache) GetOrLoadDSC(uuid string, provider FileProvider) (*SharedCacheStrings, error) {
	c.mu.RLock()
	if v, ok := c.dsc[uuid]; ok {
		c.mu.RUnlock()
		return v, nil
	}
	c.mu.RUnlock()

	value, err := provider.ReadDSCUUID(uuid)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.dsc[uuid] = value
	c.mu.Unlock()
	return value, nil
}
