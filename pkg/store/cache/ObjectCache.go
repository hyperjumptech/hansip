package cache

import (
	"strings"
	"sync"
	"time"
)

// ObjectCache interface to define a standard CACHE interface.
type ObjectCache interface {
	Store(key string, object interface{})
	Fetch(key string) (bool, interface{})
	KeysByPrefix(prefix string) []string
	Delete(key string)
	Clear()
	Size() int
}

// CacheItem is a linked list node. It maintain links up and down (equals to next and prev)
type CacheItem struct {
	Key        string
	up         *CacheItem
	down       *CacheItem
	Item       interface{}
	createTime time.Time
}

// IsExpired check if this item is expired
func (item *CacheItem) IsExpired(maxAgeSecond int) bool {
	dur := time.Now().Sub(item.createTime)
	return dur > (time.Duration(maxAgeSecond) * time.Second)
}

// NewInMemoryCache create new instance of InMemoryCache
func NewInMemoryCache(capacity, ttlsecond int, ttlextend bool) ObjectCache {
	c := &InMemoryCache{
		TTLSecond: ttlsecond,
		TTLExtend: ttlextend,
		Capacity:  capacity,
		data:      make(map[string]*CacheItem),
		top:       nil,
		bottom:    nil,
	}
	if c.Capacity < 10 {
		c.Capacity = 10
	}
	if c.TTLSecond < 1 {
		c.TTLSecond = 1
	}
	return c
}

// InMemoryCache is an implementation of Object cache
type InMemoryCache struct {
	mutex     sync.Mutex
	TTLSecond int
	TTLExtend bool
	Capacity  int
	data      map[string]*CacheItem
	top       *CacheItem
	bottom    *CacheItem
}

// Size returns total number of valid cached object.
func (cache *InMemoryCache) Size() int {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.removeExpired()
	return len(cache.data)
}

// Store saves object into this cache
func (cache *InMemoryCache) Store(key string, object interface{}) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if item, exist := cache.data[key]; exist { // Replacing
		i := &CacheItem{
			Key:        key,
			up:         item.up,
			down:       item.down,
			Item:       object,
			createTime: time.Now(),
		}
		if item.up != nil {
			item.up.down = i
		}
		if item.down != nil {
			item.down.up = i
		}
		cache.data[key] = i
	} else { // Inserting
		i := &CacheItem{
			Key:        key,
			up:         nil,
			down:       nil,
			Item:       object,
			createTime: time.Now(),
		}
		if cache.top != nil {
			cache.top.up = i
			i.down = cache.top
		}
		cache.top = i

		if cache.bottom == nil {
			cache.bottom = cache.top
		}
		cache.data[key] = i
	}
	// if the cache capacity is too long, cut the bottom most.
	for len(cache.data) > cache.Capacity {
		bottom := cache.bottom
		bottom.up.down = nil
		cache.bottom = bottom.up
		delete(cache.data, bottom.Key)
	}
	cache.removeExpired()
}

func (cache *InMemoryCache) removeExpired() {
	if cache.bottom == nil || !cache.bottom.IsExpired(cache.TTLSecond) {
		return
	}
	if cache.bottom == cache.top {
		delete(cache.data, cache.bottom.Key)
		cache.top = nil
		cache.bottom = nil
		return
	}
	for cache.bottom != nil && cache.bottom.IsExpired(cache.TTLSecond) {
		todel := cache.bottom
		cache.bottom = todel.up
		if cache.bottom != nil {
			cache.bottom.down = nil
		}
		delete(cache.data, todel.Key)
		todel = cache.bottom
	}
}

// Fetch valid objects from the cache. Valid means that its not yet expired.
func (cache *InMemoryCache) Fetch(key string) (bool, interface{}) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if data, ok := cache.data[key]; ok {
		if data.IsExpired(cache.TTLSecond) {
			cache.removeExpired()
			return false, nil
		}
		if cache.TTLExtend {
			data.createTime = time.Now()
			if data.up != nil {
				if data.down != nil { // we are in the middle
					// remove data from the linklist
					data.down.up = data.up
					data.up.down = data.down
				} else { // we are at the bottom
					// remove data from the linklist
					data.up.down = nil
					cache.bottom = data.up
				}
				// move to the top
				data.up = nil
				cache.top.up = data
				data.down = cache.top
				cache.top = data
			}
		}
		cache.removeExpired()
		return true, data.Item
	}
	return false, nil
}

// KeysByPrefix returns all valid cached key which have the specified prefix.
func (cache *InMemoryCache) KeysByPrefix(prefix string) []string {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	keys := make([]string, 0)
	cache.removeExpired()
	for k, _ := range cache.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
		if len(keys) > 100 {
			return keys
		}
	}
	return keys
}

// Delete a cached object by its key.
func (cache *InMemoryCache) Delete(key string) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if item, exist := cache.data[key]; exist {
		if item.up != nil {
			if item.down != nil { // we are in the middle
				item.up.down = item.down
				item.down.up = item.up
			} else { // we are at the bottom
				item.up.down = nil
				cache.bottom = item.up
			}
		} else {
			if item.down != nil { // we are at the top
				item.down.up = nil
				cache.top = item.down
			} else { // we are the only item.
				cache.bottom = nil
				cache.top = nil
			}
		}
		delete(cache.data, key)
	}
}

// Clear all objects from this cache
func (cache *InMemoryCache) Clear() {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.data = make(map[string]*CacheItem)
	cache.top = nil
	cache.bottom = nil
}
