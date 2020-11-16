package cache

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewInMemoryCache_Store(t *testing.T) {
	cache := NewInMemoryCache(10, 1, false)
	cache.Store("1", "ABC")
	cache.Store("1", "BCD")
	cache.Store("1", "CDE")
	cache.Store("1", "DEF")

	ok, str := cache.Fetch("1")
	assert.True(t, ok)
	assert.Equal(t, "DEF", str.(string))

	assert.Equal(t, 1, cache.Size())

	cache.Delete("1")
	ok, str = cache.Fetch("1")
	assert.False(t, ok)
}

func TestNewInMemoryCache_Capacity(t *testing.T) {
	cache := NewInMemoryCache(5, 1, false)
	cache.Store("1", "ABC")
	cache.Store("2", "BCD")
	cache.Store("3", "CDE")
	cache.Store("4", "DEF")
	cache.Store("5", "EFG")
	cache.Store("6", "FGH")
	cache.Store("7", "GHI")
	cache.Store("8", "HIJ")
	cache.Store("9", "IJK")
	cache.Store("10", "JKL")
	assert.Equal(t, 10, cache.Size())
	cache.Store("11", "ABC")
	assert.Equal(t, 10, cache.Size())
	cache.Store("12", "BCD")
	assert.Equal(t, 10, cache.Size())
	cache.Store("13", "CDE")
	assert.Equal(t, 10, cache.Size())

	ok, _ := cache.Fetch("1")
	assert.False(t, ok)
	ok, _ = cache.Fetch("2")
	assert.False(t, ok)
	ok, _ = cache.Fetch("3")
	assert.False(t, ok)
	ok, _ = cache.Fetch("4")
	assert.True(t, ok)
	ok, _ = cache.Fetch("5")
	assert.True(t, ok)
	ok, _ = cache.Fetch("6")
	assert.True(t, ok)
	ok, _ = cache.Fetch("7")
	assert.True(t, ok)
	ok, _ = cache.Fetch("8")
	assert.True(t, ok)

	time.Sleep(1001 * time.Millisecond)

	assert.Equal(t, 0, cache.Size())
}

func TestInMemoryCache_Fetch(t *testing.T) {
	cache := NewInMemoryCache(10, 1, false)
	cache.Store("1", "ABC")
	cache.Store("2", "BCA")
	time.Sleep(1001 * time.Millisecond)
	ok, _ := cache.Fetch("1")
	assert.False(t, ok)
	ok, _ = cache.Fetch("2")
	assert.False(t, ok)
}
