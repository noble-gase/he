package kvkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {
	kv1 := KV{}
	kv1.Set("bar", "baz")
	kv1.Set("foo", "quux")

	assert.Equal(t, "bar=baz&foo=quux", kv1.Encode("=", "&"))
	assert.Equal(t, "bar:baz#foo:quux", kv1.Encode(":", "#"))

	kv2 := KV{}
	kv2.Set("hello", "world")
	kv2.Set("bar", "baz")
	kv2.Set("foo", "")

	assert.Equal(t, "bar=baz&foo=&hello=world", kv2.Encode("=", "&"))
	assert.Equal(t, "bar=baz&foo=&hello=world", kv2.Encode("=", "&", WithEmptyMode(EmptyDefault)))
	assert.Equal(t, "bar=baz&foo&hello=world", kv2.Encode("=", "&", WithEmptyMode(EmptyOnlyKey)))
	assert.Equal(t, "bar=baz&hello=world", kv2.Encode("=", "&", WithEmptyMode(EmptyIgnore)))
	assert.Equal(t, "bar=baz&foo=", kv2.Encode("=", "&", WithIgnoreKeys("hello")))
	assert.Equal(t, "bar=baz", kv2.Encode("=", "&", WithIgnoreKeys("hello"), WithEmptyMode(EmptyIgnore)))
}

func TestURLEncode(t *testing.T) {
	kv := KV{}
	kv.Set("bar", "baz@666")
	kv.Set("foo", "quux%666")

	assert.Equal(t, "bar=baz%40666&foo=quux%25666", kv.URLEncode())
}
