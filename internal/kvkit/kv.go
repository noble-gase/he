package kvkit

import (
	"net/url"
	"sort"
	"strings"
)

// KV 用于处理 k/v 需要格式化的场景，如：签名
type KV map[string]string

// Set 设置 k/v
func (kv KV) Set(key, value string) {
	kv[key] = value
}

// Get 获取值
func (kv KV) Get(key string) string {
	return kv[key]
}

// Del 删除Key
func (kv KV) Del(key string) {
	delete(kv, key)
}

// Has 判断Key是否存在
func (kv KV) Has(key string) bool {
	_, ok := kv[key]
	return ok
}

// Encode 通过自定义的符号和分隔符按照key的ASCII码升序格式化为字符串。
// 例如：("=", "&") ---> bar=baz&foo=quux；
// 例如：(":", "#") ---> bar:baz#foo:quux；
func (kv KV) Encode(sym, sep string, opts ...Option) string {
	if len(kv) == 0 {
		return ""
	}

	o := &options{
		ignoreKeys: make(map[string]struct{}),
	}
	for _, f := range opts {
		f(o)
	}

	keys := make([]string, 0, len(kv))
	for k := range kv {
		if _, ok := o.ignoreKeys[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var buf strings.Builder
	for _, k := range keys {
		val := kv[k]
		if len(val) == 0 && o.emptyMode == EmptyIgnore {
			continue
		}

		if buf.Len() > 0 {
			buf.WriteString(sep)
		}

		buf.WriteString(k)
		if len(val) != 0 {
			buf.WriteString(sym)
			buf.WriteString(val)
		} else {
			if o.emptyMode != EmptyOnlyKey {
				buf.WriteString(sym)
			}
		}
	}
	return buf.String()
}

// URLEncode encodes the KV into “URL encoded” form ("bar=baz&foo=quux") sorted by key.
func (kv KV) URLEncode() string {
	query := url.Values{}
	for k, v := range kv {
		query.Set(k, v)
	}
	return query.Encode()
}

func FromURLQuery(query string) (KV, error) {
	vals, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}

	kv := make(KV, len(vals))
	for k, v := range vals {
		kv.Set(k, v[0])
	}
	return kv, nil
}
