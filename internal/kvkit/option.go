package kvkit

// EmptyMode 值为空时的Encode模式
type EmptyMode int

const (
	EmptyDefault EmptyMode = iota // 默认：bar=baz&foo=
	EmptyIgnore                   // 忽略：bar=baz
	EmptyOnlyKey                  // 仅保留Key：bar=baz&foo
)

type options struct {
	emptyMode  EmptyMode
	ignoreKeys map[string]struct{}
}

// Option KV Encode 选项
type Option func(o *options)

// WithEmptyMode 设置值为空时的Encode模式
func WithEmptyMode(mode EmptyMode) Option {
	return func(o *options) {
		o.emptyMode = mode
	}
}

// WithIgnoreKeys 设置Encode时忽略的key
func WithIgnoreKeys(keys ...string) Option {
	return func(o *options) {
		for _, k := range keys {
			o.ignoreKeys[k] = struct{}{}
		}
	}
}
