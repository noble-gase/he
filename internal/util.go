package internal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"strconv"

	"github.com/tidwall/gjson"
)

type X map[string]any

func Fail(text string) (gjson.Result, error) {
	return gjson.Result{}, errors.New(text)
}

func FailE(err error) (gjson.Result, error) {
	return gjson.Result{}, err
}

func FailF(format string, a ...any) (gjson.Result, error) {
	return gjson.Result{}, fmt.Errorf(format, a...)
}

// Nonce 生成指定长度的随机串 (最好是偶数)
func Nonce(size uint) string {
	nonce := make([]byte, size/2)
	_, _ = io.ReadFull(rand.Reader, nonce)
	return hex.EncodeToString(nonce)
}

// NonceByte 生成指定长度的随机字节
func NonceByte(size uint) []byte {
	nonce := make([]byte, size)
	_, _ = io.ReadFull(rand.Reader, nonce)
	return nonce
}

// EncodeUint32ToBytes 把整数 uint32 格式化成 4 字节的网络字节序
func EncodeUint32ToBytes(i uint32) []byte {
	b := make([]byte, 4)

	b[0] = byte(i >> 24)
	b[1] = byte(i >> 16)
	b[2] = byte(i >> 8)
	b[3] = byte(i)

	return b
}

// DecodeBytesToUint32 从 4 字节的网络字节序里解析出整数 uint32
func DecodeBytesToUint32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// MarshalNoEscapeHTML 不带HTML转义的JSON序列化
func MarshalNoEscapeHTML(v any) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}

	b := buf.Bytes()
	// 去掉 go std 给末尾加的 '\n'
	// @see https://github.com/golang/go/issues/7767
	if l := len(b); l != 0 && b[l-1] == '\n' {
		b = b[:l-1]
	}
	return b, nil
}

func AnyToStr(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case int:
		return strconv.Itoa(v)
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case json.Number:
		return v.String()
	case []byte:
		return string(v)
	case template.HTML:
		return string(v)
	case template.URL:
		return string(v)
	case template.JS:
		return string(v)
	case template.CSS:
		return string(v)
	case template.HTMLAttr:
		return string(v)
	case nil:
		return "<nil>"
	case error:
		return v.Error()
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%+v", val)
	}
}
