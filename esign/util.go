package esign

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

type KV = kvkit.KV

type X map[string]any

const (
	HeaderContentMD5           = "Content-MD5"
	HeaderTSignOpenAppID       = "X-Tsign-Open-App-Id"
	HeaderTSignOpenAuthMode    = "X-Tsign-Open-Auth-Mode"
	HeaderTSignOpenCaTimestamp = "X-Tsign-Open-Ca-Timestamp"
	HeaderTSignOpenCaSignature = "X-Tsign-Open-Ca-Signature"
	HeaderTSignOpenTimestamp   = "X-Tsign-Open-TIMESTAMP"
	HeaderTSignOpenSignature   = "X-Tsign-Open-SIGNATURE"
)

const (
	AcceptAll    = "*/*"
	AuthModeSign = "Signature"
)

// ContentMD5 计算内容MD5值
func ContentMD5(b []byte) string {
	h := md5.New()
	h.Write(b)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// FileMD5 计算文件MD5值
func FileMD5(filename string) (string, int64) {
	f, err := os.Open(filename)
	if err != nil {
		return err.Error(), -1
	}
	defer f.Close()

	h := md5.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err.Error(), -1
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), n
}

func Result(b []byte) (gjson.Result, error) {
	ret := gjson.ParseBytes(b)
	if code := ret.Get("code").Int(); code != 0 {
		return internal.FailF("%d | %s", code, ret.Get("message"))
	}
	return ret.Get("data"), nil
}

func ErrFromStream(b []byte) error {
	ret := gjson.ParseBytes(b)
	if code := ret.Get("errCode").Int(); code != 0 {
		return fmt.Errorf("%d | %s", code, ret.Get("msg"))
	}
	return nil
}
