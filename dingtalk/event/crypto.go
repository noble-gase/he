package event

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/cryptokit"
	"github.com/noble-gase/he/internal/kvkit"
)

// SignWithSHA1 事件消息sha1签名
//
//	[参考](https://dingtalk.apifox.cn/doc-392311)
func SignWithSHA1(token string, items ...string) string {
	items = append(items, token)
	sort.Strings(items)

	h := sha1.New()
	for _, v := range items {
		h.Write([]byte(v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Encrypt 事件消息加密
//
//	[参考](https://dingtalk.apifox.cn/doc-392311)
func Encrypt(appkey, encodingAESKey, nonce string, plainText []byte) (*cryptokit.CipherText, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, err
	}

	contentLen := len(plainText)
	appidOffset := 20 + contentLen

	encryptData := make([]byte, appidOffset+len(appkey))

	copy(encryptData[:16], nonce)
	copy(encryptData[16:20], internal.EncodeUint32ToBytes(uint32(contentLen)))
	copy(encryptData[20:], plainText)
	copy(encryptData[appidOffset:], appkey)

	return cryptokit.AESEncryptCBC(key, key[:aes.BlockSize], encryptData)
}

// Decrypt 事件消息解密
//
//	[参考](https://dingtalk.apifox.cn/doc-392311)
func Decrypt(appkey, encodingAESKey, cipherText string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, err
	}

	decryptData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	plainText, err := cryptokit.AESDecryptCBC(key, key[:aes.BlockSize], decryptData)
	if err != nil {
		return nil, err
	}

	// 校验 appkey
	appidOffset := len(plainText) - len([]byte(appkey))
	if v := string(plainText[appidOffset:]); v != appkey {
		return nil, fmt.Errorf("appkey mismatch, want: %s, got: %s", appkey, v)
	}
	return plainText[20:appidOffset], nil
}

func Reply(appkey, token, encodingAESKey, msg string) (kvkit.KV, error) {
	nonce := internal.Nonce(16)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	ct, err := Encrypt(appkey, encodingAESKey, nonce, []byte(msg))
	if err != nil {
		return nil, err
	}

	encryptMsg := ct.String()

	return kvkit.KV{
		"encrypt":       encryptMsg,
		"msg_signature": SignWithSHA1(token, timestamp, nonce, encryptMsg),
		"timeStamp":     timestamp,
		"nonce":         nonce,
	}, nil
}
