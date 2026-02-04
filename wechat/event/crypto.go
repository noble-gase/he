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
//	[参考](https://developer.work.weixin.qq.com/document/path/90968)
func Encrypt(receiveID, encodingAESKey, nonce string, plainText []byte) (*cryptokit.CipherText, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, err
	}

	contentLen := len(plainText)
	appidOffset := 20 + contentLen

	encryptData := make([]byte, appidOffset+len(receiveID))

	copy(encryptData[:16], nonce)
	copy(encryptData[16:20], internal.EncodeUint32ToBytes(uint32(contentLen)))
	copy(encryptData[20:], plainText)
	copy(encryptData[appidOffset:], receiveID)

	return cryptokit.AESEncryptCBC(key, key[:aes.BlockSize], encryptData)
}

// Decrypt 事件消息解密
//
//	[参考](https://developer.work.weixin.qq.com/document/path/90968)
func Decrypt(receiveID, encodingAESKey, cipherText string) ([]byte, error) {
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

	// 校验 receiveid
	appidOffset := len(plainText) - len([]byte(receiveID))
	if v := string(plainText[appidOffset:]); v != receiveID {
		return nil, fmt.Errorf("receive_id mismatch, want: %s, got: %s", receiveID, v)
	}
	return plainText[20:appidOffset], nil
}

func Reply(receiveID, token, encodingAESKey string, msg kvkit.KV) (kvkit.KV, error) {
	str, err := internal.KVToXML(msg)
	if err != nil {
		return nil, err
	}

	nonce := internal.Nonce(16)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	ct, err := Encrypt(receiveID, encodingAESKey, nonce, []byte(str))
	if err != nil {
		return nil, err
	}

	encryptMsg := ct.String()

	return kvkit.KV{
		"Encrypt":      encryptMsg,
		"MsgSignature": SignWithSHA1(token, timestamp, nonce, encryptMsg),
		"TimeStamp":    timestamp,
		"Nonce":        nonce,
	}, nil
}
