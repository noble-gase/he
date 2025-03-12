package crypts

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAesCBC(t *testing.T) {
	key := "AES256Key-32Characters1234567890"
	iv := key[:16]
	data := "ILoveNobleGase"

	cipher, err := AESEncryptCBC([]byte(key), []byte(iv), []byte(data))
	assert.Nil(t, err)
	assert.Equal(t, "WDq8s1qdHCML8YLhfdmGRw==", cipher.String())

	plain, err := AESDecryptCBC([]byte(key), []byte(iv), cipher.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain))

	cipher2, err := AESEncryptCBC([]byte(key), []byte(iv), []byte(data), 32)
	assert.Nil(t, err)
	assert.Equal(t, "vjemH/hxbwNh+WXhkKseCu2GrM4O6bnaaKv59wgkRSE=", cipher2.String())

	plain2, err := AESDecryptCBC([]byte(key), []byte(iv), cipher2.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain2))
}

func TestAesECB(t *testing.T) {
	key := "AES256Key-32Characters1234567890"
	data := "ILoveNobleGase"

	cipher, err := AESEncryptECB([]byte(key), []byte(data))
	assert.Nil(t, err)
	assert.Equal(t, "oYDjdGHY8lK1/sJo750Waw==", cipher.String())

	plain, err := AESDecryptECB([]byte(key), cipher.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain))

	cipher2, err := AESEncryptECB([]byte(key), []byte(data), 32)
	assert.Nil(t, err)
	assert.Equal(t, "u0iDWHM8JMnRyJNCiCzKJNib2cOjUrx2FqMjmg3ZTZA=", cipher2.String())

	plain2, err := AESDecryptECB([]byte(key), cipher.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain2))
}

func TestAesGCM(t *testing.T) {
	key := "AES256Key-32Characters1234567890"
	nonce := key[:12]
	data := "ILoveNobleGase"
	aad := "IIInsomnia"

	cipher, err := AESEncryptGCM([]byte(key), []byte(nonce), []byte(data), []byte(aad), &GCMOption{})
	assert.Nil(t, err)
	assert.Equal(t, "qciumnROL4U9F0klEKhzE/DngAy/clYUsZGfcafh", cipher.String())
	assert.Equal(t, "qciumnROL4U9F0klEKg=", base64.StdEncoding.EncodeToString(cipher.Data()))
	assert.Equal(t, "cxPw54AMv3JWFLGRn3Gn4Q==", base64.StdEncoding.EncodeToString(cipher.Tag()))

	plain, err := AESDecryptGCM([]byte(key), []byte(nonce), cipher.Bytes(), []byte(aad), nil)
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain))
}
