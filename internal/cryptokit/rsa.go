package cryptokit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/pkcs12"
)

type PrivatePEMType string

const (
	RSA_PRIVATE_KEY PrivatePEMType = "RSA PRIVATE KEY" // PKCS#1
	PRIVATE_KEY     PrivatePEMType = "PRIVATE KEY"     // PKCS#8
)

type PublicPEMType string

const (
	RSA_PUBLIC_KEY PublicPEMType = "RSA PUBLIC KEY" // PKCS#1
	PUBLIC_KEY     PublicPEMType = "PUBLIC KEY"     // PKCS#8
	CERTIFICATE    PublicPEMType = "CERTIFICATE"    // X.509 证书
)

// ------------------------------------ private-key ------------------------------------

// PrivateKey RSA私钥
type PrivateKey struct {
	key *rsa.PrivateKey
}

// Decrypt RSA私钥 PKCS#1 v1.5 解密
func (pk *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pk.key, data)
}

// DecryptOAEP RSA私钥 PKCS#1 OAEP 解密
func (pk *PrivateKey) DecryptOAEP(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	return rsa.DecryptOAEP(hash.New(), rand.Reader, pk.key, data, nil)
}

// Sign RSA私钥签名
func (pk *PrivateKey) Sign(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	return rsa.SignPKCS1v15(rand.Reader, pk.key, hash, h.Sum(nil))
}

// SignPSS RSA私钥签名(PSS填充)
func (pk *PrivateKey) SignPSS(hash crypto.Hash, data []byte, opts *rsa.PSSOptions) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	return rsa.SignPSS(rand.Reader, pk.key, hash, h.Sum(nil), opts)
}

// NewPrivateKey 生成RSA私钥
func NewPrivateKey(data []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}

	switch PrivatePEMType(block.Type) {
	case RSA_PRIVATE_KEY:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{key: key}, nil
	case PRIVATE_KEY:
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8: not a private key")
		}
		return &PrivateKey{key: key}, nil
	}
	return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
}

// PfxToPrivateKey pfx(p12)证书生成RSA私钥
//
//	注意：证书需采用「TripleDES-SHA1」加密方式
func PfxToPrivateKey(pfxData []byte, password string) (*PrivateKey, error) {
	cert, err := PfxToCert(pfxData, password)
	if err != nil {
		return nil, err
	}
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not a private key")
	}
	return &PrivateKey{key: key}, nil
}

// ------------------------------------ public-key ------------------------------------

// PublicKey RSA公钥
type PublicKey struct {
	key *rsa.PublicKey
}

// Encrypt RSA公钥 PKCS#1 v1.5 加密
func (pk *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pk.key, data)
}

// EncryptOAEP RSA公钥 PKCS#1 OAEP 加密
func (pk *PublicKey) EncryptOAEP(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}
	return rsa.EncryptOAEP(hash.New(), rand.Reader, pk.key, data, nil)
}

// Verify RSA公钥验签
func (pk *PublicKey) Verify(hash crypto.Hash, data, signature []byte) error {
	if !hash.Available() {
		return fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(pk.key, hash, h.Sum(nil), signature)
}

// VerifyPSS RSA公钥验签(PSS填充)
func (pk *PublicKey) VerifyPSS(hash crypto.Hash, data, signature []byte, opts *rsa.PSSOptions) error {
	if !hash.Available() {
		return fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)
	return rsa.VerifyPSS(pk.key, hash, h.Sum(nil), signature, opts)
}

// NewPublicKey 生成RSA公钥
//
//	X.509证书格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
//	X.509证书转换PEM: openssl x509 -inform der -in cert.cer -out cert.pem
func NewPublicKey(data []byte) (*PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	switch PublicPEMType(block.Type) {
	case RSA_PUBLIC_KEY: // PKCS#1
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#1: %w", err)
		}
		return &PublicKey{key: key}, nil
	case PUBLIC_KEY: // PKIX
		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKIX: %w", err)
		}

		key, ok := pk.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("PKIX: not a public key")
		}
		return &PublicKey{key: key}, nil
	case CERTIFICATE: // X.509 证书
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("X.509: %w", err)
		}

		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("X.509: not a public key")
		}
		return &PublicKey{key: key}, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}

// LoadCertFromPfxFile 通过pfx(p12)证书文件生成TLS证书
// 注意：证书需采用「TripleDES-SHA1」加密方式
func PfxToCert(pfxData []byte, password string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	blocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return fail(err)
	}

	var certPEM, keyPEM []byte
	for _, b := range blocks {
		switch b.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			keyPEM = pem.EncodeToMemory(b)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fail(errors.New("pfx missing cert or key"))
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
