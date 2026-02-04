package cryptokit

import "strings"

// FormatPrivatePemRaw formats base64-encoded private key to PEM format
func FormatPrivatePemRaw(raw string, pemType PrivatePEMType) string {
	lineLen := 64
	rawLen := len(raw)

	var b strings.Builder

	b.WriteString("-----BEGIN ")
	b.WriteString(string(pemType))
	b.WriteString("-----\n")

	for i := 0; i < rawLen; i += lineLen {
		end := i + lineLen
		if end > rawLen {
			end = rawLen
		}
		b.WriteString(raw[i:end])
		b.WriteByte('\n')
	}

	b.WriteString("-----END ")
	b.WriteString(string(pemType))
	b.WriteString("-----\n")

	return b.String()
}

// FormatPublicPemRaw formats base64-encoded public key to PEM format
func FormatPublicPemRaw(raw string, pemType PublicPEMType) string {
	lineLen := 64
	rawLen := len(raw)

	var b strings.Builder

	b.WriteString("-----BEGIN ")
	b.WriteString(string(pemType))
	b.WriteString("-----\n")

	for i := 0; i < rawLen; i += lineLen {
		end := i + lineLen
		if end > rawLen {
			end = rawLen
		}
		b.WriteString(raw[i:end])
		b.WriteByte('\n')
	}

	b.WriteString("-----END ")
	b.WriteString(string(pemType))
	b.WriteString("-----\n")

	return b.String()
}
