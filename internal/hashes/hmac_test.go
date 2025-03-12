package hashes

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHMacSHA1(t *testing.T) {
	assert.Equal(t, "91744d74ad0305d399d8b2379d8c319c27719e20", HMacSHA1("iiinsomnia", "ILoveNobleGase"))
}

func TestHMacSHA256(t *testing.T) {
	assert.Equal(t, "f911c64b98472100cfe6210593336a28d5ba97d56480a5dc03f4157987e170a2", HMacSHA256("iiinsomnia", "ILoveNobleGase"))
}

func TestHMac(t *testing.T) {
	type args struct {
		hash crypto.Hash
		key  string
		s    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "md5",
			args: args{hash: crypto.MD5, key: "iiinsomnia", s: "ILoveNobleGase"},
			want: "ac98900ebe0ff24ce98b7f774893de7a",
		},
		{
			name: "sha1",
			args: args{hash: crypto.SHA1, key: "iiinsomnia", s: "ILoveNobleGase"},
			want: "91744d74ad0305d399d8b2379d8c319c27719e20",
		},
		{
			name: "sha224",
			args: args{hash: crypto.SHA224, key: "iiinsomnia", s: "ILoveNobleGase"},
			want: "650212709f90adbe5d72997c25d4a2421e30754cae7c659020e43c39",
		},
		{
			name: "sha256",
			args: args{hash: crypto.SHA256, key: "iiinsomnia", s: "ILoveNobleGase"},
			want: "f911c64b98472100cfe6210593336a28d5ba97d56480a5dc03f4157987e170a2",
		},
		{
			name: "sha384",
			args: args{hash: crypto.SHA384, key: "iiinsomnia", s: "ILoveNobleGase"},
			want: "369c2bcedc7363cb86adf1716a0924d0f9ff9fb1953d55fffc90a01545408ecf38a00bbacd614d734e8783d8b188d3e3",
		},
		{
			name: "sha512",
			args: args{hash: crypto.SHA512, key: "iiinsomnia", s: "ILoveNobleGase"},
			want: "ad6cd4a8fd049631ddacc0f67f52808c13688713d30c98a0a9a45bc3f23cf809bbd15c873393611f9f48ea129323c6045cea31a76a4e4eae9285a0ee09e64d78",
		},
	}
	for _, tt := range tests {
		v, err := HMac(tt.args.hash, tt.args.key, tt.args.s)

		assert.Nil(t, err)
		assert.Equal(t, tt.want, v)
	}
}
