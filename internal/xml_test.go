package internal

import (
	"testing"

	"github.com/noble-gase/he/internal/kvkit"
	"github.com/stretchr/testify/assert"
)

func TestXML(t *testing.T) {
	m := kvkit.KV{
		"appid":     "wx2421b1c4370ec43b",
		"partnerid": "10000100",
		"prepayid":  "WX1217752501201407033233368018",
		"package":   "Sign=WXPay",
		"noncestr":  "5K8264ILTKCH16CQ2502SI8ZNMTM67VS",
		"timestamp": "1514363815",
	}
	x, err := KVToXML(m)
	assert.Nil(t, err)

	r, err := XMLToKV([]byte(x))
	assert.Nil(t, err)
	assert.Equal(t, m, r)
}
