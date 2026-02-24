package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	sign := SignWithSHA1("tokenxxxx", "1605695694141", "WelUQl6bCqcBa2fM", "X1VSe9cTJUMZu60d3kyLYTrBq5578ZRJtteU94wG0Q4Uk6E/wQYeJRIC0/UFW5Wkya1Ihz9oXAdLlyC9TRaqsQ==")
	t.Log(sign)
	assert.True(t, sign == "f36f4ba5337d426c7d4bca0dbcb06b3ddc1388fc")
}

func TestEncrypt(t *testing.T) {
	ret, err := Encrypt("dingxxxxxx", "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus", "randomxxx", []byte("success"))
	assert.Nil(t, err)
	t.Log(ret.String())
}

func TestDecrypt(t *testing.T) {
	b, err := Decrypt("dingxxxxxx", "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus", "X1VSe9cTJUMZu60d3kyLYTrBq5578ZRJtteU94wG0Q4Uk6E/wQYeJRIC0/UFW5Wkya1Ihz9oXAdLlyC9TRaqsQ==")
	assert.Nil(t, err)
	t.Log(string(b))
}

func TestReply(t *testing.T) {
	ret, err := Reply("dingxxxxxx", "tokenxxxx", "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus", "success")
	assert.Nil(t, err)
	t.Log(ret)
}
