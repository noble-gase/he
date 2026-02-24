package v1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_VerifyEventMsg(t *testing.T) {
	c := NewClient("dingxxxxxx", "secret")
	c.SetServerConfig("tokenxxxx", "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus")

	err := c.VerifyEventMsg("f36f4ba5337d426c7d4bca0dbcb06b3ddc1388fc", "1605695694141", "WelUQl6bCqcBa2fM", "X1VSe9cTJUMZu60d3kyLYTrBq5578ZRJtteU94wG0Q4Uk6E/wQYeJRIC0/UFW5Wkya1Ihz9oXAdLlyC9TRaqsQ==")
	assert.Nil(t, err)
}

func Test_DecodeEventMsg(t *testing.T) {
	c := NewClient("dingxxxxxx", "secret")
	c.SetServerConfig("tokenxxxx", "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus")

	b, err := c.DecodeEventMsg("X1VSe9cTJUMZu60d3kyLYTrBq5578ZRJtteU94wG0Q4Uk6E/wQYeJRIC0/UFW5Wkya1Ihz9oXAdLlyC9TRaqsQ==")
	assert.Nil(t, err)
	fmt.Println(string(b))
}
