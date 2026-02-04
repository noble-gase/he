package v2

import (
	"fmt"

	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

const CodeOK = "10000" // API请求成功

type KV = kvkit.KV

type X map[string]any

type GrantType string

const (
	OAuthCode    GrantType = "authorization_code"
	RefreshToken GrantType = "refresh_token"
)

const (
	TRADE_SUCCESS  = "TRADE_SUCCESS"
	TRADE_CLOSED   = "TRADE_CLOSED"
	TRADE_FINISHED = "TRADE_FINISHED"
	WAIT_BUYER_PAY = "WAIT_BUYER_PAY"
)

func ResultOK(ret gjson.Result) bool {
	return ret.Get("code").String() == CodeOK
}

func ResultErr(ret gjson.Result) error {
	code := ret.Get("code").String()
	if code == CodeOK {
		return nil
	}
	return fmt.Errorf("%s (%s | %s)", code, ret.Get("sub_code").String(), ret.Get("sub_msg").String())
}

func SubCode(ret gjson.Result) string {
	return ret.Get("sub_code").String()
}

func SubMsg(ret gjson.Result) string {
	return ret.Get("sub_msg").String()
}
