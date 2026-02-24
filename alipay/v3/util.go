package v3

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

const (
	HeaderMethodOverride = "x-http-method-override"
	HeaderRequestID      = "alipay-request-id"
	HeaderTraceID        = "alipay-trace-id"
	HeaderRootCertSN     = "alipay-root-cert-sn"
	HeaderNonce          = "alipay-nonce"
	HeaderTimestamp      = "alipay-timestamp"
	HeaderEncryptType    = "alipay-encrypt-type"
	HeaderAppAuthToken   = "alipay-app-auth-token"
	HeaderSignature      = "alipay-signature"
)

const (
	TRADE_SUCCESS  = "TRADE_SUCCESS"
	TRADE_CLOSED   = "TRADE_CLOSED"
	TRADE_FINISHED = "TRADE_FINISHED"
	WAIT_BUYER_PAY = "WAIT_BUYER_PAY"
)

func exception(resp *resty.Response) error {
	ret := gjson.ParseBytes(resp.Body())
	return fmt.Errorf("%s (%s | %s)", resp.Status(), ret.Get("code").String(), ret.Get("message").String())
}

func SubCode(ret gjson.Result) string {
	return ret.Get("sub_code").String()
}

func SubMsg(ret gjson.Result) string {
	return ret.Get("sub_msg").String()
}
