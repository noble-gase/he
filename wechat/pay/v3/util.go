package v3

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

type X = internal.X

type KV = kvkit.KV

const (
	HeaderRequestID = "Request-ID"
	HeaderNonce     = "Wechatpay-Nonce"
	HeaderTimestamp = "Wechatpay-Timestamp"
	HeaderSerial    = "Wechatpay-Serial"
	HeaderSignature = "Wechatpay-Signature"
)

const TRANSACTION_SUCCESS = "TRANSACTION.SUCCESS" // 事件类型：支付成功通知

const (
	TRADE_SUCCESS    = "SUCCESS"    // 支付成功
	TRADE_REFUND     = "REFUND"     // 转入退款
	TRADE_NOTPAY     = "NOTPAY"     // 未支付
	TRADE_CLOSED     = "CLOSED"     // 已关闭
	TRADE_REVOKED    = "REVOKED"    // 已撤销（仅付款码支付会返回）
	TRADE_USERPAYING = "USERPAYING" // 用户支付中（仅付款码支付会返回）
	TRADE_PAYERROR   = "PAYERROR"   // 支付失败（仅付款码支付会返回）
)

const AuthFmt = `WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`

func exception(resp *resty.Response) error {
	ret := gjson.ParseBytes(resp.Body())
	return fmt.Errorf("%s (%s | %s)", resp.Status(), ret.Get("code").String(), ret.Get("message").String())
}
