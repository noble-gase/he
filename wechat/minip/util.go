package minip

import (
	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

type X = internal.X

type KV = kvkit.KV

const AccessToken = "access_token"

const (
	HeaderAppID               = "Wechatmp-Appid"
	HeaderTimestamp           = "Wechatmp-TimeStamp"
	HeaderSerial              = "Wechatmp-Serial"
	HeaderSignature           = "Wechatmp-Signature"
	HeaderSerialDeprecated    = "Wechatmp-Serial-Deprecated"
	HeaderSignatureDeprecated = "Wechatmp-Signature-Deprecated"
)

func result(b []byte) (gjson.Result, error) {
	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.FailF("%d | %s", code, ret.Get("errmsg").String())
	}
	return ret, nil
}
