package wecom

import (
	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

type X = internal.X

type KV = kvkit.KV

const AccessToken = "access_token"

// AuthScope 网页授权作用域
type AuthScope string

const (
	SnsapiBase        AuthScope = "snsapi_base"        // 静默授权，可获取基础信息
	SnsapiUser        AuthScope = "snsapi_userinfo"    // 手动授权(公众号)，可通过openid拿到昵称、性别、所在地。并且，即使在未关注的情况下，只要用户授权，也能获取其信息
	SnsapiPrivateInfo AuthScope = "snsapi_privateinfo" // 手动授权(企业微信)，可获取成员的详细信息，包含头像、二维码等敏感信息
)

func result(b []byte) (gjson.Result, error) {
	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.FailF("%d | %s", code, ret.Get("errmsg").String())
	}
	return ret, nil
}
