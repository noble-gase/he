package v1

import (
	"github.com/noble-gase/he/internal"
	"github.com/tidwall/gjson"
)

const AccessToken = "access_token"

func result(b []byte) (gjson.Result, error) {
	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.FailF("%d | %s", code, ret.Get("errmsg").String())
	}
	return ret, nil
}
