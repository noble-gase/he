package v2

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
	"github.com/tidwall/gjson"
)

const AccessToken = "access_token"

type X = internal.X

type KV = kvkit.KV

func exception(resp *resty.Response) error {
	ret := gjson.ParseBytes(resp.Body())
	return fmt.Errorf("%s | %s", ret.Get("code").String(), ret.Get("message").String())
}
