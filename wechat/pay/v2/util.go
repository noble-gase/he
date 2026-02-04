package v2

import (
	"fmt"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/kvkit"
)

type XML = kvkit.KV

var (
	KVToXML = internal.KVToXML
	XMLToKV = internal.XMLToKV
)

// SignAlgo 签名算法
type SignAlgo string

const (
	SignMD5        SignAlgo = "MD5"
	SignHMacSHA256 SignAlgo = "HMAC-SHA256"
)

// 支付v2返回结果
const (
	ResultSuccess = "SUCCESS"
	ResultFail    = "FAIL"
	ResultNull    = "RESULT NULL" // 查询结果为空
)

// 支付v2错误码
const (
	SystemError        = "SYSTEMERROR"           // 系统繁忙，请稍后再试
	ParamError         = "PARAM_ERROR"           // 参数错误
	SignError          = "SIGNERROR"             // 签名错误
	LackParams         = "LACK_PARAMS"           // 缺少参数
	NotUTF8            = "NOT_UTF8"              // 编码格式错误
	NoAuth             = "NOAUTH"                // 商户无权限
	NotFound           = "NOT_FOUND"             // 数据不存在
	NotEnough          = "NOTENOUGH"             // 余额不足
	NotSupportCard     = "NOTSUPORTCARD"         // 不支持的卡类型
	UserPaying         = "USERPAYING"            // 用户支付中，需要输入密码
	AppIDNotExist      = "APPID_NOT_EXIST"       // APPID不存在
	MchIDNotExist      = "MCHID_NOT_EXIST"       // MCHID不存在
	AppIDMchIDNotMatch = "APPID_MCHID_NOT_MATCH" // appid和mch_id不匹配
	AuthCodeExpire     = "AUTHCODEEXPIRE"        // 二维码已过期，请用户在微信上刷新后再试
	AuthCodeError      = "AUTH_CODE_ERROR"       // 付款码参数错误
	AuthCodeInvalid    = "AUTH_CODE_INVALID"     // 付款码检验错误
	BankError          = "BANKERROR"             // 银行系统异常
	OrderNotExist      = "ORDERNOTEXIST"         // 订单不存在
	OrderPaid          = "ORDERPAID"             // 订单已支付
	OrderClosed        = "ORDERCLOSED"           // 订单已关闭
	OrderReversed      = "ORDERREVERSED"         // 订单已撤销
	RefundNotExist     = "REFUNDNOTEXIST"        // 退款不存在
	BuyerMismatch      = "BUYER_MISMATCH"        // 支付账号错误
	OutTradeNoUsed     = "OUT_TRADE_NO_USED"     // 商户订单号重复
	XmlFormatError     = "XML_FORMAT_ERROR"      // XML格式错误
	RequestPostMethod  = "REQUIRE_POST_METHOD"   // 请使用post方法
	PostDataEmpty      = "POST_DATA_EMPTY"       // post数据为空
	InvalidRequest     = "INVALID_REQUEST"       // 无效请求
	TradeError         = "TRADE_ERROR"           // 交易错误
	URLFormatError     = "URLFORMATERROR"        // URL格式错误
)

func result(b []byte) (XML, error) {
	ret, err := XMLToKV(b)
	if err != nil {
		return nil, err
	}

	if code := ret.Get("return_code"); code != ResultSuccess {
		return nil, fmt.Errorf("%s | %s", code, ret.Get("return_msg"))
	}
	return ret, nil
}

func errFromXML(v XML) error {
	return fmt.Errorf("%s (%s | %s)", v.Get("return_code"), v.Get("error_code"), v.Get("err_code_des"))
}

func ResultCode(v XML) string {
	return v.Get("result_code")
}

func ErrCode(v XML) string {
	return v.Get("err_code")
}

func ErrCodeDes(v XML) string {
	return v.Get("err_code_des")
}
