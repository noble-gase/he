package wechat

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"

	"github.com/noble-gase/he/internal"
	"github.com/noble-gase/he/internal/crypts"
)

// SafeMode 安全鉴权模式配置
type SafeMode struct {
	aesSN  string
	aeskey string
	prvKey *crypts.PrivateKey
	pubSN  string
	pubKey *crypts.PublicKey
}

// MiniProgram 小程序
type MiniProgram struct {
	host   string
	appid  string
	secret string
	srvCfg ServerConfig
	sfMode SafeMode
	token  atomic.Value
	client *resty.Client

	logger func(ctx context.Context, err error, data map[string]string)
}

// AppID 返回appid
func (mp *MiniProgram) AppID() string {
	return mp.appid
}

// Secret 返回secret
func (mp *MiniProgram) Secret() string {
	return mp.secret
}

func (mp *MiniProgram) url(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(mp.host)
	if len(path) != 0 && path[0] != '/' {
		builder.WriteString("/")
	}
	builder.WriteString(path)
	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}

	return builder.String()
}

func (mp *MiniProgram) do(ctx context.Context, method, path string, header http.Header, query url.Values, params X) ([]byte, error) {
	reqURL := mp.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, mp.logger)

	var (
		body []byte
		err  error
	)

	if params != nil {
		body, err = json.Marshal(params)
		if err != nil {
			log.SetError(err)
			return nil, err
		}
		log.SetReqBody(string(body))
	}

	resp, err := mp.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(header).
		SetBody(body).
		Execute(method, reqURL)
	if err != nil {
		log.SetError(err)
		return nil, err
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode())
	}
	return resp.Body(), nil
}

func (mp *MiniProgram) doSafe(ctx context.Context, method, path string, query url.Values, params X) ([]byte, error) {
	reqURL := mp.url(path, query)

	log := internal.NewReqLog(method, reqURL)
	defer log.Do(ctx, mp.logger)

	now := time.Now().Unix()

	// 加密
	params, err := mp.encrypt(log, path, query, params, now)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	body, err := json.Marshal(params)
	if err != nil {
		log.SetError(err)
		return nil, err
	}
	log.SetReqBody(string(body))

	// 签名
	sign, err := mp.sign(path, now, body)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	reqHeader := http.Header{}
	reqHeader.Set(internal.HeaderContentType, internal.ContentJSON)
	reqHeader.Set(HeaderMPAppID, mp.appid)
	reqHeader.Set(HeaderMPTimestamp, strconv.FormatInt(now, 10))
	reqHeader.Set(HeaderMPSignature, sign)
	log.SetReqHeader(reqHeader)

	resp, err := mp.client.R().
		SetContext(ctx).
		SetHeaderMultiValues(reqHeader).
		SetBody(body).
		Execute(method, reqURL)
	if err != nil {
		log.SetError(err)
		return nil, err
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode())
	}

	// 验签
	if err = mp.verify(path, resp.Header(), resp.Body()); err != nil {
		log.SetError(err)
		return nil, err
	}

	// 解密
	data, err := mp.decrypt(path, resp.Header(), resp.Body())
	if err != nil {
		log.SetError(err)
		return nil, err
	}
	log.Set("origin_response_body", string(data))
	return data, nil
}

func (mp *MiniProgram) encrypt(log *internal.ReqLog, path string, query url.Values, params X, timestamp int64) (X, error) {
	if len(mp.sfMode.aeskey) == 0 {
		return nil, errors.New("missing aes-gcm key (forgotten configure?)")
	}

	if params == nil {
		params = X{}
	}

	params["_n"] = base64.StdEncoding.EncodeToString(internal.NonceByte(16))
	params["_appid"] = mp.appid
	params["_timestamp"] = timestamp

	for k, v := range query {
		if k != AccessToken && len(v) != 0 {
			params[k] = v[0]
		}
	}

	data, err := json.Marshal(params)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	log.Set("origin_request_body", string(data))

	key, err := base64.StdEncoding.DecodeString(mp.sfMode.aeskey)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	iv := internal.NonceByte(12)
	aad := fmt.Sprintf("%s|%s|%d|%s", mp.url(path, nil), mp.appid, timestamp, mp.sfMode.aesSN)

	ct, err := crypts.AESEncryptGCM(key, iv, data, []byte(aad), nil)
	if err != nil {
		log.SetError(err)
		return nil, err
	}

	body := X{
		"iv":      base64.StdEncoding.EncodeToString(iv),
		"data":    base64.StdEncoding.EncodeToString(ct.Data()),
		"authtag": base64.StdEncoding.EncodeToString(ct.Tag()),
	}
	return body, nil
}

func (mp *MiniProgram) sign(path string, timestamp int64, body []byte) (string, error) {
	if mp.sfMode.prvKey == nil {
		return "", errors.New("missing private key (forgotten configure?)")
	}

	var builder strings.Builder

	builder.WriteString(mp.url(path, nil))
	builder.WriteString("\n")
	builder.WriteString(mp.appid)
	builder.WriteString("\n")
	builder.WriteString(strconv.FormatInt(timestamp, 10))
	builder.WriteString("\n")
	builder.Write(body)

	b, err := mp.sfMode.prvKey.SignPSS(crypto.SHA256, []byte(builder.String()), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (mp *MiniProgram) verify(path string, header http.Header, body []byte) error {
	if mp.sfMode.pubKey == nil {
		return errors.New("missing public key (forgotten configure?)")
	}

	if appid := header.Get(HeaderMPAppID); appid != mp.appid {
		return fmt.Errorf("header appid mismatch, expect = %s", mp.appid)
	}

	var sign string
	if serial := header.Get(HeaderMPSerial); serial == mp.sfMode.pubSN {
		sign = header.Get(HeaderMPSignature)
	} else {
		serialDeprecated := header.Get(HeaderMPSerialDeprecated)
		if serialDeprecated != mp.sfMode.pubSN {
			return fmt.Errorf("header serial mismatch, expect = %s", mp.sfMode.pubSN)
		}
		sign = header.Get(HeaderMPSignatureDeprecated)
	}
	b, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	var builder strings.Builder

	builder.WriteString(mp.url(path, nil))
	builder.WriteString("\n")
	builder.WriteString(mp.appid)
	builder.WriteString("\n")
	builder.WriteString(header.Get(HeaderMPTimestamp))
	builder.WriteString("\n")
	builder.Write(body)

	return mp.sfMode.pubKey.VerifyPSS(crypto.SHA256, []byte(builder.String()), b, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func (mp *MiniProgram) decrypt(path string, header http.Header, body []byte) ([]byte, error) {
	if len(mp.sfMode.aeskey) == 0 {
		return nil, errors.New("missing aes-gcm key (forgotten configure?)")
	}

	key, err := base64.StdEncoding.DecodeString(mp.sfMode.aeskey)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(body)

	iv, err := base64.StdEncoding.DecodeString(ret.Get("iv").String())
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(ret.Get("data").String())
	if err != nil {
		return nil, err
	}

	tag, err := base64.StdEncoding.DecodeString(ret.Get("authtag").String())
	if err != nil {
		return nil, err
	}

	aad := fmt.Sprintf("%s|%s|%s|%s", mp.url(path, nil), mp.appid, header.Get(HeaderMPTimestamp), mp.sfMode.aesSN)

	return crypts.AESDecryptGCM(key, iv, append(data, tag...), []byte(aad), nil)
}

// Code2Session 通过临时登录凭证code完成登录流程
func (mp *MiniProgram) Code2Session(ctx context.Context, code string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", mp.appid)
	query.Set("secret", mp.secret)
	query.Set("js_code", code)
	query.Set("grant_type", "authorization_code")

	b, err := mp.do(ctx, http.MethodGet, "/sns/jscode2session", nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// AccessToken 获取接口调用凭据
func (mp *MiniProgram) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", mp.appid)
	query.Set("secret", mp.secret)
	query.Set("grant_type", "client_credential")

	b, err := mp.do(ctx, http.MethodGet, "/cgi-bin/token", nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// StableAccessToken 获取稳定版接口调用凭据
//
//	有两种调用模式:
//	[普通模式] access_token有效期内重复调用该接口不会更新access_token，绝大部分场景下使用该模式；
//	[强制刷新模式] 会导致上次获取的access_token失效，并返回新的access_token
func (mp *MiniProgram) StableAccessToken(ctx context.Context, forceRefresh bool) (gjson.Result, error) {
	params := X{
		"grant_type":    "client_credential",
		"appid":         mp.appid,
		"secret":        mp.secret,
		"force_refresh": forceRefresh,
	}

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := mp.do(ctx, http.MethodPost, "/cgi-bin/stable_token", header, nil, params)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// AutoLoadAccessToken 自动加载AccessToken(使用StableAccessToken接口)
func (mp *MiniProgram) AutoLoadAccessToken(interval time.Duration) error {
	ctx := context.Background()

	// 初始化AccessToken
	ret, err := mp.StableAccessToken(context.Background(), false)
	if err != nil {
		return err
	}
	mp.token.Store(ret.Get("access_token").String())

	// 异步定时加载
	go func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			_ret, _ := mp.StableAccessToken(ctx, false)
			if token := _ret.Get("access_token").String(); len(token) != 0 {
				mp.token.Store(token)
			}
		}
	}(ctx)
	return nil
}

// CustomAccessTokenLoad 自定义加载AccessToken
func (mp *MiniProgram) CustomAccessTokenLoad(fn func(ctx context.Context, mp *MiniProgram) (string, error), interval time.Duration) error {
	ctx := context.Background()

	// 初始化AccessToken
	token, err := fn(ctx, mp)
	if err != nil {
		return err
	}
	mp.token.Store(token)

	// 异步定时加载
	go func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			_token, _ := fn(ctx, mp)
			if len(token) != 0 {
				mp.token.Store(_token)
			}
		}
	}(ctx)

	return nil
}

func (mp *MiniProgram) getToken() (string, error) {
	v := mp.token.Load()
	if v == nil {
		return "", errors.New("access_token is empty (forgotten auto load?)")
	}
	token, ok := v.(string)
	if !ok {
		return "", errors.New("access_token is not a string")
	}
	return token, nil
}

// GetJSON GET请求JSON数据
func (mp *MiniProgram) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	token, err := mp.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	b, err := mp.do(ctx, http.MethodGet, path, nil, query, nil)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// GetBuffer GET请求获取buffer (如：获取媒体资源)
func (mp *MiniProgram) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := mp.getToken()
	if err != nil {
		return nil, err
	}
	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	b, err := mp.do(ctx, http.MethodGet, path, nil, query, nil)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String())
	}
	return b, nil
}

// PostJSON POST请求JSON数据
func (mp *MiniProgram) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := mp.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := mp.do(ctx, http.MethodPost, path, header, query, params)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// PostBuffer POST请求获取buffer (如：获取二维码)
func (mp *MiniProgram) PostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := mp.getToken()
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	header := http.Header{}
	header.Set(internal.HeaderContentType, internal.ContentJSON)

	b, err := mp.do(ctx, http.MethodPost, path, header, query, params)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String())
	}
	return b, nil
}

// SafePostJSON POST请求JSON数据
//
//	[安全鉴权模式](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html)
//	[支持的API](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc)
func (mp *MiniProgram) SafePostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := mp.getToken()
	if err != nil {
		return internal.Fail(err)
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	b, err := mp.doSafe(ctx, http.MethodPost, path, query, params)
	if err != nil {
		return internal.Fail(err)
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// SafePostBuffer POST请求获取buffer (如：获取二维码)
//
//	[安全鉴权模式](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html)
//	[支持的API](https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc)
func (mp *MiniProgram) SafePostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := mp.getToken()
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set(AccessToken, token)

	b, err := mp.doSafe(ctx, http.MethodPost, path, query, params)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String())
	}
	return b, nil
}

// Upload 上传媒体资源
func (mp *MiniProgram) Upload(ctx context.Context, reqPath, fieldName, filePath string, formData Form, query url.Values) (gjson.Result, error) {
	token, err := mp.getToken()
	if err != nil {
		return internal.Fail(err)
	}

	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	reqURL := mp.url(reqPath, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.client.R().
		SetContext(ctx).
		SetFile(fieldName, filePath).
		SetFormData(formData).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return internal.Fail(err)
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return internal.Fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode()))
	}

	ret := gjson.ParseBytes(resp.Body())
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// UploadWithReader 上传媒体资源
func (mp *MiniProgram) UploadWithReader(ctx context.Context, reqPath, fieldName, fileName string, reader io.Reader, formData Form, query url.Values) (gjson.Result, error) {
	token, err := mp.getToken()
	if err != nil {
		return internal.Fail(err)
	}

	if query == nil {
		query = url.Values{}
	}
	query.Set(AccessToken, token)

	reqURL := mp.url(reqPath, query)

	log := internal.NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.client.R().
		SetContext(ctx).
		SetMultipartField(fieldName, fileName, "", reader).
		SetFormData(formData).
		Post(reqURL)
	if err != nil {
		log.SetError(err)
		return internal.Fail(err)
	}
	log.SetRespHeader(resp.Header())
	log.SetStatusCode(resp.StatusCode())
	log.SetRespBody(string(resp.Body()))
	if !resp.IsSuccess() {
		return internal.Fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode()))
	}

	ret := gjson.ParseBytes(resp.Body())
	if code := ret.Get("errcode").Int(); code != 0 {
		return internal.Fail(fmt.Errorf("[%d] %s", code, ret.Get("errmsg").String()))
	}
	return ret, nil
}

// DecodeEncryptData 解析加密数据，如：授权的用户信息和手机号
//
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/signature.html)
func (mp *MiniProgram) DecodeEncryptData(sessionKey, iv, encryptData string) ([]byte, error) {
	keyBlock, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("session_key base64.decode error: %w", err)
	}
	ivBlock, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, fmt.Errorf("iv base64.decode error: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, fmt.Errorf("encrypt_data base64.decode error: %w", err)
	}
	return crypts.AESDecryptCBC(keyBlock, ivBlock, data)
}

// VerifyEventMsg 验证事件消息
//
//	[服务器URL验证]
//	URL参数中的 signature、timestamp、nonce
//	注意：验证成功后，原样返回 echostr 字段值
//
//	[事件消息验证]
//	[明文模式] URL参数中的 signature、timestamp、nonce
//	[安全模式] URL参数中的 msg_signature、timestamp、nonce 和包体内的 Encrypt 字段
//
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) VerifyEventMsg(signature string, items ...string) error {
	if len(mp.srvCfg.token) == 0 || len(mp.srvCfg.aeskey) == 0 {
		return errors.New("missing server config (forgotten configure?)")
	}
	if v := SignWithSHA1(mp.srvCfg.token, items...); v != signature {
		return fmt.Errorf("signature verified fail, expect=%s, actual=%s", signature, v)
	}
	return nil
}

// DecodeEventMsg 事件消息解密
//
//	使用包体内的 Encrypt 字段
//	根据配置的数据格式，解析 XML/JSON
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) DecodeEventMsg(encrypt string) ([]byte, error) {
	if len(mp.srvCfg.token) == 0 || len(mp.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return EventDecrypt(mp.appid, mp.srvCfg.aeskey, encrypt)
}

// EncodeEventReply 事件回复加密
//
//	根据配置的数据格式，输出 XML/JSON
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) EncodeEventReply(msg V) (V, error) {
	if len(mp.srvCfg.token) == 0 || len(mp.srvCfg.aeskey) == 0 {
		return nil, errors.New("missing server config (forgotten configure?)")
	}
	return EventReply(mp.appid, mp.srvCfg.token, mp.srvCfg.aeskey, msg)
}

// MPOption 小程序设置项
type MPOption func(mp *MiniProgram)

// WithMPSrvCfg 设置小程序服务器配置
//
//	[参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func WithMPSrvCfg(token, aeskey string) MPOption {
	return func(mp *MiniProgram) {
		mp.srvCfg.token = token
		mp.srvCfg.aeskey = aeskey
	}
}

// WithMPClient 设置小程序请求的 HTTP Client
func WithMPClient(cli *http.Client) MPOption {
	return func(mp *MiniProgram) {
		mp.client = resty.NewWithClient(cli)
	}
}

// WithMPLogger 设置小程序日志记录
func WithMPLogger(fn func(ctx context.Context, err error, data map[string]string)) MPOption {
	return func(mp *MiniProgram) {
		mp.logger = fn
	}
}

// WithMPAesKey 设置小程序 AES-GCM 加密Key
func WithMPAesKey(serialNO, key string) MPOption {
	return func(mp *MiniProgram) {
		mp.sfMode.aesSN = serialNO
		mp.sfMode.aeskey = key
	}
}

// WithMPPrivateKey 设置小程序RSA私钥
func WithMPPrivateKey(key *crypts.PrivateKey) MPOption {
	return func(mp *MiniProgram) {
		mp.sfMode.prvKey = key
	}
}

// WithMPPublicKey 设置小程序平台RSA公钥
func WithMPPublicKey(serialNO string, key *crypts.PublicKey) MPOption {
	return func(mp *MiniProgram) {
		mp.sfMode.pubSN = serialNO
		mp.sfMode.pubKey = key
	}
}

// NewMiniProgram 生成一个小程序实例
func NewMiniProgram(appid, secret string, options ...MPOption) *MiniProgram {
	mp := &MiniProgram{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
		client: internal.NewClient(),
	}
	for _, f := range options {
		f(mp)
	}
	return mp
}
