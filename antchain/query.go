package antchain

import (
	"context"
	"fmt"
)

// QueryTransaction 查询交易
func (c *Client) QueryTransaction(ctx context.Context, hash string) (string, error) {
	return c.chainCall(ctx, "QUERYTRANSACTION", WithParam("hash", hash))
}

// QueryReceipt 查询交易回执
func (c *Client) QueryReceipt(ctx context.Context, hash string) (string, error) {
	return c.chainCall(ctx, "QUERYRECEIPT", WithParam("hash", hash))
}

// QueryBlockHeader 查询块头
func (c *Client) QueryBlockHeader(ctx context.Context, blockNumber int64) (string, error) {
	return c.chainCall(ctx, "QUERYBLOCK", WithParam("requestStr", blockNumber))
}

// QueryBlockBody 查询块体
func (c *Client) QueryBlockBody(ctx context.Context, blockNumber int64) (string, error) {
	return c.chainCall(ctx, "QUERYBLOCKBODY", WithParam("requestStr", blockNumber))
}

// QueryLastBlock 查询最新块高
func (c *Client) QueryLastBlock(ctx context.Context) (string, error) {
	return c.chainCall(ctx, "QUERYLASTBLOCK")
}

// QueryAccount 查询账户
func (c *Client) QueryAccount(ctx context.Context, account string) (string, error) {
	return c.chainCall(ctx, "QUERYACCOUNT", WithParam("requestStr", fmt.Sprintf(`{"queryAccount":"%s"}`, account)))
}
