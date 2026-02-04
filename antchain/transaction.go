package antchain

import "context"

// CreateAccount 创建账户
func (c *Client) CreateAccount(ctx context.Context, account, kmsID string, gas int) (string, error) {
	return c.chainCallForBiz(ctx, "TENANTCREATEACCUNT",
		WithParam("newAccountId", account),
		WithParam("newAccountKmsId", kmsID),
		WithParam("gas", gas),
	)
}

// Deposit 存证
func (c *Client) Deposit(ctx context.Context, content string, gas int) (string, error) {
	return c.chainCallForBiz(ctx, "DEPOSIT",
		WithParam("content", content),
		WithParam("gas", gas),
	)
}

// DeploySolidity 部署Solidity合约
func (c *Client) DeploySolidity(ctx context.Context, name, code string, gas int) (string, error) {
	return c.chainCallForBiz(ctx, "DEPLOYCONTRACTFORBIZ",
		WithParam("contractName", name),
		WithParam("contractCode", code),
		WithParam("gas", gas),
	)
}

// AsyncCallSolidity 异步调用Solidity合约
func (c *Client) AsyncCallSolidity(ctx context.Context, contractName, methodSign, inputParams, outTypes string, gas int) (string, error) {
	return c.chainCallForBiz(ctx, "CALLCONTRACTBIZASYNC",
		WithParam("contractName", contractName),
		WithParam("methodSignature", methodSign),
		WithParam("inputParamListStr", inputParams),
		WithParam("outTypes", outTypes),
		WithParam("gas", gas),
	)
}
