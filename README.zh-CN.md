# Polaris Mall API

语言：中文 | [English](README.md)

`polaris-mall-api` 是 Polaris Mall MVP 阶段的 Go 后端服务基线。

## 当前已实现

- A001 基线：
  - 注册
  - 登录
  - 刷新令牌
  - 当前用户查询
  - 管理员鉴权探针
- A002 基线：
  - 商品列表与详情
  - 管理员商品创建与更新
- A003 基线：
  - 购物车增删改查
  - 购物车汇总（结算预览）
- A004 基线：
  - 结算金额试算
  - 运费/优惠扩展点
  - 同输入下稳定输出 trace_id
- A005 基线：
  - 从购物车创建订单
  - 严格订单状态机流转
  - 待支付订单超时关单接口
- A006 基线：
  - 基于订单创建支付单
  - 回调签名验签
  - 重复回调幂等处理
- A007 基线：
  - 已支付订单的管理员发货
  - 买家/管理员物流轨迹查询
  - 买家确认收货与退款申请/查询
- `healthz` 健康检查
- 内存存储（用于快速启动）
- Go 单元测试覆盖鉴权、RBAC、商品目录、订单支付履约流程

## 目录结构

```text
main.go
internal/server/
  server.go
  store.go
  token.go
  server_test.go
```

## 启动服务

```powershell
go run .
```

环境变量：

- `POLARIS_API_HOST`（默认 `127.0.0.1`）
- `POLARIS_API_PORT`（默认 `9000`）
- `POLARIS_API_TOKEN_SECRET`（默认 `dev-token-secret`）
- `POLARIS_PAY_CALLBACK_SECRET`（默认 `dev-pay-callback-secret`）

## 接口列表

- `GET /healthz`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me`（需要 Bearer access token）
- `GET /api/v1/admin/ping`（需要 admin token）
- `GET /api/v1/products`
- `GET /api/v1/products/{id}`
- `POST /api/v1/admin/products`（需要 admin token）
- `PATCH /api/v1/admin/products/{id}`（需要 admin token）
- `GET /api/v1/cart`（需要 Bearer access token）
- `GET /api/v1/cart/summary`（需要 Bearer access token）
- `POST /api/v1/cart/items`（需要 Bearer access token）
- `PATCH /api/v1/cart/items/{product_id}`（需要 Bearer access token）
- `DELETE /api/v1/cart/items/{product_id}`（需要 Bearer access token）
- `POST /api/v1/checkout/preview`（需要 Bearer access token）
- `POST /api/v1/orders`（需要 Bearer access token）
- `GET /api/v1/orders`（需要 Bearer access token）
- `GET /api/v1/orders/{id}`（需要 Bearer access token）
- `POST /api/v1/orders/{id}/transitions`（需要 Bearer access token）
- `POST /api/v1/admin/orders/close-expired`（需要 admin token）
- `POST /api/v1/payments/create`（需要 Bearer access token）
- `GET /api/v1/payments/order/{order_id}`（需要 Bearer access token）
- `POST /api/v1/payments/callback/mockpay`（需在 `X-Mockpay-Signature` 传入签名）
- `POST /api/v1/admin/orders/{id}/ship`（需要 admin token）
- `GET /api/v1/orders/{id}/tracking`（需要 Bearer access token）
- `POST /api/v1/orders/{id}/confirm-delivery`（需要 Bearer access token）
- `POST /api/v1/orders/{id}/refunds`（需要 Bearer access token）
- `GET /api/v1/orders/{id}/refunds`（需要 Bearer access token）

## 运行测试

```powershell
go test ./...
```
