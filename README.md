# Polaris Mall API

Language: English | [中文](README.zh-CN.md)

`polaris-mall-api` contains the Go backend baseline for the first MVP slice.

## Implemented In This Step

- A001 baseline:
  - register
  - login
  - refresh token
  - current user query
- role-protected admin probe endpoint
- A002 baseline:
  - product list and detail
  - admin product create and update
- A003 baseline:
  - cart add, update, remove, and query
  - cart summary for checkout pre-calculation
- A004 baseline:
  - checkout pricing preview
  - shipping and discount extension points
  - deterministic trace id for same request input
- health endpoint
- in-memory store for rapid bootstrap
- Go unit tests for auth, RBAC, and product catalog behavior

## Directory Layout

```text
main.go
internal/server/
  server.go
  store.go
  token.go
  server_test.go
```

## Run Service

```powershell
go run .
```

Environment variables:

- `POLARIS_API_HOST` (default `127.0.0.1`)
- `POLARIS_API_PORT` (default `9000`)
- `POLARIS_API_TOKEN_SECRET` (default `dev-token-secret`)

## API Endpoints

- `GET /healthz`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me` (Bearer access token required)
- `GET /api/v1/admin/ping` (Bearer admin token required)
- `GET /api/v1/products`
- `GET /api/v1/products/{id}`
- `POST /api/v1/admin/products` (Bearer admin token required)
- `PATCH /api/v1/admin/products/{id}` (Bearer admin token required)
- `GET /api/v1/cart` (Bearer access token required)
- `GET /api/v1/cart/summary` (Bearer access token required)
- `POST /api/v1/cart/items` (Bearer access token required)
- `PATCH /api/v1/cart/items/{product_id}` (Bearer access token required)
- `DELETE /api/v1/cart/items/{product_id}` (Bearer access token required)
- `POST /api/v1/checkout/preview` (Bearer access token required)

## Run Tests

```powershell
go test ./...
```

Note:

- Go implementation is the active backend baseline.
