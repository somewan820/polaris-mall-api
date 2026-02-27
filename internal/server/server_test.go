package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testResponse struct {
	Status int
	Body   map[string]any
}

func TestRegisterLoginMe(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	registerResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "buyer@example.com",
		"password": "buyer-pass",
	}, "")
	if registerResp.Status != http.StatusCreated {
		t.Fatalf("register status = %d, want %d", registerResp.Status, http.StatusCreated)
	}

	loginResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "buyer@example.com",
		"password": "buyer-pass",
	}, "")
	if loginResp.Status != http.StatusOK {
		t.Fatalf("login status = %d, want %d", loginResp.Status, http.StatusOK)
	}
	accessToken := toString(loginResp.Body["access_token"])
	if accessToken == "" {
		t.Fatalf("missing access token")
	}

	meResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/auth/me", nil, accessToken)
	if meResp.Status != http.StatusOK {
		t.Fatalf("me status = %d, want %d", meResp.Status, http.StatusOK)
	}
	user := meResp.Body["user"].(map[string]any)
	if toString(user["email"]) != "buyer@example.com" {
		t.Fatalf("me email = %v, want buyer@example.com", user["email"])
	}
}

func TestRefreshRotation(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "member@example.com",
		"password": "member-pass",
	}, "")
	loginResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "member@example.com",
		"password": "member-pass",
	}, "")
	oldRefresh := toString(loginResp.Body["refresh_token"])

	refreshResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": oldRefresh,
	}, "")
	if refreshResp.Status != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d", refreshResp.Status, http.StatusOK)
	}
	newRefresh := toString(refreshResp.Body["refresh_token"])
	if newRefresh == "" || newRefresh == oldRefresh {
		t.Fatalf("refresh token rotation failed")
	}

	oldRefreshResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": oldRefresh,
	}, "")
	if oldRefreshResp.Status != http.StatusUnauthorized {
		t.Fatalf("old refresh status = %d, want %d", oldRefreshResp.Status, http.StatusUnauthorized)
	}
}

func TestAdminEndpointRoleCheck(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "buyer2@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "buyer2@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])

	buyerPing := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/admin/ping", nil, buyerToken)
	if buyerPing.Status != http.StatusForbidden {
		t.Fatalf("buyer ping status = %d, want %d", buyerPing.Status, http.StatusForbidden)
	}

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])
	adminPing := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/admin/ping", nil, adminToken)
	if adminPing.Status != http.StatusOK {
		t.Fatalf("admin ping status = %d, want %d", adminPing.Status, http.StatusOK)
	}
}

func TestCatalogAdminCreateAndPublicFilter(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "catalog-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "catalog-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])

	online := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Demo Product Online",
		"description":  "Visible to storefront",
		"price_cents":  19900,
		"stock":        10,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	if online.Status != http.StatusCreated {
		t.Fatalf("online create status = %d, want %d", online.Status, http.StatusCreated)
	}
	onlineID := toString(online.Body["item"].(map[string]any)["id"])

	offline := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Demo Product Offline",
		"description":  "Hidden from storefront",
		"price_cents":  29900,
		"stock":        2,
		"category":     "demo",
		"shelf_status": "offline",
	}, adminToken)
	if offline.Status != http.StatusCreated {
		t.Fatalf("offline create status = %d, want %d", offline.Status, http.StatusCreated)
	}
	offlineID := toString(offline.Body["item"].(map[string]any)["id"])

	listResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/products", nil, "")
	if listResp.Status != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.Status, http.StatusOK)
	}
	items := listResp.Body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("list items len = %d, want 1", len(items))
	}
	firstID := toString(items[0].(map[string]any)["id"])
	if firstID != onlineID {
		t.Fatalf("list first id = %s, want %s", firstID, onlineID)
	}

	hiddenDetail := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/products/"+offlineID, nil, "")
	if hiddenDetail.Status != http.StatusNotFound {
		t.Fatalf("hidden detail status = %d, want %d", hiddenDetail.Status, http.StatusNotFound)
	}

	patch := callJSON(t, httpSrv.URL, http.MethodPatch, "/api/v1/admin/products/"+offlineID, map[string]any{
		"shelf_status": "online",
	}, adminToken)
	if patch.Status != http.StatusOK {
		t.Fatalf("patch status = %d, want %d", patch.Status, http.StatusOK)
	}

	visibleDetail := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/products/"+offlineID, nil, "")
	if visibleDetail.Status != http.StatusOK {
		t.Fatalf("visible detail status = %d, want %d", visibleDetail.Status, http.StatusOK)
	}
}

func TestCartAddUpdateRemoveAndSummary(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "cart-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "cart-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])

	createProduct := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Cart Product",
		"description":  "Used in cart tests",
		"price_cents":  1000,
		"stock":        5,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	if createProduct.Status != http.StatusCreated {
		t.Fatalf("create product status = %d, want %d", createProduct.Status, http.StatusCreated)
	}
	productID := toString(createProduct.Body["item"].(map[string]any)["id"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "buyer-cart@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "buyer-cart@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])

	addResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   2,
	}, buyerToken)
	if addResp.Status != http.StatusOK {
		t.Fatalf("add cart status = %d, want %d", addResp.Status, http.StatusOK)
	}
	addSummary := addResp.Body["summary"].(map[string]any)
	if toInt(addSummary["total_quantity"]) != 2 {
		t.Fatalf("cart total quantity = %d, want 2", toInt(addSummary["total_quantity"]))
	}

	getResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/cart", nil, buyerToken)
	if getResp.Status != http.StatusOK {
		t.Fatalf("get cart status = %d, want %d", getResp.Status, http.StatusOK)
	}
	items := getResp.Body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("cart items len = %d, want 1", len(items))
	}
	first := items[0].(map[string]any)
	if toInt(first["quantity"]) != 2 {
		t.Fatalf("item quantity = %d, want 2", toInt(first["quantity"]))
	}

	updateResp := callJSON(t, httpSrv.URL, http.MethodPatch, "/api/v1/cart/items/"+productID, map[string]any{
		"quantity": 4,
	}, buyerToken)
	if updateResp.Status != http.StatusOK {
		t.Fatalf("update cart status = %d, want %d", updateResp.Status, http.StatusOK)
	}
	updateSummary := updateResp.Body["summary"].(map[string]any)
	if toInt(updateSummary["total_quantity"]) != 4 {
		t.Fatalf("updated total quantity = %d, want 4", toInt(updateSummary["total_quantity"]))
	}

	overStockResp := callJSON(t, httpSrv.URL, http.MethodPatch, "/api/v1/cart/items/"+productID, map[string]any{
		"quantity": 99,
	}, buyerToken)
	if overStockResp.Status != http.StatusBadRequest {
		t.Fatalf("over stock status = %d, want %d", overStockResp.Status, http.StatusBadRequest)
	}

	deleteResp := callJSON(t, httpSrv.URL, http.MethodDelete, "/api/v1/cart/items/"+productID, nil, buyerToken)
	if deleteResp.Status != http.StatusOK {
		t.Fatalf("delete cart status = %d, want %d", deleteResp.Status, http.StatusOK)
	}

	summaryResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/cart/summary", nil, buyerToken)
	if summaryResp.Status != http.StatusOK {
		t.Fatalf("summary status = %d, want %d", summaryResp.Status, http.StatusOK)
	}
	summary := summaryResp.Body["summary"].(map[string]any)
	if toInt(summary["total_quantity"]) != 0 {
		t.Fatalf("summary total quantity = %d, want 0", toInt(summary["total_quantity"]))
	}

	noTokenResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/cart", nil, "")
	if noTokenResp.Status != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want %d", noTokenResp.Status, http.StatusUnauthorized)
	}
}

func TestCheckoutPreviewDeterministicAndCappedDiscount(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "checkout-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "checkout-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])
	createProduct := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Checkout Product",
		"description":  "Used in checkout tests",
		"price_cents":  1000,
		"stock":        5,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	productID := toString(createProduct.Body["item"].(map[string]any)["id"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "checkout-buyer@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "checkout-buyer@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])
	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   2,
	}, buyerToken)

	previewBody := map[string]any{
		"shipping_cents": 500,
		"discount_cents": 200,
		"coupon_code":    "SPRING",
	}
	previewA := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/checkout/preview", previewBody, buyerToken)
	previewB := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/checkout/preview", previewBody, buyerToken)
	if previewA.Status != http.StatusOK || previewB.Status != http.StatusOK {
		t.Fatalf("preview status = %d/%d, want %d", previewA.Status, previewB.Status, http.StatusOK)
	}
	traceA := toString(previewA.Body["trace_id"])
	traceB := toString(previewB.Body["trace_id"])
	if traceA == "" || traceA != traceB {
		t.Fatalf("trace_id should be deterministic, got %s and %s", traceA, traceB)
	}
	pricing := previewA.Body["pricing"].(map[string]any)
	if toInt(pricing["total_cents"]) != 2300 {
		t.Fatalf("total_cents = %d, want 2300", toInt(pricing["total_cents"]))
	}

	capped := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/checkout/preview", map[string]any{
		"shipping_cents": 500,
		"discount_cents": 9999,
		"coupon_code":    "SPRING",
	}, buyerToken)
	if capped.Status != http.StatusOK {
		t.Fatalf("capped preview status = %d, want %d", capped.Status, http.StatusOK)
	}
	cappedPricing := capped.Body["pricing"].(map[string]any)
	if toInt(cappedPricing["discount_cents"]) != 2500 {
		t.Fatalf("discount_cents = %d, want 2500", toInt(cappedPricing["discount_cents"]))
	}
	if toInt(cappedPricing["total_cents"]) != 0 {
		t.Fatalf("total_cents = %d, want 0", toInt(cappedPricing["total_cents"]))
	}

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "empty-cart@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	emptyLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "empty-cart@example.com",
		"password": "buyer-pass",
	}, "")
	emptyToken := toString(emptyLogin.Body["access_token"])
	emptyPreview := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/checkout/preview", map[string]any{
		"shipping_cents": 0,
		"discount_cents": 0,
	}, emptyToken)
	if emptyPreview.Status != http.StatusBadRequest {
		t.Fatalf("empty cart preview status = %d, want %d", emptyPreview.Status, http.StatusBadRequest)
	}
}

func TestOrderLifecycleAndTimeoutClose(t *testing.T) {
	srv := New("test-secret")
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "order-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "order-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])
	createProduct := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Order Product",
		"description":  "Used in order tests",
		"price_cents":  1200,
		"stock":        10,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	productID := toString(createProduct.Body["item"].(map[string]any)["id"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "order-buyer@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "order-buyer@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   2,
	}, buyerToken)
	createOrder := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders", map[string]any{}, buyerToken)
	if createOrder.Status != http.StatusCreated {
		t.Fatalf("create order status = %d, want %d", createOrder.Status, http.StatusCreated)
	}
	orderID := toString(createOrder.Body["order"].(map[string]any)["id"])

	invalidTransition := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/transitions", map[string]any{
		"to_status": "shipped",
	}, buyerToken)
	if invalidTransition.Status != http.StatusBadRequest {
		t.Fatalf("invalid transition status = %d, want %d", invalidTransition.Status, http.StatusBadRequest)
	}

	paid := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/transitions", map[string]any{
		"to_status": "paid",
	}, buyerToken)
	if paid.Status != http.StatusOK {
		t.Fatalf("paid transition status = %d, want %d", paid.Status, http.StatusOK)
	}
	shipped := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/transitions", map[string]any{
		"to_status": "shipped",
	}, buyerToken)
	if shipped.Status != http.StatusOK {
		t.Fatalf("shipped transition status = %d, want %d", shipped.Status, http.StatusOK)
	}
	done := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/transitions", map[string]any{
		"to_status": "done",
	}, buyerToken)
	if done.Status != http.StatusOK {
		t.Fatalf("done transition status = %d, want %d", done.Status, http.StatusOK)
	}

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   1,
	}, buyerToken)
	pendingOrder := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders", map[string]any{}, buyerToken)
	if pendingOrder.Status != http.StatusCreated {
		t.Fatalf("pending order status = %d, want %d", pendingOrder.Status, http.StatusCreated)
	}
	pendingOrderID := toString(pendingOrder.Body["order"].(map[string]any)["id"])

	closeExpired := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/orders/close-expired", map[string]any{
		"timeout_seconds": 0,
	}, adminToken)
	if closeExpired.Status != http.StatusOK {
		t.Fatalf("close expired status = %d, want %d", closeExpired.Status, http.StatusOK)
	}

	detail := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/orders/"+pendingOrderID, nil, buyerToken)
	if detail.Status != http.StatusOK {
		t.Fatalf("order detail status = %d, want %d", detail.Status, http.StatusOK)
	}
	detailOrder := detail.Body["order"].(map[string]any)
	if toString(detailOrder["status"]) != "canceled" {
		t.Fatalf("pending order status = %s, want canceled", toString(detailOrder["status"]))
	}
}

func TestPaymentCallbackSignatureAndIdempotency(t *testing.T) {
	callbackSecret := "mockpay-test-secret"
	srv := NewWithSecrets("test-secret", callbackSecret)
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "pay-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "pay-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])
	createProduct := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Pay Product",
		"description":  "Used in payment tests",
		"price_cents":  1888,
		"stock":        5,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	productID := toString(createProduct.Body["item"].(map[string]any)["id"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "pay-buyer@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "pay-buyer@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])
	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   1,
	}, buyerToken)
	orderResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders", map[string]any{}, buyerToken)
	orderID := toString(orderResp.Body["order"].(map[string]any)["id"])

	createPayment := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/create", map[string]any{
		"order_id": orderID,
		"provider": "mockpay",
	}, buyerToken)
	if createPayment.Status != http.StatusOK {
		t.Fatalf("create payment status = %d, want %d", createPayment.Status, http.StatusOK)
	}

	callbackPayload := map[string]any{
		"order_id":        orderID,
		"external_txn_id": "txn-123",
		"result":          "success",
	}
	rawBody, err := json.Marshal(callbackPayload)
	if err != nil {
		t.Fatalf("marshal callback payload: %v", err)
	}
	signature := signCallback(rawBody, callbackSecret)
	firstCallback := callRawJSONWithHeaders(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/callback/mockpay", rawBody, map[string]string{
		"X-Mockpay-Signature": signature,
		"Content-Type":        "application/json",
	})
	if firstCallback.Status != http.StatusOK {
		t.Fatalf("first callback status = %d, want %d", firstCallback.Status, http.StatusOK)
	}
	if firstCallback.Body["idempotent"] != false {
		t.Fatalf("first callback idempotent should be false")
	}

	secondCallback := callRawJSONWithHeaders(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/callback/mockpay", rawBody, map[string]string{
		"X-Mockpay-Signature": signature,
		"Content-Type":        "application/json",
	})
	if secondCallback.Status != http.StatusOK {
		t.Fatalf("second callback status = %d, want %d", secondCallback.Status, http.StatusOK)
	}
	if secondCallback.Body["idempotent"] != true {
		t.Fatalf("second callback idempotent should be true")
	}

	orderDetail := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/orders/"+orderID, nil, buyerToken)
	if orderDetail.Status != http.StatusOK {
		t.Fatalf("order detail status = %d, want %d", orderDetail.Status, http.StatusOK)
	}
	if toString(orderDetail.Body["order"].(map[string]any)["status"]) != "paid" {
		t.Fatalf("order status should be paid")
	}

	invalidSig := callRawJSONWithHeaders(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/callback/mockpay", rawBody, map[string]string{
		"X-Mockpay-Signature": "invalid",
		"Content-Type":        "application/json",
	})
	if invalidSig.Status != http.StatusUnauthorized {
		t.Fatalf("invalid signature status = %d, want %d", invalidSig.Status, http.StatusUnauthorized)
	}
}

func TestFulfillmentShipmentTrackingAndRefundFlow(t *testing.T) {
	callbackSecret := "fulfillment-test-secret"
	srv := NewWithSecrets("test-secret", callbackSecret)
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "fulfillment-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "fulfillment-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])

	createProduct := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Fulfillment Product",
		"description":  "Used in fulfillment tests",
		"price_cents":  2580,
		"stock":        5,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	productID := toString(createProduct.Body["item"].(map[string]any)["id"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "fulfillment-buyer@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "fulfillment-buyer@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   1,
	}, buyerToken)
	orderResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders", map[string]any{}, buyerToken)
	if orderResp.Status != http.StatusCreated {
		t.Fatalf("create order status = %d, want %d", orderResp.Status, http.StatusCreated)
	}
	orderID := toString(orderResp.Body["order"].(map[string]any)["id"])

	createPayment := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/create", map[string]any{
		"order_id": orderID,
		"provider": "mockpay",
	}, buyerToken)
	if createPayment.Status != http.StatusOK {
		t.Fatalf("create payment status = %d, want %d", createPayment.Status, http.StatusOK)
	}

	callbackPayload := map[string]any{
		"order_id":        orderID,
		"external_txn_id": "txn-fulfillment-1",
		"result":          "success",
	}
	rawBody, err := json.Marshal(callbackPayload)
	if err != nil {
		t.Fatalf("marshal callback payload: %v", err)
	}
	signature := signCallback(rawBody, callbackSecret)
	callbackResp := callRawJSONWithHeaders(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/callback/mockpay", rawBody, map[string]string{
		"X-Mockpay-Signature": signature,
		"Content-Type":        "application/json",
	})
	if callbackResp.Status != http.StatusOK {
		t.Fatalf("callback status = %d, want %d", callbackResp.Status, http.StatusOK)
	}

	shipResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/orders/"+orderID+"/ship", map[string]any{
		"tracking_no": "SF123456789CN",
		"carrier":     "SF",
	}, adminToken)
	if shipResp.Status != http.StatusOK {
		t.Fatalf("ship status = %d, want %d", shipResp.Status, http.StatusOK)
	}
	shipment := shipResp.Body["shipment"].(map[string]any)
	if toString(shipment["status"]) != "in_transit" {
		t.Fatalf("shipment status = %s, want in_transit", toString(shipment["status"]))
	}

	trackingResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/orders/"+orderID+"/tracking", nil, buyerToken)
	if trackingResp.Status != http.StatusOK {
		t.Fatalf("tracking status = %d, want %d", trackingResp.Status, http.StatusOK)
	}
	tracking := trackingResp.Body["shipment"].(map[string]any)
	if toString(tracking["tracking_no"]) != "SF123456789CN" {
		t.Fatalf("tracking_no = %s, want SF123456789CN", toString(tracking["tracking_no"]))
	}

	confirmResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/confirm-delivery", map[string]any{}, buyerToken)
	if confirmResp.Status != http.StatusOK {
		t.Fatalf("confirm delivery status = %d, want %d", confirmResp.Status, http.StatusOK)
	}
	if toString(confirmResp.Body["order"].(map[string]any)["status"]) != "done" {
		t.Fatalf("order status after confirm should be done")
	}

	refundReq := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/refunds", map[string]any{
		"amount_cents": 1000,
		"reason":       "buyer_request",
	}, buyerToken)
	if refundReq.Status != http.StatusOK {
		t.Fatalf("request refund status = %d, want %d", refundReq.Status, http.StatusOK)
	}
	refund := refundReq.Body["refund"].(map[string]any)
	if toString(refund["status"]) != "requested" {
		t.Fatalf("refund status = %s, want requested", toString(refund["status"]))
	}
	refundID := toString(refund["id"])

	refundGet := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/orders/"+orderID+"/refunds", nil, buyerToken)
	if refundGet.Status != http.StatusOK {
		t.Fatalf("get refund status = %d, want %d", refundGet.Status, http.StatusOK)
	}
	got := refundGet.Body["refund"].(map[string]any)
	if toString(got["id"]) != refundID {
		t.Fatalf("refund id = %s, want %s", toString(got["id"]), refundID)
	}
}

func TestAuditAndNotificationTracing(t *testing.T) {
	callbackSecret := "audit-test-secret"
	srv := NewWithSecrets("test-secret", callbackSecret)
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "audit-admin@example.com",
		"password": "admin-pass",
		"role":     "admin",
	}, "")
	adminLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "audit-admin@example.com",
		"password": "admin-pass",
	}, "")
	adminToken := toString(adminLogin.Body["access_token"])

	createProduct := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/products", map[string]any{
		"name":         "Audit Product",
		"description":  "Used in audit tests",
		"price_cents":  3200,
		"stock":        5,
		"category":     "demo",
		"shelf_status": "online",
	}, adminToken)
	productID := toString(createProduct.Body["item"].(map[string]any)["id"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":    "audit-buyer@example.com",
		"password": "buyer-pass",
		"role":     "buyer",
	}, "")
	buyerLogin := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "audit-buyer@example.com",
		"password": "buyer-pass",
	}, "")
	buyerToken := toString(buyerLogin.Body["access_token"])

	callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/cart/items", map[string]any{
		"product_id": productID,
		"quantity":   1,
	}, buyerToken)
	orderResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders", map[string]any{}, buyerToken)
	if orderResp.Status != http.StatusCreated {
		t.Fatalf("create order status = %d, want %d", orderResp.Status, http.StatusCreated)
	}
	orderID := toString(orderResp.Body["order"].(map[string]any)["id"])

	createPayment := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/create", map[string]any{
		"order_id": orderID,
		"provider": "mockpay",
	}, buyerToken)
	if createPayment.Status != http.StatusOK {
		t.Fatalf("create payment status = %d, want %d", createPayment.Status, http.StatusOK)
	}

	callbackPayload := map[string]any{
		"order_id":        orderID,
		"external_txn_id": "txn-audit-1",
		"result":          "success",
	}
	rawBody, err := json.Marshal(callbackPayload)
	if err != nil {
		t.Fatalf("marshal callback payload: %v", err)
	}
	signature := signCallback(rawBody, callbackSecret)
	callbackResp := callRawJSONWithHeaders(t, httpSrv.URL, http.MethodPost, "/api/v1/payments/callback/mockpay", rawBody, map[string]string{
		"X-Mockpay-Signature": signature,
		"Content-Type":        "application/json",
	})
	if callbackResp.Status != http.StatusOK {
		t.Fatalf("callback status = %d, want %d", callbackResp.Status, http.StatusOK)
	}

	shipResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/admin/orders/"+orderID+"/ship", map[string]any{
		"tracking_no": "YTO-AUDIT-001",
		"carrier":     "YTO",
	}, adminToken)
	if shipResp.Status != http.StatusOK {
		t.Fatalf("ship status = %d, want %d", shipResp.Status, http.StatusOK)
	}

	refundResp := callJSON(t, httpSrv.URL, http.MethodPost, "/api/v1/orders/"+orderID+"/refunds", map[string]any{
		"amount_cents": 2000,
		"reason":       "audit_case",
	}, buyerToken)
	if refundResp.Status != http.StatusOK {
		t.Fatalf("refund status = %d, want %d", refundResp.Status, http.StatusOK)
	}

	eventsResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/admin/notifications/events?order_id="+orderID, nil, adminToken)
	if eventsResp.Status != http.StatusOK {
		t.Fatalf("events status = %d, want %d", eventsResp.Status, http.StatusOK)
	}
	eventItems := eventsResp.Body["items"].([]any)
	eventSet := map[string]bool{}
	for _, raw := range eventItems {
		item := raw.(map[string]any)
		eventSet[toString(item["event_type"])] = true
	}
	if !eventSet["order.created"] || !eventSet["payment.created"] || !eventSet["payment.succeeded"] || !eventSet["shipment.created"] || !eventSet["refund.requested"] {
		t.Fatalf("event types missing, got %+v", eventSet)
	}

	auditResp := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/admin/audit/logs?order_id="+orderID, nil, adminToken)
	if auditResp.Status != http.StatusOK {
		t.Fatalf("audit status = %d, want %d", auditResp.Status, http.StatusOK)
	}
	auditItems := auditResp.Body["items"].([]any)
	actionSet := map[string]bool{}
	for _, raw := range auditItems {
		item := raw.(map[string]any)
		actionSet[toString(item["action"])] = true
	}
	if !actionSet["order.create"] || !actionSet["payment.create"] || !actionSet["payment.callback"] || !actionSet["shipment.create"] || !actionSet["refund.request"] {
		t.Fatalf("audit actions missing, got %+v", actionSet)
	}

	buyerAudit := callJSON(t, httpSrv.URL, http.MethodGet, "/api/v1/admin/audit/logs?order_id="+orderID, nil, buyerToken)
	if buyerAudit.Status != http.StatusForbidden {
		t.Fatalf("buyer audit status = %d, want %d", buyerAudit.Status, http.StatusForbidden)
	}
}

func callJSON(t *testing.T, baseURL, method, path string, payload map[string]any, bearerToken string) testResponse {
	t.Helper()
	var bodyBytes []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json marshal: %v", err)
		}
		bodyBytes = raw
	}

	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer response.Body.Close()

	result := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		result = map[string]any{}
	}
	return testResponse{
		Status: response.StatusCode,
		Body:   result,
	}
}

func callRawJSONWithHeaders(t *testing.T, baseURL, method, path string, rawBody []byte, headers map[string]string) testResponse {
	t.Helper()
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer response.Body.Close()

	result := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		result = map[string]any{}
	}
	return testResponse{
		Status: response.StatusCode,
		Body:   result,
	}
}

func toString(value any) string {
	text, _ := value.(string)
	return text
}

func toInt(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return 0
	}
}

func signCallback(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
