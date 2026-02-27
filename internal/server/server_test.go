package server

import (
	"bytes"
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

func toString(value any) string {
	text, _ := value.(string)
	return text
}
