package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var allowedRoles = map[string]bool{
	"buyer": true,
	"admin": true,
	"ops":   true,
}

type Server struct {
	store          *memoryStore
	tokenSecret    string
	callbackSecret string
}

type authRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type authLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type cartSetRequest struct {
	ProductID string `json:"product_id"`
	Quantity  int    `json:"quantity"`
}

type cartUpdateRequest struct {
	Quantity int `json:"quantity"`
}

type checkoutPreviewRequest struct {
	ShippingCents int    `json:"shipping_cents"`
	DiscountCents int    `json:"discount_cents"`
	CouponCode    string `json:"coupon_code"`
}

type orderTransitionRequest struct {
	ToStatus string `json:"to_status"`
}

type closeExpiredOrdersRequest struct {
	TimeoutSeconds int64 `json:"timeout_seconds"`
}

type createPaymentRequest struct {
	OrderID  string `json:"order_id"`
	Provider string `json:"provider"`
}

type paymentCallbackRequest struct {
	OrderID       string `json:"order_id"`
	ExternalTxnID string `json:"external_txn_id"`
	Result        string `json:"result"`
}

type shipOrderRequest struct {
	TrackingNo string `json:"tracking_no"`
	Carrier    string `json:"carrier"`
}

type requestRefundBody struct {
	AmountCents int    `json:"amount_cents"`
	Reason      string `json:"reason"`
}

type createProductInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	PriceCents  int    `json:"price_cents"`
	Stock       int    `json:"stock"`
	ShelfStatus string `json:"shelf_status"`
}

type updateProductInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Category    *string `json:"category"`
	PriceCents  *int    `json:"price_cents"`
	Stock       *int    `json:"stock"`
	ShelfStatus *string `json:"shelf_status"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiErrorEnvelope struct {
	Error apiError `json:"error"`
}

func New(tokenSecret string) *Server {
	return NewWithSecrets(tokenSecret, tokenSecret)
}

func NewWithSecrets(tokenSecret, callbackSecret string) *Server {
	return &Server{
		store:          newMemoryStore(),
		tokenSecret:    tokenSecret,
		callbackSecret: callbackSecret,
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		s.writeCORS(writer)
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/healthz":
		s.writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/register":
		s.handleRegister(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/login":
		s.handleLogin(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/refresh":
		s.handleRefresh(writer, request)
		return
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/auth/me":
		s.handleAuthMe(writer, request)
		return
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/admin/ping":
		s.handleAdminPing(writer, request)
		return
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/cart":
		s.handleCartQuery(writer, request)
		return
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/cart/summary":
		s.handleCartQuery(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/cart/items":
		s.handleCartAdd(writer, request)
		return
	case request.Method == http.MethodPatch && strings.HasPrefix(request.URL.Path, "/api/v1/cart/items/"):
		s.handleCartUpdate(writer, request)
		return
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/cart/items/"):
		s.handleCartDelete(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/checkout/preview":
		s.handleCheckoutPreview(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/orders":
		s.handleCreateOrder(writer, request)
		return
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/orders":
		s.handleListOrders(writer, request)
		return
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/confirm-delivery") && strings.HasPrefix(request.URL.Path, "/api/v1/orders/"):
		s.handleConfirmDelivery(writer, request)
		return
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/tracking") && strings.HasPrefix(request.URL.Path, "/api/v1/orders/"):
		s.handleGetTracking(writer, request)
		return
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/refunds") && strings.HasPrefix(request.URL.Path, "/api/v1/orders/"):
		s.handleRequestRefund(writer, request)
		return
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/refunds") && strings.HasPrefix(request.URL.Path, "/api/v1/orders/"):
		s.handleGetRefund(writer, request)
		return
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/transitions") && strings.HasPrefix(request.URL.Path, "/api/v1/orders/"):
		s.handleTransitionOrder(writer, request)
		return
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/orders/"):
		s.handleGetOrder(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/admin/orders/close-expired":
		s.handleCloseExpiredOrders(writer, request)
		return
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/ship") && strings.HasPrefix(request.URL.Path, "/api/v1/admin/orders/"):
		s.handleShipOrder(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/payments/create":
		s.handleCreatePayment(writer, request)
		return
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/payments/order/"):
		s.handleGetPayment(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/payments/callback/mockpay":
		s.handleMockpayCallback(writer, request)
		return
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/products":
		s.handleListProducts(writer)
		return
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/products/"):
		s.handleGetProduct(writer, request)
		return
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/admin/products":
		s.handleAdminCreateProduct(writer, request)
		return
	case request.Method == http.MethodPatch && strings.HasPrefix(request.URL.Path, "/api/v1/admin/products/"):
		s.handleAdminUpdateProduct(writer, request)
		return
	default:
		s.writeError(writer, http.StatusNotFound, "NOT_FOUND", "Route not found")
		return
	}
}

func (s *Server) handleRegister(writer http.ResponseWriter, request *http.Request) {
	var body authRegisterRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	role := strings.TrimSpace(strings.ToLower(body.Role))
	if role == "" {
		role = "buyer"
	}
	if !allowedRoles[role] {
		s.writeError(writer, http.StatusBadRequest, "INVALID_ROLE", "role must be buyer, admin, or ops")
		return
	}
	created, err := s.store.createUser(body.Email, body.Password, role)
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			s.writeError(writer, http.StatusConflict, "EMAIL_EXISTS", err.Error())
			return
		}
		s.writeError(writer, http.StatusBadRequest, "REGISTER_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusCreated, map[string]any{"user": created})
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	var body authLoginRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	user, ok := s.store.authenticate(body.Email, body.Password)
	if !ok {
		s.writeError(writer, http.StatusUnauthorized, "LOGIN_FAILED", "Invalid email or password")
		return
	}
	access, err := issueAccessToken(user.ID, user.Role, s.tokenSecret, 900)
	if err != nil {
		s.writeError(writer, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to issue access token")
		return
	}
	refresh, jti, exp, err := issueRefreshToken(user.ID, s.tokenSecret, 604800)
	if err != nil {
		s.writeError(writer, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to issue refresh token")
		return
	}
	s.store.saveRefreshSession(jti, user.ID, exp)
	s.writeJSON(writer, http.StatusOK, map[string]any{
		"user":          user,
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (s *Server) handleRefresh(writer http.ResponseWriter, request *http.Request) {
	var body authRefreshRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	token := strings.TrimSpace(body.RefreshToken)
	if token == "" {
		s.writeError(writer, http.StatusBadRequest, "REFRESH_REQUIRED", "refresh_token is required")
		return
	}
	payload, err := parseToken(token, s.tokenSecret, "refresh")
	if err != nil {
		s.writeError(writer, http.StatusUnauthorized, "REFRESH_INVALID", "Refresh token is invalid or expired")
		return
	}
	if !s.store.isRefreshSessionActive(payload.JTI, payload.Sub, time.Now().Unix()) {
		s.writeError(writer, http.StatusUnauthorized, "REFRESH_REVOKED", "Refresh token is revoked or unknown")
		return
	}
	user, exists := s.store.getUserByID(payload.Sub)
	if !exists {
		s.writeError(writer, http.StatusUnauthorized, "REFRESH_INVALID", "User not found")
		return
	}
	s.store.revokeRefreshSession(payload.JTI)
	access, err := issueAccessToken(user.ID, user.Role, s.tokenSecret, 900)
	if err != nil {
		s.writeError(writer, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to issue access token")
		return
	}
	refresh, jti, exp, err := issueRefreshToken(user.ID, s.tokenSecret, 604800)
	if err != nil {
		s.writeError(writer, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to issue refresh token")
		return
	}
	s.store.saveRefreshSession(jti, user.ID, exp)
	s.writeJSON(writer, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (s *Server) handleAuthMe(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleAdminPing(writer http.ResponseWriter, request *http.Request) {
	_, status, ok := s.authUser(request, "admin")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "scope": "admin"})
}

func (s *Server) handleListProducts(writer http.ResponseWriter) {
	items := s.store.listProducts(false)
	s.writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCartQuery(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	cart := s.store.getCart(user.ID)
	s.writeJSON(writer, http.StatusOK, cart)
}

func (s *Server) handleCartAdd(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	var body cartSetRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	cart, err := s.store.setCartItem(user.ID, body.ProductID, body.Quantity)
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "CART_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, cart)
}

func (s *Server) handleCartUpdate(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	productID := strings.TrimPrefix(request.URL.Path, "/api/v1/cart/items/")
	if productID == "" || strings.Contains(productID, "/") {
		s.writeError(writer, http.StatusNotFound, "CART_ITEM_NOT_FOUND", "Cart item not found")
		return
	}
	var body cartUpdateRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	cart, err := s.store.setCartItem(user.ID, productID, body.Quantity)
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "CART_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, cart)
}

func (s *Server) handleCartDelete(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	productID := strings.TrimPrefix(request.URL.Path, "/api/v1/cart/items/")
	if productID == "" || strings.Contains(productID, "/") {
		s.writeError(writer, http.StatusNotFound, "CART_ITEM_NOT_FOUND", "Cart item not found")
		return
	}
	cart, exists := s.store.removeCartItem(user.ID, productID)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "CART_ITEM_NOT_FOUND", "Cart item not found")
		return
	}
	s.writeJSON(writer, http.StatusOK, cart)
}

func (s *Server) handleCheckoutPreview(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}

	var body checkoutPreviewRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	if body.ShippingCents < 0 || body.DiscountCents < 0 {
		s.writeError(writer, http.StatusBadRequest, "CHECKOUT_INVALID", "shipping_cents and discount_cents must be non-negative")
		return
	}

	cart := s.store.getCart(user.ID)
	if cart.Summary.TotalItems == 0 {
		s.writeError(writer, http.StatusBadRequest, "CHECKOUT_EMPTY", "Cart is empty")
		return
	}

	subtotal := cart.Summary.TotalAmountCents
	shipping := body.ShippingCents
	discount := body.DiscountCents
	maxDiscount := subtotal + shipping
	if discount > maxDiscount {
		discount = maxDiscount
	}
	total := subtotal + shipping - discount
	couponCode := strings.TrimSpace(body.CouponCode)

	s.writeJSON(writer, http.StatusOK, map[string]any{
		"pricing": map[string]any{
			"subtotal_cents": subtotal,
			"shipping_cents": shipping,
			"discount_cents": discount,
			"total_cents":    total,
			"currency":       "CNY",
		},
		"cart_summary": cart.Summary,
		"coupon_code":  couponCode,
		"trace_id":     checkoutTraceID(user.ID, cart.Items, shipping, discount, couponCode),
	})
}

func (s *Server) handleCreateOrder(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	order, err := s.store.createOrderFromCart(user.ID)
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "ORDER_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusCreated, map[string]any{"order": order})
}

func (s *Server) handleListOrders(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	items := s.store.listOrders(user.ID, user.Role)
	s.writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleGetOrder(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID := strings.TrimPrefix(request.URL.Path, "/api/v1/orders/")
	if orderID == "" || strings.Contains(orderID, "/") {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	order, exists, err := s.store.getOrder(user.ID, user.Role, orderID)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	if err != nil {
		s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"order": order})
}

func (s *Server) handleTransitionOrder(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	base := strings.TrimPrefix(request.URL.Path, "/api/v1/orders/")
	if !strings.HasSuffix(base, "/transitions") {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	orderID := strings.TrimSuffix(base, "/transitions")
	if orderID == "" || strings.Contains(orderID, "/") {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}

	var body orderTransitionRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	order, exists, err := s.store.transitionOrder(user.ID, user.Role, orderID, body.ToStatus)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	if err != nil {
		if err.Error() == "forbidden" {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusBadRequest, "ORDER_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"order": order})
}

func (s *Server) handleCloseExpiredOrders(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "admin")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	_ = user
	var body closeExpiredOrdersRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	closed := s.store.closeExpiredPendingOrders(body.TimeoutSeconds, time.Now().Unix())
	s.writeJSON(writer, http.StatusOK, map[string]any{
		"closed_count":     len(closed),
		"closed_order_ids": closed,
	})
}

func (s *Server) handleShipOrder(writer http.ResponseWriter, request *http.Request) {
	_, status, ok := s.authUser(request, "admin")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID, valid := extractOrderID(request.URL.Path, "/api/v1/admin/orders/", "/ship")
	if !valid {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	var body shipOrderRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	shipment, exists, err := s.store.shipOrder(orderID, body.TrackingNo, body.Carrier)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "SHIPMENT_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"shipment": shipment})
}

func (s *Server) handleGetTracking(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID, valid := extractOrderID(request.URL.Path, "/api/v1/orders/", "/tracking")
	if !valid {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	shipment, exists, err := s.store.getShipment(user.ID, user.Role, orderID)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "SHIPMENT_NOT_FOUND", "Shipment not found")
		return
	}
	if err != nil {
		s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"shipment": shipment})
}

func (s *Server) handleConfirmDelivery(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID, valid := extractOrderID(request.URL.Path, "/api/v1/orders/", "/confirm-delivery")
	if !valid {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	order, exists, err := s.store.confirmDelivery(user.ID, user.Role, orderID)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	if err != nil {
		if err.Error() == "forbidden" {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusBadRequest, "ORDER_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"order": order})
}

func (s *Server) handleRequestRefund(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID, valid := extractOrderID(request.URL.Path, "/api/v1/orders/", "/refunds")
	if !valid {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	var body requestRefundBody
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	refund, exists, err := s.store.requestRefund(user.ID, user.Role, orderID, body.AmountCents, body.Reason)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	if err != nil {
		if err.Error() == "forbidden" {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusBadRequest, "REFUND_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"refund": refund})
}

func (s *Server) handleGetRefund(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID, valid := extractOrderID(request.URL.Path, "/api/v1/orders/", "/refunds")
	if !valid {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	refund, exists, err := s.store.getRefund(user.ID, user.Role, orderID)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "REFUND_NOT_FOUND", "Refund not found")
		return
	}
	if err != nil {
		s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"refund": refund})
}

func (s *Server) handleCreatePayment(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	var body createPaymentRequest
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	payment, exists, err := s.store.createPayment(user.ID, user.Role, body.OrderID, body.Provider)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "ORDER_NOT_FOUND", "Order not found")
		return
	}
	if err != nil {
		if err.Error() == "forbidden" {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusBadRequest, "PAYMENT_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"payment": payment})
}

func (s *Server) handleGetPayment(writer http.ResponseWriter, request *http.Request) {
	user, status, ok := s.authUser(request, "")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	orderID := strings.TrimPrefix(request.URL.Path, "/api/v1/payments/order/")
	if orderID == "" || strings.Contains(orderID, "/") {
		s.writeError(writer, http.StatusNotFound, "PAYMENT_NOT_FOUND", "Payment not found")
		return
	}
	payment, exists, err := s.store.getPayment(user.ID, user.Role, orderID)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "PAYMENT_NOT_FOUND", "Payment not found")
		return
	}
	if err != nil {
		s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"payment": payment})
}

func (s *Server) handleMockpayCallback(writer http.ResponseWriter, request *http.Request) {
	rawBody, err := io.ReadAll(request.Body)
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid callback body")
		return
	}
	signature := strings.TrimSpace(request.Header.Get("X-Mockpay-Signature"))
	if !verifyCallbackSignature(rawBody, s.callbackSecret, signature) {
		s.writeError(writer, http.StatusUnauthorized, "CALLBACK_INVALID", "Invalid callback signature")
		return
	}
	var body paymentCallbackRequest
	if err := json.Unmarshal(rawBody, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid callback body")
		return
	}
	payment, exists, idempotent, err := s.store.processPaymentCallback("mockpay", body.OrderID, body.ExternalTxnID, body.Result)
	if !exists {
		s.writeError(writer, http.StatusNotFound, "PAYMENT_NOT_FOUND", "Payment not found")
		return
	}
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "CALLBACK_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{
		"payment":    payment,
		"idempotent": idempotent,
	})
}

func (s *Server) handleGetProduct(writer http.ResponseWriter, request *http.Request) {
	productID := strings.TrimPrefix(request.URL.Path, "/api/v1/products/")
	if productID == "" || strings.Contains(productID, "/") {
		s.writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "Product not found")
		return
	}
	item, exists := s.store.getProduct(productID)
	if !exists || item.ShelfStatus != "online" {
		s.writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "Product not found")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"item": item})
}

func (s *Server) handleAdminCreateProduct(writer http.ResponseWriter, request *http.Request) {
	_, status, ok := s.authUser(request, "admin")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	var body createProductInput
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	item, err := s.store.createProduct(body)
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID", err.Error())
		return
	}
	s.writeJSON(writer, http.StatusCreated, map[string]any{"item": item})
}

func (s *Server) handleAdminUpdateProduct(writer http.ResponseWriter, request *http.Request) {
	_, status, ok := s.authUser(request, "admin")
	if !ok {
		if status == http.StatusForbidden {
			s.writeError(writer, http.StatusForbidden, "AUTH_FORBIDDEN", "Insufficient role for this endpoint")
			return
		}
		s.writeError(writer, http.StatusUnauthorized, "AUTH_INVALID", "Access token is invalid or expired")
		return
	}
	productID := strings.TrimPrefix(request.URL.Path, "/api/v1/admin/products/")
	if productID == "" || strings.Contains(productID, "/") {
		s.writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "Product not found")
		return
	}

	var body updateProductInput
	if err := s.readJSON(request, &body); err != nil {
		s.writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", "Invalid JSON body")
		return
	}
	item, err, exists := s.store.updateProduct(productID, body)
	if err != nil {
		s.writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID", err.Error())
		return
	}
	if !exists {
		s.writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "Product not found")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{"item": item})
}

func (s *Server) authUser(request *http.Request, requiredRole string) (publicUser, int, bool) {
	token := parseBearerToken(request.Header.Get("Authorization"))
	if token == "" {
		return publicUser{}, http.StatusUnauthorized, false
	}
	payload, err := parseToken(token, s.tokenSecret, "access")
	if err != nil {
		return publicUser{}, http.StatusUnauthorized, false
	}
	user, exists := s.store.getUserByID(payload.Sub)
	if !exists {
		return publicUser{}, http.StatusUnauthorized, false
	}
	if requiredRole != "" && user.Role != requiredRole {
		return publicUser{}, http.StatusForbidden, false
	}
	return user, http.StatusOK, true
}

func (s *Server) readJSON(request *http.Request, output any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func (s *Server) writeJSON(writer http.ResponseWriter, status int, payload any) {
	body, _ := json.Marshal(payload)
	s.writeCORS(writer)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	writer.Write(body)
}

func (s *Server) writeCORS(writer http.ResponseWriter) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
}

func (s *Server) writeError(writer http.ResponseWriter, status int, code, message string) {
	s.writeJSON(writer, status, apiErrorEnvelope{Error: apiError{Code: code, Message: message}})
}

func extractOrderID(path, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	orderID := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if orderID == "" || strings.Contains(orderID, "/") {
		return "", false
	}
	return orderID, true
}

func checkoutTraceID(userID string, items []publicCartItem, shipping, discount int, couponCode string) string {
	builder := strings.Builder{}
	builder.WriteString(userID)
	builder.WriteString("|")
	for _, item := range items {
		builder.WriteString(item.ProductID)
		builder.WriteString(":")
		builder.WriteString(fmt.Sprintf("%d:%d", item.Quantity, item.PriceCents))
		builder.WriteString("|")
	}
	builder.WriteString(fmt.Sprintf("%d|%d|%s", shipping, discount, couponCode))
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])[:20]
}

func verifyCallbackSignature(payload []byte, secret, providedSignature string) bool {
	if providedSignature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(strings.ToLower(expected)), []byte(strings.ToLower(providedSignature)))
}
