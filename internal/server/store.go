package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type user struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    string
}

type publicUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

type product struct {
	ID          string
	Name        string
	Description string
	Category    string
	PriceCents  int
	Stock       int
	ShelfStatus string
	CreatedAt   string
	UpdatedAt   string
}

type publicProduct struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	PriceCents  int    `json:"price_cents"`
	Stock       int    `json:"stock"`
	ShelfStatus string `json:"shelf_status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type publicCartItem struct {
	ProductID      string `json:"product_id"`
	Name           string `json:"name"`
	PriceCents     int    `json:"price_cents"`
	Quantity       int    `json:"quantity"`
	LineTotalCents int    `json:"line_total_cents"`
	Stock          int    `json:"stock"`
}

type publicCartSummary struct {
	TotalItems       int `json:"total_items"`
	TotalQuantity    int `json:"total_quantity"`
	TotalAmountCents int `json:"total_amount_cents"`
}

type publicCartPayload struct {
	Items   []publicCartItem  `json:"items"`
	Summary publicCartSummary `json:"summary"`
}

type orderItem struct {
	ProductID      string
	Name           string
	PriceCents     int
	Quantity       int
	LineTotalCents int
}

type order struct {
	ID            string
	UserID        string
	Status        string
	TotalCents    int
	Items         []orderItem
	CreatedAt     string
	UpdatedAt     string
	CreatedAtUnix int64
}

type publicOrderItem struct {
	ProductID      string `json:"product_id"`
	Name           string `json:"name"`
	PriceCents     int    `json:"price_cents"`
	Quantity       int    `json:"quantity"`
	LineTotalCents int    `json:"line_total_cents"`
}

type publicOrder struct {
	ID         string            `json:"id"`
	UserID     string            `json:"user_id"`
	Status     string            `json:"status"`
	TotalCents int               `json:"total_cents"`
	Items      []publicOrderItem `json:"items"`
	CreatedAt  string            `json:"created_at"`
	UpdatedAt  string            `json:"updated_at"`
}

type refreshSession struct {
	UserID    string
	ExpiresAt int64
	Revoked   bool
}

type memoryStore struct {
	mu sync.Mutex

	nextUserID    int
	nextProductID int
	nextOrderID   int

	usersByEmail map[string]user
	usersByID    map[string]user

	productsByID   map[string]product
	refreshByJTI   map[string]refreshSession
	cartsByUser    map[string]map[string]int
	ordersByID     map[string]order
	orderIDsByUser map[string][]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		nextUserID:     1,
		nextProductID:  1,
		nextOrderID:    1,
		usersByEmail:   map[string]user{},
		usersByID:      map[string]user{},
		productsByID:   map[string]product{},
		refreshByJTI:   map[string]refreshSession{},
		cartsByUser:    map[string]map[string]int{},
		ordersByID:     map[string]order{},
		orderIDsByUser: map[string][]string{},
	}
}

func (s *memoryStore) createUser(email, password, role string) (publicUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	if cleanEmail == "" {
		return publicUser{}, fmt.Errorf("email is required")
	}
	if password == "" {
		return publicUser{}, fmt.Errorf("password is required")
	}
	if _, exists := s.usersByEmail[cleanEmail]; exists {
		return publicUser{}, fmt.Errorf("email already exists")
	}

	id := fmt.Sprintf("U%04d", s.nextUserID)
	s.nextUserID++
	item := user{
		ID:           id,
		Email:        cleanEmail,
		PasswordHash: makePasswordHash(password),
		Role:         role,
		CreatedAt:    nowISO(),
	}
	s.usersByEmail[cleanEmail] = item
	s.usersByID[id] = item
	return toPublicUser(item), nil
}

func (s *memoryStore) authenticate(email, password string) (publicUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	item, exists := s.usersByEmail[cleanEmail]
	if !exists {
		return publicUser{}, false
	}
	if !verifyPassword(password, item.PasswordHash) {
		return publicUser{}, false
	}
	return toPublicUser(item), true
}

func (s *memoryStore) getUserByID(userID string) (publicUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.usersByID[userID]
	if !exists {
		return publicUser{}, false
	}
	return toPublicUser(item), true
}

func (s *memoryStore) saveRefreshSession(jti, userID string, exp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshByJTI[jti] = refreshSession{
		UserID:    userID,
		ExpiresAt: exp,
		Revoked:   false,
	}
}

func (s *memoryStore) revokeRefreshSession(jti string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.refreshByJTI[jti]
	if !exists {
		return
	}
	session.Revoked = true
	s.refreshByJTI[jti] = session
}

func (s *memoryStore) isRefreshSessionActive(jti, userID string, nowTs int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.refreshByJTI[jti]
	if !exists {
		return false
	}
	if session.Revoked {
		return false
	}
	if session.UserID != userID {
		return false
	}
	return session.ExpiresAt > nowTs
}

func (s *memoryStore) createProduct(input createProductInput) (publicProduct, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := strings.TrimSpace(input.Name)
	if name == "" {
		return publicProduct{}, fmt.Errorf("product name is required")
	}
	if input.PriceCents < 0 || input.Stock < 0 {
		return publicProduct{}, fmt.Errorf("price_cents and stock must be non-negative")
	}
	status := normalizeShelfStatus(input.ShelfStatus)
	if status == "" {
		return publicProduct{}, fmt.Errorf("shelf_status must be online or offline")
	}
	category := strings.TrimSpace(input.Category)
	if category == "" {
		category = "general"
	}

	id := fmt.Sprintf("P%04d", s.nextProductID)
	s.nextProductID++
	now := nowISO()

	item := product{
		ID:          id,
		Name:        name,
		Description: input.Description,
		Category:    category,
		PriceCents:  input.PriceCents,
		Stock:       input.Stock,
		ShelfStatus: status,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.productsByID[id] = item
	return toPublicProduct(item), nil
}

func (s *memoryStore) updateProduct(productID string, input updateProductInput) (publicProduct, error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.productsByID[productID]
	if !exists {
		return publicProduct{}, nil, false
	}

	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if name == "" {
			return publicProduct{}, fmt.Errorf("product name is required"), true
		}
		item.Name = name
	}
	if input.Description != nil {
		item.Description = *input.Description
	}
	if input.Category != nil {
		category := strings.TrimSpace(*input.Category)
		if category == "" {
			category = "general"
		}
		item.Category = category
	}
	if input.PriceCents != nil {
		if *input.PriceCents < 0 {
			return publicProduct{}, fmt.Errorf("price_cents must be non-negative"), true
		}
		item.PriceCents = *input.PriceCents
	}
	if input.Stock != nil {
		if *input.Stock < 0 {
			return publicProduct{}, fmt.Errorf("stock must be non-negative"), true
		}
		item.Stock = *input.Stock
	}
	if input.ShelfStatus != nil {
		status := normalizeShelfStatus(*input.ShelfStatus)
		if status == "" {
			return publicProduct{}, fmt.Errorf("shelf_status must be online or offline"), true
		}
		item.ShelfStatus = status
	}
	item.UpdatedAt = nowISO()
	s.productsByID[productID] = item
	return toPublicProduct(item), nil, true
}

func (s *memoryStore) listProducts(includeOffline bool) []publicProduct {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]publicProduct, 0, len(s.productsByID))
	for _, item := range s.productsByID {
		if !includeOffline && item.ShelfStatus != "online" {
			continue
		}
		result = append(result, toPublicProduct(item))
	}
	sortPublicProducts(result)
	return result
}

func (s *memoryStore) getProduct(productID string) (publicProduct, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.productsByID[productID]
	if !exists {
		return publicProduct{}, false
	}
	return toPublicProduct(item), true
}

func (s *memoryStore) setCartItem(userID, productID string, quantity int) (publicCartPayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(productID) == "" {
		return publicCartPayload{}, fmt.Errorf("product_id is required")
	}
	if quantity <= 0 {
		return publicCartPayload{}, fmt.Errorf("quantity must be greater than zero")
	}

	item, exists := s.productsByID[productID]
	if !exists || item.ShelfStatus != "online" {
		return publicCartPayload{}, fmt.Errorf("product is not available")
	}
	if quantity > item.Stock {
		return publicCartPayload{}, fmt.Errorf("quantity exceeds stock")
	}

	cart, ok := s.cartsByUser[userID]
	if !ok {
		cart = map[string]int{}
		s.cartsByUser[userID] = cart
	}
	cart[productID] = quantity
	return s.getCartLocked(userID), nil
}

func (s *memoryStore) removeCartItem(userID, productID string) (publicCartPayload, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cart, ok := s.cartsByUser[userID]
	if !ok {
		return s.getCartLocked(userID), false
	}
	_, exists := cart[productID]
	if !exists {
		return s.getCartLocked(userID), false
	}
	delete(cart, productID)
	if len(cart) == 0 {
		delete(s.cartsByUser, userID)
	}
	return s.getCartLocked(userID), true
}

func (s *memoryStore) getCart(userID string) publicCartPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getCartLocked(userID)
}

func (s *memoryStore) getCartLocked(userID string) publicCartPayload {
	cart, ok := s.cartsByUser[userID]
	if !ok {
		return publicCartPayload{
			Items: []publicCartItem{},
			Summary: publicCartSummary{
				TotalItems:       0,
				TotalQuantity:    0,
				TotalAmountCents: 0,
			},
		}
	}

	items := make([]publicCartItem, 0, len(cart))
	totalQuantity := 0
	totalAmount := 0

	for productID, quantity := range cart {
		item, exists := s.productsByID[productID]
		if !exists || item.ShelfStatus != "online" || quantity <= 0 {
			continue
		}
		if quantity > item.Stock {
			quantity = item.Stock
			cart[productID] = quantity
		}
		lineTotal := item.PriceCents * quantity
		items = append(items, publicCartItem{
			ProductID:      item.ID,
			Name:           item.Name,
			PriceCents:     item.PriceCents,
			Quantity:       quantity,
			LineTotalCents: lineTotal,
			Stock:          item.Stock,
		})
		totalQuantity += quantity
		totalAmount += lineTotal
	}

	sortCartItems(items)
	return publicCartPayload{
		Items: items,
		Summary: publicCartSummary{
			TotalItems:       len(items),
			TotalQuantity:    totalQuantity,
			TotalAmountCents: totalAmount,
		},
	}
}

func (s *memoryStore) createOrderFromCart(userID string) (publicOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cart := s.getCartLocked(userID)
	if cart.Summary.TotalItems == 0 {
		return publicOrder{}, fmt.Errorf("cart is empty")
	}

	orderItems := make([]orderItem, 0, len(cart.Items))
	for _, item := range cart.Items {
		orderItems = append(orderItems, orderItem{
			ProductID:      item.ProductID,
			Name:           item.Name,
			PriceCents:     item.PriceCents,
			Quantity:       item.Quantity,
			LineTotalCents: item.LineTotalCents,
		})
	}

	id := fmt.Sprintf("O%04d", s.nextOrderID)
	s.nextOrderID++
	now := nowISO()
	entity := order{
		ID:            id,
		UserID:        userID,
		Status:        "pending_payment",
		TotalCents:    cart.Summary.TotalAmountCents,
		Items:         orderItems,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedAtUnix: time.Now().Unix(),
	}
	s.ordersByID[id] = entity
	s.orderIDsByUser[userID] = append(s.orderIDsByUser[userID], id)
	delete(s.cartsByUser, userID)
	return toPublicOrder(entity), nil
}

func (s *memoryStore) listOrders(actorUserID, actorRole string) []publicOrder {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := []publicOrder{}
	if actorRole == "admin" {
		for _, item := range s.ordersByID {
			result = append(result, toPublicOrder(item))
		}
		sortPublicOrders(result)
		return result
	}

	for _, id := range s.orderIDsByUser[actorUserID] {
		item, exists := s.ordersByID[id]
		if !exists {
			continue
		}
		result = append(result, toPublicOrder(item))
	}
	sortPublicOrders(result)
	return result
}

func (s *memoryStore) getOrder(actorUserID, actorRole, orderID string) (publicOrder, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.ordersByID[orderID]
	if !exists {
		return publicOrder{}, false, nil
	}
	if actorRole != "admin" && item.UserID != actorUserID {
		return publicOrder{}, true, fmt.Errorf("forbidden")
	}
	return toPublicOrder(item), true, nil
}

func (s *memoryStore) transitionOrder(actorUserID, actorRole, orderID, toStatus string) (publicOrder, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.ordersByID[orderID]
	if !exists {
		return publicOrder{}, false, nil
	}
	if actorRole != "admin" && item.UserID != actorUserID {
		return publicOrder{}, true, fmt.Errorf("forbidden")
	}
	next := strings.TrimSpace(strings.ToLower(toStatus))
	if next == "" {
		return publicOrder{}, true, fmt.Errorf("to_status is required")
	}
	if !isValidOrderTransition(item.Status, next) {
		return publicOrder{}, true, fmt.Errorf("invalid state transition")
	}
	item.Status = next
	item.UpdatedAt = nowISO()
	s.ordersByID[orderID] = item
	return toPublicOrder(item), true, nil
}

func (s *memoryStore) closeExpiredPendingOrders(timeoutSeconds, nowTs int64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if timeoutSeconds < 0 {
		timeoutSeconds = 0
	}

	closed := []string{}
	for id, item := range s.ordersByID {
		if item.Status != "pending_payment" {
			continue
		}
		if nowTs-item.CreatedAtUnix < timeoutSeconds {
			continue
		}
		item.Status = "canceled"
		item.UpdatedAt = nowISO()
		s.ordersByID[id] = item
		closed = append(closed, id)
	}
	sortStrings(closed)
	return closed
}

func toPublicUser(item user) publicUser {
	return publicUser{
		ID:        item.ID,
		Email:     item.Email,
		Role:      item.Role,
		CreatedAt: item.CreatedAt,
	}
}

func toPublicProduct(item product) publicProduct {
	return publicProduct{
		ID:          item.ID,
		Name:        item.Name,
		Description: item.Description,
		Category:    item.Category,
		PriceCents:  item.PriceCents,
		Stock:       item.Stock,
		ShelfStatus: item.ShelfStatus,
		CreatedAt:   item.CreatedAt,
		UpdatedAt:   item.UpdatedAt,
	}
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func makePasswordHash(password string) string {
	salt := randomHex(12)
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return salt + "$" + hex.EncodeToString(sum[:])
}

func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 2 {
		return false
	}
	salt := parts[0]
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:]) == parts[1]
}

func randomHex(size int) string {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	if err != nil {
		return "fallbacksalt"
	}
	return hex.EncodeToString(buf)
}

func normalizeShelfStatus(raw string) string {
	status := strings.TrimSpace(strings.ToLower(raw))
	if status == "" {
		status = "online"
	}
	if status != "online" && status != "offline" {
		return ""
	}
	return status
}

func sortPublicProducts(items []publicProduct) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].ID < items[i].ID {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func sortCartItems(items []publicCartItem) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].ProductID < items[i].ProductID {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func toPublicOrder(item order) publicOrder {
	publicItems := make([]publicOrderItem, 0, len(item.Items))
	for _, line := range item.Items {
		publicItems = append(publicItems, publicOrderItem{
			ProductID:      line.ProductID,
			Name:           line.Name,
			PriceCents:     line.PriceCents,
			Quantity:       line.Quantity,
			LineTotalCents: line.LineTotalCents,
		})
	}
	return publicOrder{
		ID:         item.ID,
		UserID:     item.UserID,
		Status:     item.Status,
		TotalCents: item.TotalCents,
		Items:      publicItems,
		CreatedAt:  item.CreatedAt,
		UpdatedAt:  item.UpdatedAt,
	}
}

func isValidOrderTransition(currentStatus, nextStatus string) bool {
	if currentStatus == "pending_payment" {
		return nextStatus == "paid" || nextStatus == "canceled"
	}
	if currentStatus == "paid" {
		return nextStatus == "shipped"
	}
	if currentStatus == "shipped" {
		return nextStatus == "done"
	}
	return false
}

func sortPublicOrders(items []publicOrder) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].ID < items[i].ID {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func sortStrings(items []string) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j] < items[i] {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}
