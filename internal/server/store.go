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

type refreshSession struct {
	UserID    string
	ExpiresAt int64
	Revoked   bool
}

type memoryStore struct {
	mu sync.Mutex

	nextUserID    int
	nextProductID int

	usersByEmail map[string]user
	usersByID    map[string]user

	productsByID map[string]product
	refreshByJTI map[string]refreshSession
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		nextUserID:    1,
		nextProductID: 1,
		usersByEmail:  map[string]user{},
		usersByID:     map[string]user{},
		productsByID:  map[string]product{},
		refreshByJTI:  map[string]refreshSession{},
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
