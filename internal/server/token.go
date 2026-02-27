package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type tokenPayload struct {
	Type string `json:"type"`
	Sub  string `json:"sub"`
	Role string `json:"role,omitempty"`
	JTI  string `json:"jti,omitempty"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

func issueAccessToken(userID, role, secret string, ttlSeconds int64) (string, error) {
	nowTs := time.Now().Unix()
	payload := tokenPayload{
		Type: "access",
		Sub:  userID,
		Role: role,
		Iat:  nowTs,
		Exp:  nowTs + ttlSeconds,
	}
	return signToken(payload, secret)
}

func issueRefreshToken(userID, secret string, ttlSeconds int64) (token, jti string, exp int64, err error) {
	nowTs := time.Now().Unix()
	jti = randomHex(12)
	exp = nowTs + ttlSeconds
	payload := tokenPayload{
		Type: "refresh",
		Sub:  userID,
		JTI:  jti,
		Iat:  nowTs,
		Exp:  exp,
	}
	token, err = signToken(payload, secret)
	return token, jti, exp, err
}

func parseToken(rawToken, secret, expectedType string) (tokenPayload, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return tokenPayload{}, fmt.Errorf("invalid token structure")
	}
	unsigned := parts[0] + "." + parts[1]
	expectedSig := signRaw(unsigned, secret)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return tokenPayload{}, fmt.Errorf("invalid token signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenPayload{}, fmt.Errorf("invalid token payload")
	}
	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return tokenPayload{}, fmt.Errorf("invalid token payload")
	}
	if payload.Exp <= time.Now().Unix() {
		return tokenPayload{}, fmt.Errorf("token expired")
	}
	if expectedType != "" && payload.Type != expectedType {
		return tokenPayload{}, fmt.Errorf("invalid token type")
	}
	return payload, nil
}

func signToken(payload tokenPayload, secret string) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	headerPart := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := headerPart + "." + payloadPart
	signature := signRaw(unsigned, secret)
	return unsigned + "." + signature, nil
}

func signRaw(unsigned, secret string) string {
	sum := hmac.New(sha256.New, []byte(secret))
	sum.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}

func parseBearerToken(header string) string {
	parts := strings.Split(strings.TrimSpace(header), " ")
	if len(parts) != 2 {
		return ""
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
