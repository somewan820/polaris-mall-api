package main

import (
	"log"
	"net/http"
	"os"

	"polaris-mall-api/internal/server"
)

func main() {
	host := getenv("POLARIS_API_HOST", "127.0.0.1")
	port := getenv("POLARIS_API_PORT", "9000")
	secret := getenv("POLARIS_API_TOKEN_SECRET", "dev-token-secret")

	addr := host + ":" + port
	handler := server.New(secret)

	log.Printf("Polaris API listening on http://%s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
