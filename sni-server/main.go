package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	port   int
	secret string
)

func main() {
	flag.IntVar(&port, "port", 443, "Listen port")
	flag.StringVar(&secret, "secret", "CHANGE_ME_IN_PRODUCTION", "Auth secret (x-novaproxy-auth)")
	flag.Parse()

	// Prefer reading Secret from environment variable
	if envSecret := os.Getenv("AUTH_SECRET"); envSecret != "" {
		secret = envSecret
	}

	proxy := NewProxy(secret)

	serverAddr := fmt.Sprintf(":%d", port)
	log.Printf("NovaProxy Server (sni-server) starting on %s", serverAddr)
	log.Printf("Auth Secret: %s", secret)

	err := http.ListenAndServe(serverAddr, proxy)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
