package core

import (
	"net/http"
	"time"
)

func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 1800 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func QwenHeaders(token string) http.Header {
	headers := http.Header{}
	headers.Set("Accept", "application/json, text/event-stream")
	headers.Set("Content-Type", "application/json")
	headers.Set("User-Agent", "Mozilla/5.0 qwen2api-go")
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	return headers
}
