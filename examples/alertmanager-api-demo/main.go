package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19095", "loopback listen address")
	flag.Parse()
	log.Printf("MoniCheck Alertmanager API demo listening on http://%s", *listen)
	if err := http.ListenAndServe(*listen, demoHandler(os.Getenv("MONICHECK_DEMO_BASIC_AUTH_USERNAME"), os.Getenv("MONICHECK_DEMO_BASIC_AUTH_PASSWORD"))); err != nil {
		log.Fatal(err)
	}
}

func demoHandler(username, password string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/alerts", jsonResponse(`[{"labels":{"alertname":"CheckoutHighErrorRate","service":"checkout","severity":"warning"},"annotations":{"summary":"Checkout error rate is high"},"fingerprint":"demo-alert-1","status":{"state":"active"},"receivers":[{"name":"platform"}]}]`))
	mux.HandleFunc("/api/v2/status", jsonResponse(`{"cluster":{"status":"ready","peers":[]},"versionInfo":{"version":"0.28.1"},"config":{"original":"route:\n  receiver: platform\nreceivers:\n- name: platform\n  webhook_configs:\n  - url: https://example.invalid/notify\n"}}`))
	mux.HandleFunc("/api/v2/silences", jsonResponse(`[]`))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(username) != "" || password != "" {
			actualUsername, actualPassword, ok := r.BasicAuth()
			if !ok || actualUsername != username || actualPassword != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="MoniCheck Alertmanager demo"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func jsonResponse(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, body)
	}
}
