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
	listen := flag.String("listen", "127.0.0.1:19094", "loopback listen address")
	flag.Parse()
	handler := basicAuthHandler(http.HandlerFunc(grafanaAPI), os.Getenv("MONICHECK_DEMO_BASIC_AUTH_USERNAME"), os.Getenv("MONICHECK_DEMO_BASIC_AUTH_PASSWORD"))
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5e9}
	log.Printf("MoniCheck Grafana API demo listening on http://%s", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func basicAuthHandler(next http.Handler, username, password string) http.Handler {
	username = strings.TrimSpace(username)
	if username == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestUsername, requestPassword, ok := r.BasicAuth()
		if !ok || requestUsername != username || requestPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="MoniCheck Grafana demo"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func grafanaAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/datasources":
		fmt.Fprint(w, `[{"id":1,"uid":"prom","name":"Prometheus","type":"prometheus","url":"http://prometheus.internal:9090","access":"proxy","isDefault":true,"readOnly":true}]`)
	case "/api/search":
		fmt.Fprint(w, `[{"uid":"checkout","title":"Checkout Overview","folderUid":"services","folderTitle":"Services"}]`)
	case "/api/dashboards/uid/checkout":
		fmt.Fprint(w, `{"meta":{"folderUid":"services","folderTitle":"Services"},"dashboard":{"title":"Checkout Overview","version":1,"schemaVersion":39,"tags":["checkout"],"panels":[{"id":1,"title":"Request rate","type":"timeseries","datasource":"prom","targets":[{"expr":"sum(rate(http_requests_total[5m]))"}]}]}}`)
	case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
		fmt.Fprint(w, `[]`)
	case "/api/v1/provisioning/policies":
		fmt.Fprint(w, `{}`)
	case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
		fmt.Fprint(w, `{"items":[]}`)
	case "/api/health":
		fmt.Fprint(w, `{"database":"ok","version":"12.1.0"}`)
	case "/api/datasources/uid/prom/health":
		fmt.Fprint(w, `{"status":"OK"}`)
	default:
		http.NotFound(w, r)
	}
}
