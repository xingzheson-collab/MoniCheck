package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultAddress = "127.0.0.1:19090"

func main() {
	address := flag.String("listen", defaultAddress, "loopback address for the Prometheus API demo")
	omitServiceLabel := flag.Bool("omit-service-label", false, "omit the explicit service label to exercise job-based service inference")
	flag.Parse()
	if err := validateAddress(*address); err != nil {
		log.Fatal(err)
	}
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { servePrometheusAPI(w, r, !*omitServiceLabel) })
	server := &http.Server{
		Addr: *address,
		Handler: basicAuthHandler(handler,
			os.Getenv("MONICHECK_DEMO_BASIC_AUTH_USERNAME"),
			os.Getenv("MONICHECK_DEMO_BASIC_AUTH_PASSWORD"),
		),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("MoniCheck Prometheus API demo listening on http://%s", *address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func basicAuthHandler(next http.Handler, username string, password string) http.Handler {
	username = strings.TrimSpace(username)
	if username == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestUsername, requestPassword, ok := r.BasicAuth()
		if !ok || requestUsername != username || requestPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="MoniCheck Prometheus demo"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateAddress(address string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("invalid --listen: must be host:port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("invalid --listen: demo must bind to a loopback address")
	}
	return nil
}

func prometheusAPI(w http.ResponseWriter, r *http.Request) {
	servePrometheusAPI(w, r, true)
}

func servePrometheusAPI(w http.ResponseWriter, r *http.Request, includeServiceLabel bool) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	targetLabels := `"instance":"api:8080","job":"checkout"`
	if includeServiceLabel {
		targetLabels += `,"service":"checkout"`
	}
	responses := map[string]string{
		"/api/v1/label/__name__/values": `{"status":"success","data":["up","http_requests_total"]}`,
		"/api/v1/metadata":              `{"status":"success","data":{"up":[{"type":"gauge","help":"Target health","unit":""}],"http_requests_total":[{"type":"counter","help":"Requests","unit":""}]}}`,
		"/api/v1/targets/metadata":      `{"status":"success","data":[]}`,
		"/api/v1/targets":               fmt.Sprintf(`{"status":"success","data":{"activeTargets":[{"discoveredLabels":{"__address__":"api:8080","job":"checkout"},"labels":{%s},"scrapePool":"checkout","scrapeUrl":"http://api:8080/metrics","globalUrl":"http://api:8080/metrics","lastError":"","lastScrape":%q,"lastScrapeDuration":0.02,"health":"up","scrapeInterval":"15s","scrapeTimeout":"10s"}],"droppedTargets":[]}}`, targetLabels, now),
		"/api/v1/rules":                 `{"status":"success","data":{"groups":[]}}`,
		"/api/v1/alerts":                `{"status":"success","data":{"alerts":[]}}`,
		"/api/v1/series":                `{"status":"success","data":[{"__name__":"up","job":"checkout","instance":"api:8080"},{"__name__":"http_requests_total","job":"checkout","instance":"api:8080"}]}`,
		"/api/v1/status/tsdb":           `{"status":"success","data":{"headStats":{"numSeries":24000,"chunkCount":48000,"minTime":1786100000000,"maxTime":1786107600000},"seriesCountByMetricName":[{"name":"http_requests_total","value":18000},{"name":"up","value":1}],"labelValueCountByLabelName":[],"memoryInBytesByLabelName":[],"seriesCountByLabelValuePair":[]}}`,
		"/api/v1/alertmanagers":         `{"status":"success","data":{"activeAlertmanagers":[],"droppedAlertmanagers":[]}}`,
		"/api/v1/status/runtimeinfo":    `{"status":"success","data":{"reloadConfigSuccess":true,"corruptionCount":0,"storageRetention":"15d"}}`,
		"/api/v1/status/flags":          `{"status":"success","data":{"web.enable-admin-api":"false","web.enable-lifecycle":"false","web.enable-remote-write-receiver":"false","web.enable-otlp-receiver":"false","storage.tsdb.retention.time":"15d"}}`,
	}
	body, found := responses[r.URL.Path]
	if !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, body)
}
