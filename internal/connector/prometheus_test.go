package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestPrometheusConnectorRetriesTransientAPIResponse(t *testing.T) {
	var metricNameAttempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/label/__name__/values":
			if metricNameAttempts.Add(1) < 3 {
				http.Error(w, `{"status":"error"}`, http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":["up"]}`))
		case "/api/v1/metadata":
			_, _ = w.Write([]byte(`{"status":"success","data":{}}`))
		case "/api/v1/targets/metadata", "/api/v1/status/tsdb":
			http.NotFound(w, r)
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeTargets":[]}}`))
		case "/api/v1/rules":
			_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
		case "/api/v1/alerts":
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[]}}`))
		case "/api/v1/series":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	prometheus, err := NewPrometheusConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: 2, RetryBackoff: time.Millisecond})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := prometheus.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync after transient responses: %v", err)
	}
	if metricNameAttempts.Load() != 3 {
		t.Fatalf("expected three metric-name attempts, got %d", metricNameAttempts.Load())
	}
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
}

func TestPrometheusReceiverFlagsSupportLegacyFeatureNames(t *testing.T) {
	legacy := map[string]string{
		"enable-feature": "remote-write-receiver,otlp-write-receiver,unselected-feature",
	}
	if value := parsePrometheusReceiverFlag(legacy, "web.enable-remote-write-receiver", "remote-write-receiver"); value == nil || !*value {
		t.Fatalf("expected legacy remote-write receiver feature to be enabled, got %#v", value)
	}
	if value := parsePrometheusReceiverFlag(legacy, "web.enable-otlp-receiver", "otlp-write-receiver"); value == nil || !*value {
		t.Fatalf("expected legacy OTLP receiver feature to be enabled, got %#v", value)
	}

	dedicated := map[string]string{
		"web.enable-remote-write-receiver": "false",
		"web.enable-otlp-receiver":         "false",
		"enable-feature":                   "remote-write-receiver,otlp-write-receiver",
	}
	if value := parsePrometheusReceiverFlag(dedicated, "web.enable-remote-write-receiver", "remote-write-receiver"); value == nil || *value {
		t.Fatalf("expected dedicated remote-write flag to override legacy feature, got %#v", value)
	}
	if value := parsePrometheusReceiverFlag(dedicated, "web.enable-otlp-receiver", "otlp-write-receiver"); value == nil || *value {
		t.Fatalf("expected dedicated OTLP flag to override legacy feature, got %#v", value)
	}

	if value := parsePrometheusReceiverFlag(map[string]string{}, "web.enable-otlp-receiver", "otlp-write-receiver"); value != nil {
		t.Fatalf("expected missing receiver evidence to remain unevaluable, got %#v", value)
	}
}

func TestPrometheusQueryFlagParsingRejectsMissingAndInvalidValues(t *testing.T) {
	if value := parsePrometheusPositiveInt("40"); value == nil || *value != 40 {
		t.Fatalf("expected positive integer flag, got %#v", value)
	}
	for _, raw := range []string{"", "0", "-1", "forty", "1.5"} {
		if value := parsePrometheusPositiveInt(raw); value != nil {
			t.Fatalf("expected integer flag %q to remain unevaluable, got %#v", raw, value)
		}
	}
	if value := parsePrometheusPositiveDuration("5m"); value == nil || *value != 300 {
		t.Fatalf("expected positive duration flag, got %#v", value)
	}
	for _, raw := range []string{"", "0s", "500ms", "-1m", "forever"} {
		if value := parsePrometheusPositiveDuration(raw); value != nil {
			t.Fatalf("expected duration flag %q to remain unevaluable, got %#v", raw, value)
		}
	}
}

func TestPrometheusPositiveFloatParsingRejectsMissingAndInvalidValues(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want float64
		ok   bool
	}{
		{raw: "0.9", want: 0.9, ok: true},
		{raw: " 1 ", want: 1, ok: true},
		{raw: "1e-1", want: 0.1, ok: true},
		{raw: "", ok: false},
		{raw: "0", ok: false},
		{raw: "-0.1", ok: false},
		{raw: "default", ok: false},
	} {
		t.Run(test.raw, func(t *testing.T) {
			value := parsePrometheusPositiveFloat(test.raw)
			if !test.ok {
				if value != nil {
					t.Fatalf("expected %q to remain unevaluable, got %v", test.raw, *value)
				}
				return
			}
			if value == nil || *value != test.want {
				t.Fatalf("parse %q: got %#v, want %v", test.raw, value, test.want)
			}
		})
	}
}

func TestPrometheusLogLevelParsingUsesExactKnownValues(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
	}{
		{raw: "debug", want: "debug"},
		{raw: " INFO ", want: "info"},
		{raw: "Warn", want: "warn"},
		{raw: "error", want: "error"},
		{raw: "", want: ""},
		{raw: "verbose", want: ""},
		{raw: "debug,info", want: ""},
	} {
		t.Run(test.raw, func(t *testing.T) {
			if got := parsePrometheusLogLevel(test.raw); got != test.want {
				t.Fatalf("parse log level %q: got %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestPrometheusRuleConcurrencyFlagsUseExactFeatureAndVersionAliases(t *testing.T) {
	flags := map[string]string{
		"enable-feature":                  "concurrent-rule-eval-extra,concurrent-rule-eval",
		"rules.max-concurrent-rule-evals": "8",
	}
	if value := parsePrometheusFeatureFlag(flags, "concurrent-rule-eval"); value == nil || !*value {
		t.Fatalf("expected exact concurrent-rule-eval feature, got %#v", value)
	}
	if value := parsePrometheusPositiveIntFlag(flags, "rules.max-concurrent-evals", "rules.max-concurrent-rule-evals"); value == nil || *value != 8 {
		t.Fatalf("expected legacy rule concurrency alias, got %#v", value)
	}
	if value := parsePrometheusFeatureFlag(map[string]string{"enable-feature": "concurrent-rule-eval-extra"}, "concurrent-rule-eval"); value == nil || *value {
		t.Fatalf("expected similarly named feature to remain disabled, got %#v", value)
	}
	if value := parsePrometheusFeatureFlag(map[string]string{}, "concurrent-rule-eval"); value != nil {
		t.Fatalf("expected missing feature list to remain unevaluable, got %#v", value)
	}
	dedicatedInvalid := map[string]string{
		"rules.max-concurrent-evals":      "invalid",
		"rules.max-concurrent-rule-evals": "8",
	}
	if value := parsePrometheusPositiveIntFlag(dedicatedInvalid, "rules.max-concurrent-evals", "rules.max-concurrent-rule-evals"); value != nil {
		t.Fatalf("expected present current flag to take precedence without alias fallback, got %#v", value)
	}
}

func TestPrometheusStorageFeatureFlagsUseExactTokens(t *testing.T) {
	flags := map[string]string{
		"enable-feature": "exemplar-storage-extra,exemplar-storage,extra-scrape-metrics,created-timestamp-zero-ingestion,otlp-deltatocumulative,xor2-encoding,st-storage,st-synthesis,otlp-native-delta-ingestion,metadata-wal-records,type-and-unit-labels,use-uncached-io",
	}
	if value := parsePrometheusFeatureFlag(flags, "exemplar-storage"); value == nil || !*value {
		t.Fatalf("expected exact exemplar-storage feature, got %#v", value)
	}
	if value := parsePrometheusFeatureFlag(flags, "extra-scrape-metrics"); value == nil || !*value {
		t.Fatalf("expected exact extra-scrape-metrics feature, got %#v", value)
	}
	if value := parsePrometheusFeatureFlag(map[string]string{"enable-feature": "exemplar-storage-extra"}, "exemplar-storage"); value == nil || *value {
		t.Fatalf("expected similarly named exemplar feature to remain disabled, got %#v", value)
	}
	if value := parsePrometheusFeatureFlag(map[string]string{}, "extra-scrape-metrics"); value != nil {
		t.Fatalf("expected missing feature list to remain unevaluable, got %#v", value)
	}
	for _, feature := range []string{"created-timestamp-zero-ingestion", "otlp-deltatocumulative", "xor2-encoding"} {
		if value := parsePrometheusFeatureFlag(flags, feature); value == nil || !*value {
			t.Fatalf("expected exact %s feature, got %#v", feature, value)
		}
		if value := parsePrometheusFeatureFlag(map[string]string{"enable-feature": feature + "-extra"}, feature); value == nil || *value {
			t.Fatalf("expected similarly named %s token to remain disabled, got %#v", feature, value)
		}
	}
	for _, feature := range []string{"st-storage", "st-synthesis", "otlp-native-delta-ingestion"} {
		if value := parsePrometheusFeatureFlag(flags, feature); value == nil || !*value {
			t.Fatalf("expected exact %s feature, got %#v", feature, value)
		}
		if value := parsePrometheusFeatureFlag(map[string]string{"enable-feature": feature + "-extra"}, feature); value == nil || *value {
			t.Fatalf("expected similarly named %s token to remain disabled, got %#v", feature, value)
		}
	}
	for _, feature := range []string{"metadata-wal-records", "type-and-unit-labels", "use-uncached-io"} {
		if value := parsePrometheusFeatureFlag(flags, feature); value == nil || !*value {
			t.Fatalf("expected exact %s feature, got %#v", feature, value)
		}
		if value := parsePrometheusFeatureFlag(map[string]string{"enable-feature": feature + "-extra"}, feature); value == nil || *value {
			t.Fatalf("expected similarly named %s token to remain disabled, got %#v", feature, value)
		}
	}
}

func TestPrometheusNonNegativeFlagParsingSupportsScientificNotation(t *testing.T) {
	tests := []struct {
		raw  string
		want int64
		ok   bool
	}{
		{raw: "0", want: 0, ok: true},
		{raw: "10", want: 10, ok: true},
		{raw: "5e7", want: 50_000_000, ok: true},
		{raw: "1.0e3", want: 1_000, ok: true},
		{raw: "", ok: false},
		{raw: "-1", ok: false},
		{raw: "1.5", ok: false},
		{raw: "1e-1", ok: false},
		{raw: "unlimited", ok: false},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			value := parsePrometheusNonNegativeInt(test.raw)
			if !test.ok {
				if value != nil {
					t.Fatalf("expected %q to remain unevaluable, got %d", test.raw, *value)
				}
				return
			}
			if value == nil || *value != test.want {
				t.Fatalf("parse %q: got %#v, want %d", test.raw, value, test.want)
			}
		})
	}
}

func TestPrometheusAlertForBelowGraceCountUsesOnlyPositiveShortAlertDurations(t *testing.T) {
	rules := prometheusRules{Groups: []prometheusRuleGroup{{Rules: []prometheusRule{
		{Type: "alerting", Duration: 0},
		{Type: "alerting", Duration: 300},
		{Type: "alerting", Duration: 600},
		{Type: "alerting", Duration: 900},
		{Type: "recording", Duration: 300},
	}}}}
	if got := prometheusAlertForBelowGraceCount(rules, 600); got != 1 {
		t.Fatalf("expected one positive alert for duration below grace, got %d", got)
	}
}

func TestPrometheusConnectorContinuesWhenOptionalEndpointsAreUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/label/__name__/values":
			_, _ = w.Write([]byte(`{"status":"success","data":["up"]}`))
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeTargets":[]}}`))
		case "/api/v1/rules":
			_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	prometheus, err := NewPrometheusConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := prometheus.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync with unavailable optional endpoints: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected unavailable optional endpoints to mark snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	if len(snapshot.Diagnostics) != 10 {
		t.Fatalf("expected ten endpoint diagnostics, got %#v", snapshot.Diagnostics)
	}
	rulesDiagnostic, found := prometheusDiagnostic(snapshot.Diagnostics, "prometheus_rules")
	if !found || rulesDiagnostic.Status != model.ExecutionStatusSucceeded {
		t.Fatalf("expected empty successful rules response to remain successful, got %#v", rulesDiagnostic)
	}
	metadataDiagnostic, found := prometheusDiagnostic(snapshot.Diagnostics, "prometheus_metadata")
	if !found || metadataDiagnostic.Status != model.ExecutionStatusWarning {
		t.Fatalf("expected unavailable metadata warning, got %#v", metadataDiagnostic)
	}
}

func TestPrometheusConnectorBoundsConcurrentOptionalDiscoveryAndPreservesDiagnosticOrder(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/label/__name__/values" {
			_, _ = w.Write([]byte(`{"status":"success","data":["up"]}`))
			return
		}

		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		defer active.Add(-1)
		time.Sleep(25 * time.Millisecond)

		switch r.URL.Path {
		case "/api/v1/metadata":
			_, _ = w.Write([]byte(`{"status":"success","data":{}}`))
		case "/api/v1/targets/metadata":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeTargets":[],"droppedTargets":[]}}`))
		case "/api/v1/rules":
			_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
		case "/api/v1/alerts":
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[]}}`))
		case "/api/v1/series":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		case "/api/v1/status/tsdb":
			_, _ = w.Write([]byte(`{"status":"success","data":{"headStats":{}}}`))
		case "/api/v1/alertmanagers":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeAlertmanagers":[],"droppedAlertmanagers":[]}}`))
		case "/api/v1/status/runtimeinfo":
			_, _ = w.Write([]byte(`{"status":"success","data":{"reloadConfigSuccess":true,"corruptionCount":0}}`))
		case "/api/v1/status/flags":
			_, _ = w.Write([]byte(`{"status":"success","data":{"web.enable-admin-api":"false","web.enable-lifecycle":"false","web.enable-remote-write-receiver":"false","web.enable-otlp-receiver":"false"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	prometheus, err := NewPrometheusConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	prometheus.discoveryWorkers = 2
	snapshot, err := prometheus.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync with concurrent optional discovery: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("expected complete snapshot, got diagnostics %#v", snapshot.Diagnostics)
	}
	if maximum.Load() < 2 || maximum.Load() > 2 {
		t.Fatalf("expected exactly two concurrent optional requests, got %d", maximum.Load())
	}

	expectedIDs := []string{
		"prometheus_metadata",
		"prometheus_target_metadata",
		"prometheus_targets",
		"prometheus_rules",
		"prometheus_alerts",
		"prometheus_recent_series",
		"prometheus_tsdb_stats",
		"prometheus_alertmanagers",
		"prometheus_runtime_info",
		"prometheus_flags",
	}
	if len(snapshot.Diagnostics) != len(expectedIDs) {
		t.Fatalf("expected %d diagnostics, got %#v", len(expectedIDs), snapshot.Diagnostics)
	}
	for index, expectedID := range expectedIDs {
		diagnostic := snapshot.Diagnostics[index]
		if diagnostic.ID != expectedID {
			t.Fatalf("diagnostic order changed at %d: expected %s, got %s", index, expectedID, diagnostic.ID)
		}
		if diagnostic.Metadata["discovery_mode"] != "bounded_concurrent" || diagnostic.Metadata["worker_count"] != "2" {
			t.Fatalf("expected concurrent discovery metadata, got %#v", diagnostic.Metadata)
		}
	}
}

func TestPrometheusCompatibleConnectorsSkipPrometheusServerOnlyEndpoints(t *testing.T) {
	constructors := []struct {
		system string
		new    func(string, HTTPOptions) (*PrometheusConnector, error)
	}{
		{system: "thanos", new: NewThanosConnectorWithOptions},
		{system: "victoriametrics", new: NewVictoriaMetricsConnectorWithOptions},
		{system: "mimir", new: NewMimirConnectorWithOptions},
		{system: "cortex", new: NewCortexConnectorWithOptions},
	}
	for _, test := range constructors {
		t.Run(test.system, func(t *testing.T) {
			var serverOnlyRequests atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v1/label/__name__/values":
					_, _ = w.Write([]byte(`{"status":"success","data":["up"]}`))
				case "/api/v1/metadata":
					_, _ = w.Write([]byte(`{"status":"success","data":{}}`))
				case "/api/v1/targets/metadata":
					_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
				case "/api/v1/targets":
					_, _ = w.Write([]byte(`{"status":"success","data":{"activeTargets":[],"droppedTargets":[]}}`))
				case "/api/v1/rules":
					_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
				case "/api/v1/alerts":
					_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[]}}`))
				case "/api/v1/series":
					_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
				case "/api/v1/status/tsdb":
					_, _ = w.Write([]byte(`{"status":"success","data":{"headStats":{}}}`))
				case "/api/v1/alertmanagers", "/api/v1/status/runtimeinfo", "/api/v1/status/flags":
					serverOnlyRequests.Add(1)
					http.Error(w, "Prometheus-only endpoint must not be called", http.StatusInternalServerError)
				default:
					http.NotFound(w, r)
				}
			})

			connector, err := test.new("http://"+test.system+".test", HTTPOptions{})
			if err != nil {
				t.Fatalf("new %s connector: %v", test.system, err)
			}
			connector.client = testHTTPClient(handler)
			snapshot, err := connector.Sync(context.Background())
			if err != nil {
				t.Fatalf("sync %s: %v", test.system, err)
			}
			if snapshot.Partial {
				t.Fatalf("expected supported capability profile to produce a complete snapshot: %#v", snapshot.Diagnostics)
			}
			if serverOnlyRequests.Load() != 0 {
				t.Fatalf("expected no Prometheus-server-only requests, got %d", serverOnlyRequests.Load())
			}
			for _, id := range []string{"prometheus_alertmanagers", "prometheus_runtime_info", "prometheus_flags"} {
				diagnostic, found := prometheusDiagnostic(snapshot.Diagnostics, id)
				if !found ||
					diagnostic.Status != model.ExecutionStatusSucceeded ||
					diagnostic.Metadata["supported"] != "false" ||
					diagnostic.Metadata["skipped"] != "true" {
					t.Fatalf("unexpected skipped diagnostic %q: %#v", id, diagnostic)
				}
			}
			for _, resource := range snapshot.Resources {
				if resource.Type == model.ResourceTypeTSDB &&
					(resource.Metadata[model.MetadataPrometheusAMDiscoveryAvailable] != "false" ||
						resource.Metadata[model.MetadataPrometheusRuntimeAvailable] != "false" ||
						resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "false") {
					t.Fatalf("skipped endpoints must remain unavailable on TSDB metadata: %#v", resource.Metadata)
				}
			}
		})
	}
}

func TestPrometheusConnectorRequiresMetricNameDiscovery(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	prometheus, err := NewPrometheusConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := prometheus.Sync(context.Background()); err == nil {
		t.Fatal("expected metric name discovery failure to fail sync")
	}
}

func prometheusDiagnostic(diagnostics []model.Diagnostic, id string) (model.Diagnostic, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.ID == id {
			return diagnostic, true
		}
	}
	return model.Diagnostic{}, false
}

func TestPrometheusConnectorSync(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/label/__name__/values":
			_, _ = w.Write([]byte(`{"status":"success","data":["http_requests_total","node_cpu_seconds_total"]}`))
		case "/api/v1/metadata":
			_, _ = w.Write([]byte(`{"status":"success","data":{"http_requests_total":[{"type":"counter","help":"Total HTTP requests","unit":""},{"type":"counter","help":"HTTP request count","unit":""}],"node_cpu_seconds_total":[{"type":"counter","help":"CPU seconds","unit":"seconds"}]}}`))
		case "/api/v1/targets/metadata":
			_, _ = w.Write([]byte(`{"status":"success","data":[{"target":{"job":"api","instance":"10.0.0.1:9100"},"metric":"http_requests_total","type":"counter","help":"Total HTTP requests","unit":""},{"target":{"job":"api","instance":"10.0.0.3:9100","service":"checkout"},"metric":"request_queue_depth","type":"gauge","help":"Queued requests","unit":"requests"}]}`))
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeTargets":[{"labels":{"job":"api","instance":"10.0.0.1:9100"},"discoveredLabels":{"__meta_kubernetes_namespace":"payments","__meta_kubernetes_service_name":"checkout","__meta_kubernetes_service_label_app":"checkout-api","__meta_kubernetes_service_label_team":"platform","__meta_kubernetes_service_label_owner":"payments-oncall"},"scrapePool":"serviceMonitor/payments/checkout-monitor/0","scrapeUrl":"http://10.0.0.1:9100/metrics","health":"up","lastError":"","lastScrape":"2026-07-13T00:03:00Z","lastScrapeDuration":1.25,"scrapeInterval":"15s","scrapeTimeout":"10s"},{"labels":{"job":"api","instance":"10.0.0.3:9100"},"discoveredLabels":{"__meta_kubernetes_namespace":"payments","__meta_kubernetes_service_name":"checkout","__meta_kubernetes_pod_name":"checkout-2","__meta_kubernetes_service_label_app":"checkout-api","__meta_kubernetes_service_label_team":"platform","__meta_kubernetes_service_label_owner":"payments-oncall"},"scrapePool":"serviceMonitor/payments/checkout-monitor/0","scrapeUrl":"http://10.0.0.3:9100/metrics","health":"up","lastError":"","lastScrape":"2026-07-13T00:03:00Z","lastScrapeDuration":0.75,"scrapeInterval":"15s","scrapeTimeout":"10s"}],"droppedTargets":[{"discoveredLabels":{"__address__":"10.0.0.9:9100","__meta_kubernetes_namespace":"payments","__meta_kubernetes_service_name":"checkout"},"scrapePool":"serviceMonitor/payments/checkout-monitor/0"}]}}`))
		case "/api/v1/rules":
			_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[{"name":"api","file":"/etc/prometheus/rules/api.yaml","interval":30,"evaluationTime":0.25,"lastEvaluation":"2026-07-13T00:01:00Z","rules":[{"type":"alerting","name":"HighRequestRate","query":"sum(rate(http_requests_total[5m])) > 100","labels":{"severity":"warning"},"health":"ok","duration":300,"evaluationTime":0.5,"lastEvaluation":"2026-07-13T00:02:00Z"},{"type":"recording","name":"job:http_requests:rate5m","query":"sum(rate(http_requests_total[5m])) by (job)","health":"ok"}]}]}}`))
		case "/api/v1/alerts":
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[{"labels":{"alertname":"HighRequestRate","service":"api","severity":"warning","slo":"api-availability","objective":"99.9"},"annotations":{"summary":"Request rate is high"},"state":"firing","activeAt":"2026-07-13T00:00:00Z","value":"123"}]}}`))
		case "/api/v1/series":
			_, _ = w.Write([]byte(`{"status":"success","data":[{"__name__":"http_requests_total","job":"api","instance":"10.0.0.1:9100","namespace":"payments","team":"platform"},{"__name__":"node_cpu_seconds_total","job":"node","instance":"10.0.0.2:9100"}]}`))
		case "/api/v1/status/tsdb":
			if r.URL.Query().Get("limit") != "10000" {
				t.Errorf("expected TSDB stats limit 10000, got %q", r.URL.Query().Get("limit"))
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"headStats":{"numSeries":3000,"chunkCount":4500,"minTime":1784332800000,"maxTime":1784340000000},"seriesCountByMetricName":[{"name":"http_requests_total","value":2500},{"name":"request_queue_depth","value":500}],"labelValueCountByLabelName":[{"name":"__name__","value":4},{"name":"user_id","value":5000},{"name":"job","value":2}],"memoryInBytesByLabelName":[{"name":"user_id","value":2000000},{"name":"job","value":100}],"seriesCountByLabelValuePair":[{"name":"user_id=customer-1","value":1200}]}}`))
		case "/api/v1/alertmanagers":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeAlertmanagers":[{"url":"https://secret-alertmanager.example/api/v2/alerts"}],"droppedAlertmanagers":[{"url":"http://old-secret-alertmanager.example/api/v2/alerts"}]}}`))
		case "/api/v1/status/runtimeinfo":
			_, _ = w.Write([]byte(`{"status":"success","data":{"startTime":"2026-07-13T08:00:00+08:00","CWD":"/secret-runtime-cwd","hostname":"secret-runtime-host","reloadConfigSuccess":false,"lastConfigTime":"2026-07-13T09:00:00+08:00","corruptionCount":2,"storageRetention":"30d","GODEBUG":"secret-runtime-debug"}}`))
		case "/api/v1/status/flags":
			_, _ = w.Write([]byte(`{"status":"success","data":{"web.enable-admin-api":"true","web.enable-lifecycle":"true","web.enable-remote-write-receiver":"true","web.enable-otlp-receiver":"true","agent":"false","storage.agent.wal-compression":"false","storage.agent.retention.max-time":"8h","storage.agent.no-lockfile":"true","storage.tsdb.wal-compression":"false","storage.tsdb.no-lockfile":"true","enable-feature":"concurrent-rule-eval,search-api,exemplar-storage,extra-scrape-metrics,created-timestamp-zero-ingestion,otlp-deltatocumulative,xor2-encoding,st-storage,st-synthesis,otlp-native-delta-ingestion,metadata-wal-records,type-and-unit-labels,use-uncached-io,secret-feature","rules.max-concurrent-evals":"40","rules.alert.for-outage-tolerance":"30m","rules.alert.for-grace-period":"10m","rules.alert.resend-delay":"15s","query.max-concurrency":"40","query.max-samples":"100000000","query.timeout":"5m","query.lookback-delta":"10m","storage.remote.read-concurrent-limit":"0","storage.remote.read-sample-limit":"0e0","storage.remote.read-max-bytes-in-frame":"2097152","web.search.max-limit":"0","web.max-connections":"1024","web.read-timeout":"10m","alertmanager.notification-queue-capacity":"0e0","alertmanager.notification-batch-size":"1024","alertmanager.drain-notification-queue-on-shutdown":"false","web.config.file":"/secret-flags/prometheus.yml","storage.tsdb.path":"/secret-flags/data"}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewPrometheusConnector("http://prometheus.test")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 4)
	assertResourceCount(t, snapshot, model.ResourceTypeMetricLabel, 6)
	assertResourceCount(t, snapshot, model.ResourceTypeTSDB, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeJob, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeExporter, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeAlert, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeRecordingRule, 1)

	if len(snapshot.Relationships) != 22 {
		t.Fatalf("expected 22 relationships, got %d", len(snapshot.Relationships))
	}
	assertRelationship(t, snapshot, model.RelationshipProduces, model.ResourceTypeTarget, model.ResourceTypeMetric)
	assertRelationshipByName(t, snapshot, model.RelationshipProduces, model.ResourceTypeTarget, "http://10.0.0.3:9100/metrics", model.ResourceTypeMetric, "request_queue_depth")
	assertRelationship(t, snapshot, model.RelationshipProduces, model.ResourceTypeRecordingRule, model.ResourceTypeMetric)
	assertRelationshipByName(t, snapshot, model.RelationshipProduces, model.ResourceTypeRecordingRule, "job:http_requests:rate5m", model.ResourceTypeMetric, "job:http_requests:rate5m")
	assertDerivedMetricRelationship(t, snapshot, "http_requests_total", "job:http_requests:rate5m", "job:http_requests:rate5m")
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeMetric)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeRecordingRule, model.ResourceTypeMetric)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeMetric, "http_requests_total", model.ResourceTypeMetricLabel, "namespace")
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeAlert, model.ResourceTypeAlertRule)

	var foundMetadata bool
	var foundMetricLabels bool
	var foundSeriesCount bool
	var foundAlert bool
	var foundAlertRuleDuration bool
	var foundRuleMetadata bool
	var foundAlertRuleRuntimeLabel bool
	var foundRecordingRuleOutput bool
	var foundTargetMetadata bool
	var foundTargetDiscoveredLabels bool
	var foundRecordingMetric bool
	var foundRuleQueryLength bool
	var foundJobContext bool
	var foundInstanceContext bool
	var foundTargetMetadataMetric bool
	var foundRecentSeriesFallback bool
	var foundMetricLabelCost bool
	var foundTSDBCost bool
	var foundDroppedTarget bool
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeMetric && resource.Name == "http_requests_total" {
			foundMetadata = resource.Metadata[model.MetadataMetricType] == "counter" &&
				resource.Metadata[model.MetadataMetricHelp] == "Total HTTP requests" &&
				resource.Metadata[model.MetadataMetricHelpVariants] == `["Total HTTP requests","HTTP request count"]`
			foundMetricLabels = resource.Labels["namespace"] == "payments" &&
				resource.Labels["team"] == "platform" &&
				resource.Metadata[model.MetadataMetricLabelKeys] == "instance,job,namespace,team" &&
				resource.Metadata["metric_label_values.namespace"] == "payments"
			foundSeriesCount = resource.Metadata[model.MetadataSeriesCount] == "2500" &&
				resource.Metadata[model.MetadataSeriesCountSource] == "tsdb_head" &&
				resource.Metadata[model.MetadataTSDBHeadSeriesCount] == "2500" &&
				resource.Metadata[model.MetadataRecentSeriesCount] == "1"
		}
		if resource.Type == model.ResourceTypeAlertRule && resource.Name == "HighRequestRate" {
			foundAlertRuleDuration = resource.Metadata[model.MetadataAlertFor] == "5m0s"
			foundAlertRuleRuntimeLabel = resource.Labels["severity"] == "warning" && resource.Labels["service"] == "api" &&
				resource.Metadata[model.MetadataSLORule] == "true" && resource.Metadata[model.MetadataSLOName] == "api-availability" && resource.Metadata[model.MetadataSLOObjective] == "99.9"
			foundRuleQueryLength = resource.Metadata[model.MetadataQueryLength] != ""
			foundRuleMetadata = resource.Metadata[model.MetadataRuleGroup] == "api" &&
				resource.Metadata[model.MetadataRuleFile] == "/etc/prometheus/rules/api.yaml" &&
				resource.Metadata[model.MetadataEvaluationInterval] == "30s" &&
				resource.Metadata[model.MetadataEvaluationTime] == "500ms" &&
				resource.Metadata[model.MetadataLastEvaluation] == "2026-07-13T00:02:00Z"
		}
		if resource.Type == model.ResourceTypeRecordingRule && resource.Name == "job:http_requests:rate5m" {
			foundRecordingRuleOutput = resource.Metadata[model.MetadataRecordingRuleOutput] == "job:http_requests:rate5m"
		}
		if resource.Type == model.ResourceTypeAlert && resource.Name == "HighRequestRate" {
			foundAlert = resource.Metadata[model.MetadataAlertState] == "firing" &&
				resource.Metadata[model.MetadataFingerprint] != "" &&
				resource.Metadata[model.MetadataStartsAt] == "2026-07-13T00:00:00Z" &&
				resource.Metadata[model.MetadataAlertValue] == "123" &&
				resource.Metadata["annotation.summary"] == "Request rate is high"
		}
		if resource.Type == model.ResourceTypeTarget && resource.Name == "http://10.0.0.1:9100/metrics" {
			foundTargetMetadata = resource.Metadata[model.MetadataScrapePool] == "serviceMonitor/payments/checkout-monitor/0" &&
				resource.Metadata[model.MetadataOperatorMonitorKind] == "ServiceMonitor" &&
				resource.Metadata[model.MetadataOperatorMonitorNamespace] == "payments" &&
				resource.Metadata[model.MetadataOperatorMonitorName] == "checkout-monitor" &&
				resource.Metadata[model.MetadataOperatorMonitorEndpoint] == "0" &&
				resource.Metadata[model.MetadataLastScrape] == "2026-07-13T00:03:00Z" &&
				resource.Metadata[model.MetadataScrapeDuration] == "1.25s" &&
				resource.Metadata[model.MetadataScrapeInterval] == "15s" &&
				resource.Metadata[model.MetadataScrapeTimeout] == "10s"
			foundTargetDiscoveredLabels = resource.Labels[model.MetadataService] == "checkout" &&
				resource.Labels["app"] == "checkout-api" &&
				resource.Labels["namespace"] == "payments" &&
				resource.Labels["team"] == "platform" &&
				resource.Labels[model.MetadataOwner] == "payments-oncall" &&
				resource.Metadata["target_discovered_label_keys"] != "" &&
				resource.Metadata["target_discovered_label.service"] == "checkout"
		}
		if resource.Type == model.ResourceTypeMetric && resource.Name == "job:http_requests:rate5m" {
			foundRecordingMetric = true
		}
		if resource.Type == model.ResourceTypeJob && resource.Name == "api" {
			foundJobContext = resource.Labels[model.MetadataService] == "checkout" &&
				resource.Labels["namespace"] == "payments" &&
				resource.Labels["team"] == "platform" &&
				resource.Labels[model.MetadataOwner] == "payments-oncall" &&
				resource.Labels["instance"] == "" &&
				resource.Labels["pod"] == "" &&
				resource.Metadata["target_count"] == "2"
		}
		if resource.Type == model.ResourceTypeInstance && resource.Name == "10.0.0.3:9100" {
			foundInstanceContext = resource.Labels[model.MetadataService] == "checkout" &&
				resource.Labels["pod"] == "checkout-2" &&
				resource.Metadata["target_count"] == "1"
		}
		if resource.Type == model.ResourceTypeMetric && resource.Name == "request_queue_depth" {
			foundTargetMetadataMetric = resource.Metadata[model.MetadataMetricType] == "gauge" &&
				resource.Metadata[model.MetadataMetricHelp] == "Queued requests" &&
				resource.Metadata[model.MetadataMetricUnit] == "requests" &&
				resource.Labels["job"] == "api" &&
				resource.Labels["instance"] == "10.0.0.3:9100" &&
				resource.Labels[model.MetadataService] == "checkout" &&
				resource.Metadata[model.MetadataSeriesCount] == "500" &&
				resource.Metadata[model.MetadataSeriesCountSource] == "tsdb_head"
		}
		if resource.Type == model.ResourceTypeMetric && resource.Name == "node_cpu_seconds_total" {
			foundRecentSeriesFallback = resource.Metadata[model.MetadataSeriesCount] == "1" &&
				resource.Metadata[model.MetadataSeriesCountSource] == "recent_1h" &&
				resource.Metadata[model.MetadataRecentSeriesCount] == "1" &&
				resource.Metadata[model.MetadataTSDBHeadSeriesCount] == ""
		}
		if resource.Type == model.ResourceTypeMetricLabel && resource.Name == "user_id" {
			foundMetricLabelCost = resource.Metadata[model.MetadataMetricLabel] == "user_id" &&
				resource.Metadata[model.MetadataMetricLabelValueCount] == "5000" &&
				resource.Metadata[model.MetadataMetricLabelMemoryBytes] == "2000000" &&
				resource.Metadata[model.MetadataMetricLabelTopValue] == "customer-1" &&
				resource.Metadata[model.MetadataMetricLabelTopSeries] == "1200"
		}
		if resource.Type == model.ResourceTypeTSDB {
			foundTSDBCost = resource.Source.System == "prometheus" &&
				resource.Metadata[model.MetadataTargetsDiscoveryAvailable] == "true" &&
				resource.Metadata[model.MetadataActiveTargetCount] == "2" &&
				resource.Metadata[model.MetadataRulesDiscoveryAvailable] == "true" &&
				resource.Metadata[model.MetadataAlertingRuleCount] == "1" &&
				resource.Metadata[model.MetadataPrometheusAMDiscoveryAvailable] == "true" &&
				resource.Metadata[model.MetadataPrometheusActiveAMCount] == "1" &&
				resource.Metadata[model.MetadataPrometheusDroppedAMCount] == "1" &&
				resource.Metadata[model.MetadataPrometheusRuntimeAvailable] == "true" &&
				resource.Metadata[model.MetadataPrometheusReloadSuccess] == "false" &&
				resource.Metadata[model.MetadataPrometheusCorruptionCount] == "2" &&
				resource.Metadata[model.MetadataPrometheusStartedAt] == "2026-07-13T00:00:00Z" &&
				resource.Metadata[model.MetadataPrometheusLastConfigAt] == "2026-07-13T01:00:00Z" &&
				resource.Metadata[model.MetadataPrometheusStorageRetention] == "30d" &&
				resource.Metadata[model.MetadataPrometheusRetentionSeconds] == "2592000" &&
				resource.Metadata[model.MetadataPrometheusFlagsAvailable] == "true" &&
				resource.Metadata[model.MetadataPrometheusAdminAPIEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusLifecycleAPIEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusRemoteWriteReceiver] == "true" &&
				resource.Metadata[model.MetadataPrometheusOTLPReceiver] == "true" &&
				resource.Metadata[model.MetadataPrometheusAgentMode] == "false" &&
				resource.Metadata[model.MetadataPrometheusAgentWALCompression] == "false" &&
				resource.Metadata[model.MetadataPrometheusAgentRetentionMaxSeconds] == "28800" &&
				resource.Metadata[model.MetadataPrometheusAgentNoLockfile] == "true" &&
				resource.Metadata[model.MetadataPrometheusTSDBWALCompression] == "false" &&
				resource.Metadata[model.MetadataPrometheusTSDBNoLockfile] == "true" &&
				resource.Metadata[model.MetadataPrometheusConcurrentRuleEval] == "true" &&
				resource.Metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] == "40" &&
				resource.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom] == "0" &&
				resource.Metadata[model.MetadataPrometheusAlertForOutageTolerance] == "1800" &&
				resource.Metadata[model.MetadataPrometheusAlertForGracePeriod] == "600" &&
				resource.Metadata[model.MetadataPrometheusAlertForBelowGraceCount] == "1" &&
				resource.Metadata[model.MetadataPrometheusQueryMaxConcurrency] == "40" &&
				resource.Metadata[model.MetadataPrometheusQueryMaxSamples] == "100000000" &&
				resource.Metadata[model.MetadataPrometheusQueryTimeoutSeconds] == "300" &&
				resource.Metadata[model.MetadataPrometheusQueryLookbackSeconds] == "600" &&
				resource.Metadata[model.MetadataPrometheusRemoteReadConcurrentLimit] == "0" &&
				resource.Metadata[model.MetadataPrometheusRemoteReadSampleLimit] == "0" &&
				resource.Metadata[model.MetadataPrometheusRemoteReadFrameBytes] == "2097152" &&
				resource.Metadata[model.MetadataPrometheusSearchAPIEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusSearchMaxLimit] == "0" &&
				resource.Metadata[model.MetadataPrometheusWebMaxConnections] == "1024" &&
				resource.Metadata[model.MetadataPrometheusWebReadTimeoutSeconds] == "600" &&
				resource.Metadata[model.MetadataPrometheusNotificationQueueCapacity] == "0" &&
				resource.Metadata[model.MetadataPrometheusDrainNotificationQueue] == "false" &&
				resource.Metadata[model.MetadataPrometheusAlertResendDelay] == "15" &&
				resource.Metadata[model.MetadataPrometheusNotificationBatchSize] == "1024" &&
				resource.Metadata[model.MetadataPrometheusExemplarStorageEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusExtraScrapeMetricsEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusCreatedTimestampZero] == "true" &&
				resource.Metadata[model.MetadataPrometheusOTLPDeltaToCumulative] == "true" &&
				resource.Metadata[model.MetadataPrometheusXOR2EncodingEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusSTStorageEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusSTSynthesisEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusOTLPNativeDeltaEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusMetadataWALRecordsEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] == "true" &&
				resource.Metadata[model.MetadataPrometheusUncachedIOEnabled] == "true" &&
				resource.Metadata[model.MetadataOperatorTargetCount] == "2" &&
				resource.Metadata[model.MetadataDroppedTargetCount] == "1" &&
				resource.Metadata[model.MetadataOperatorDroppedTargetCount] == "1" &&
				resource.Metadata[model.MetadataTSDBHeadSeries] == "3000" &&
				resource.Metadata[model.MetadataTSDBHeadChunks] == "4500" &&
				resource.Metadata[model.MetadataTSDBHeadRangeSeconds] == "7200" &&
				resource.Metadata[model.MetadataTSDBLabelValueCount] == "5002" &&
				resource.Metadata[model.MetadataTSDBLabelMemoryBytes] == "2000100"
		}
		if resource.Type == model.ResourceTypeTarget && resource.Metadata[model.MetadataTargetState] == "dropped" {
			foundDroppedTarget = resource.Status == model.ResourceStatusDeprecated &&
				resource.Metadata[model.MetadataScrapePool] == "serviceMonitor/payments/checkout-monitor/0" &&
				resource.Metadata[model.MetadataOperatorMonitorName] == "checkout-monitor" &&
				resource.Metadata[model.MetadataScrapeURL] == "" &&
				resource.Labels["namespace"] == "payments" &&
				resource.Labels[model.MetadataService] == "checkout" &&
				!strings.Contains(resource.Source.ExternalID, "10.0.0.9") &&
				!strings.Contains(resource.Name, "10.0.0.9")
		}
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(encodedSnapshot), "secret-alertmanager") ||
		strings.Contains(string(encodedSnapshot), "secret-runtime") ||
		strings.Contains(string(encodedSnapshot), "secret-flags") ||
		strings.Contains(string(encodedSnapshot), "web.config.file") ||
		strings.Contains(string(encodedSnapshot), "query.timeout") ||
		strings.Contains(string(encodedSnapshot), "query.lookback-delta") ||
		strings.Contains(string(encodedSnapshot), "rules.alert.") ||
		strings.Contains(string(encodedSnapshot), "concurrent-rule-eval") ||
		strings.Contains(string(encodedSnapshot), "search-api") ||
		strings.Contains(string(encodedSnapshot), "exemplar-storage") ||
		strings.Contains(string(encodedSnapshot), "extra-scrape-metrics") ||
		strings.Contains(string(encodedSnapshot), "created-timestamp-zero-ingestion") ||
		strings.Contains(string(encodedSnapshot), "otlp-deltatocumulative") ||
		strings.Contains(string(encodedSnapshot), "xor2-encoding") ||
		strings.Contains(string(encodedSnapshot), "st-storage") ||
		strings.Contains(string(encodedSnapshot), "st-synthesis") ||
		strings.Contains(string(encodedSnapshot), "otlp-native-delta-ingestion") ||
		strings.Contains(string(encodedSnapshot), "metadata-wal-records") ||
		strings.Contains(string(encodedSnapshot), "type-and-unit-labels") ||
		strings.Contains(string(encodedSnapshot), "use-uncached-io") ||
		strings.Contains(string(encodedSnapshot), "storage.remote.read") ||
		strings.Contains(string(encodedSnapshot), "storage.agent.") ||
		strings.Contains(string(encodedSnapshot), "storage.tsdb.") ||
		strings.Contains(string(encodedSnapshot), "web.search.max-limit") ||
		strings.Contains(string(encodedSnapshot), "web.max-connections") ||
		strings.Contains(string(encodedSnapshot), "web.read-timeout") ||
		strings.Contains(string(encodedSnapshot), "alertmanager.notification") ||
		strings.Contains(string(encodedSnapshot), "drain-notification") ||
		strings.Contains(string(encodedSnapshot), "secret-feature") {
		t.Fatalf("sensitive Alertmanager/runtime/flag values must not be persisted in the snapshot: %s", encodedSnapshot)
	}
	if !foundMetadata {
		t.Fatalf("expected metric metadata to be mapped")
	}
	if !foundMetricLabels {
		t.Fatalf("expected metric labels from series to be mapped")
	}
	if !foundSeriesCount {
		t.Fatalf("expected metric series count to be mapped")
	}
	if !foundAlert {
		t.Fatalf("expected active alert metadata to be mapped")
	}
	if !foundAlertRuleDuration {
		t.Fatalf("expected alert rule duration to be mapped")
	}
	if !foundAlertRuleRuntimeLabel {
		t.Fatalf("expected alert rule labels from runtime alert to be merged")
	}
	if !foundRuleMetadata {
		t.Fatalf("expected rule group and evaluation metadata to be mapped")
	}
	if !foundRuleQueryLength {
		t.Fatalf("expected rule query length metadata to be mapped")
	}
	if !foundRecordingRuleOutput {
		t.Fatalf("expected recording rule output metadata to be mapped")
	}
	if !foundTargetMetadata {
		t.Fatalf("expected target scrape metadata to be mapped")
	}
	if !foundTargetDiscoveredLabels {
		t.Fatalf("expected target discovered labels to be normalized")
	}
	if !foundRecordingMetric {
		t.Fatalf("expected recording rule output metric to be mapped")
	}
	if !foundJobContext {
		t.Fatalf("expected job to inherit labels shared by all targets")
	}
	if !foundInstanceContext {
		t.Fatalf("expected instance to inherit its target context")
	}
	if !foundTargetMetadataMetric {
		t.Fatalf("expected target metadata to discover and enrich a low-frequency metric")
	}
	if !foundRecentSeriesFallback {
		t.Fatalf("expected metric omitted from TSDB top results to use the recent series count")
	}
	if !foundMetricLabelCost {
		t.Fatalf("expected TSDB metric label cost metadata to be mapped")
	}
	if !foundTSDBCost {
		t.Fatalf("expected TSDB Head cost summary resource to be mapped")
	}
	if !foundDroppedTarget {
		t.Fatalf("expected dropped target to be mapped without persisting its address")
	}

	enriched := EnrichBusinessServices(snapshot, time.Now().UTC())
	assertRelationship(t, enriched, model.RelationshipBelongsTo, model.ResourceTypeJob, model.ResourceTypeService)
	assertRelationship(t, enriched, model.RelationshipBelongsTo, model.ResourceTypeInstance, model.ResourceTypeService)
}

func TestParsePrometheusOperatorScrapePool(t *testing.T) {
	tests := []struct {
		pool      string
		kind      string
		namespace string
		name      string
		endpoint  string
		ok        bool
	}{
		{pool: "serviceMonitor/prod/api/0", kind: "ServiceMonitor", namespace: "prod", name: "api", endpoint: "0", ok: true},
		{pool: "podMonitor/apps/workers/1", kind: "PodMonitor", namespace: "apps", name: "workers", endpoint: "1", ok: true},
		{pool: "probe/monitoring/public", kind: "Probe", namespace: "monitoring", name: "public", ok: true},
		{pool: "scrapeConfig/monitoring/static", kind: "ScrapeConfig", namespace: "monitoring", name: "static", ok: true},
		{pool: "api-pool", ok: false},
		{pool: "serviceMonitor//api/0", ok: false},
	}
	for _, test := range tests {
		t.Run(test.pool, func(t *testing.T) {
			kind, namespace, name, endpoint, ok := parsePrometheusOperatorScrapePool(test.pool)
			if kind != test.kind || namespace != test.namespace || name != test.name || endpoint != test.endpoint || ok != test.ok {
				t.Fatalf("unexpected parse result: kind=%q namespace=%q name=%q endpoint=%q ok=%t", kind, namespace, name, endpoint, ok)
			}
		})
	}
}

func TestPrometheusCompatibleConnectorUsesPlatformSource(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/label/__name__/values":
			_, _ = w.Write([]byte(`{"status":"success","data":["tenant:http_requests:rate5m"]}`))
		case "/api/v1/metadata":
			_, _ = w.Write([]byte(`{"status":"success","data":{}}`))
		case "/api/v1/targets/metadata":
			http.Error(w, "target metadata unsupported", http.StatusInternalServerError)
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"status":"success","data":{"activeTargets":[]}}`))
		case "/api/v1/rules":
			_, _ = w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
		case "/api/v1/alerts":
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[]}}`))
		case "/api/v1/series":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		case "/api/v1/status/tsdb":
			http.Error(w, "TSDB stats unsupported", http.StatusInternalServerError)
		case "/api/v1/alertmanagers":
			http.NotFound(w, r)
		case "/api/v1/status/runtimeinfo":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	thanosConnector, err := NewThanosConnectorWithOptions("http://thanos.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new thanos connector: %v", err)
	}
	thanosConnector.client = testHTTPClient(handler)

	snapshot, err := thanosConnector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync thanos: %v", err)
	}
	if thanosConnector.ID() != "thanos" || thanosConnector.Name() != "Thanos Connector" {
		t.Fatalf("unexpected connector identity: %s %s", thanosConnector.ID(), thanosConnector.Name())
	}
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTSDB, 1)
	for _, resource := range snapshot.Resources {
		if resource.Source.System != "thanos" || resource.Source.Instance != "http://thanos.test" {
			t.Fatalf("expected thanos source identity, got %#v", resource.Source)
		}
		if resource.Type == model.ResourceTypeTSDB && (resource.Metadata[model.MetadataTargetsDiscoveryAvailable] != "true" || resource.Metadata[model.MetadataActiveTargetCount] != "0") {
			t.Fatalf("expected successful empty target discovery metadata, got %#v", resource.Metadata)
		}
	}

	vmConnector, err := NewVictoriaMetricsConnectorWithOptions("http://victoriametrics.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new victoriametrics connector: %v", err)
	}
	vmConnector.client = testHTTPClient(handler)
	snapshot, err = vmConnector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync victoriametrics: %v", err)
	}
	if vmConnector.ID() != "victoriametrics" || vmConnector.Name() != "VictoriaMetrics Connector" {
		t.Fatalf("unexpected connector identity: %s %s", vmConnector.ID(), vmConnector.Name())
	}
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTSDB, 1)
	for _, resource := range snapshot.Resources {
		if resource.Source.System != "victoriametrics" || resource.Source.Instance != "http://victoriametrics.test" {
			t.Fatalf("expected victoriametrics source identity, got %#v", resource.Source)
		}
	}
}

func assertRelationshipByName(t *testing.T, snapshot Snapshot, relationshipType model.RelationshipType, fromType model.ResourceType, fromName string, toType model.ResourceType, toName string) {
	t.Helper()

	resources := make(map[string]model.Resource)
	for _, resource := range snapshot.Resources {
		resources[resource.ID] = resource
	}
	for _, relationship := range snapshot.Relationships {
		from := resources[relationship.FromID]
		to := resources[relationship.ToID]
		if relationship.Type == relationshipType && from.Type == fromType && from.Name == fromName && to.Type == toType && to.Name == toName {
			return
		}
	}
	t.Fatalf("expected %s relationship from %s %q to %s %q", relationshipType, fromType, fromName, toType, toName)
}

func assertDerivedMetricRelationship(t *testing.T, snapshot Snapshot, inputMetric string, outputMetric string, viaRule string) {
	t.Helper()

	resources := make(map[string]model.Resource)
	for _, resource := range snapshot.Resources {
		resources[resource.ID] = resource
	}
	for _, relationship := range snapshot.Relationships {
		from := resources[relationship.FromID]
		to := resources[relationship.ToID]
		if relationship.Type != model.RelationshipProduces || from.Type != model.ResourceTypeMetric || to.Type != model.ResourceTypeMetric {
			continue
		}
		if from.Name == inputMetric && to.Name == outputMetric && relationship.Metadata["via_rule_name"] == viaRule && relationship.Metadata["via_rule_id"] != "" {
			return
		}
	}
	t.Fatalf("expected derived metric relationship from %q to %q via %q", inputMetric, outputMetric, viaRule)
}

func assertRelationship(t *testing.T, snapshot Snapshot, relationshipType model.RelationshipType, fromType model.ResourceType, toType model.ResourceType) {
	t.Helper()

	resources := make(map[string]model.Resource)
	for _, resource := range snapshot.Resources {
		resources[resource.ID] = resource
	}
	for _, relationship := range snapshot.Relationships {
		from := resources[relationship.FromID]
		to := resources[relationship.ToID]
		if relationship.Type == relationshipType && from.Type == fromType && to.Type == toType {
			return
		}
	}
	t.Fatalf("expected %s relationship from %s to %s", relationshipType, fromType, toType)
}

func assertResourceCount(t *testing.T, snapshot Snapshot, resourceType model.ResourceType, expected int) {
	t.Helper()

	var count int
	for _, resource := range snapshot.Resources {
		if resource.Type == resourceType {
			count++
		}
	}
	if count != expected {
		t.Fatalf("expected %d %s resources, got %d", expected, resourceType, count)
	}
}
