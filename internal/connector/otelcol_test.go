package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestOpenTelemetryCollectorConnectorDiscoversAnonymousRuntimeHealth(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	content := `
receivers:
  otlp:
exporters:
  debug:
extensions:
  health_check:
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	receivedCredentials := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCredentials = r.Header.Get("Authorization") != "" ||
			r.Header.Get("X-API-Key") != "" ||
			r.Header.Get("X-Private") != ""
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"private":"response-body-must-not-persist"}`))
	}))
	defer server.Close()

	item, err := NewOpenTelemetryCollectorConnectorWithRuntimeOptions(configPath, server.URL+"/status", HTTPOptions{
		BearerToken: "secret-token",
		APIKey:      "secret-api-key",
		Headers:     map[string]string{"X-Private": "secret-header"},
	})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	if receivedCredentials {
		t.Fatal("expected health request to omit connector credentials")
	}
	if snapshot.Partial {
		t.Fatal("expected explicit HTTP 503 to remain evaluable rather than partial")
	}
	collector := findOTelColResource(t, snapshot.Resources, model.ResourceTypeInstance, "OpenTelemetry Collector")
	if collector.Metadata[model.MetadataOTelCollectorRuntime] != "true" ||
		collector.Metadata[model.MetadataOTelRuntimeHealthAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelRuntimeHealthy] != "false" ||
		collector.Metadata[model.MetadataOTelRuntimeHealthSource] != "http_status" {
		t.Fatalf("unexpected runtime metadata: %#v", collector.Metadata)
	}
	if len(snapshot.Diagnostics) != 1 ||
		snapshot.Diagnostics[0].ID != "otelcol_health" ||
		snapshot.Diagnostics[0].Status != model.ExecutionStatusWarning {
		t.Fatalf("unexpected health diagnostic: %#v", snapshot.Diagnostics)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, secret := range []string{server.URL, "response-body-must-not-persist", "secret-token", "secret-api-key", "secret-header"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("expected snapshot to omit %q: %s", secret, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorRuntimeHealthAvailability(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	if err := os.WriteFile(configPath, []byte("service:\n  pipelines: {}\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for _, test := range []struct {
		name      string
		status    int
		available string
		healthy   string
		partial   bool
	}{
		{name: "healthy", status: http.StatusNoContent, available: "true", healthy: "true"},
		{name: "unevaluable", status: http.StatusInternalServerError, partial: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			item, err := NewOpenTelemetryCollectorConnectorWithRuntimeOptions(configPath, server.URL, HTTPOptions{})
			if err != nil {
				t.Fatalf("new connector: %v", err)
			}
			snapshot, err := item.Sync(context.Background())
			if err != nil {
				t.Fatalf("sync connector: %v", err)
			}
			if snapshot.Partial != test.partial {
				t.Fatalf("partial=%v, want %v", snapshot.Partial, test.partial)
			}
			collector := findOTelColResource(t, snapshot.Resources, model.ResourceTypeInstance, "OpenTelemetry Collector")
			if collector.Metadata[model.MetadataOTelRuntimeHealthAvailable] != test.available ||
				collector.Metadata[model.MetadataOTelRuntimeHealthy] != test.healthy {
				t.Fatalf("unexpected runtime metadata: %#v", collector.Metadata)
			}
		})
	}
}

func TestOpenTelemetryCollectorConnectorRejectsInvalidHealthURL(t *testing.T) {
	if _, err := NewOpenTelemetryCollectorConnectorWithRuntimeOptions("/tmp/otelcol.yaml", "localhost:13133", HTTPOptions{}); err == nil {
		t.Fatal("expected invalid health URL error")
	}
	if _, err := NewOpenTelemetryCollectorConnectorWithTelemetryOptions("/tmp/otelcol.yaml", "", "localhost:8888/metrics", "", HTTPOptions{}); err == nil {
		t.Fatal("expected invalid metrics URL error")
	}
}

func TestOpenTelemetryCollectorConnectorDiscoversTailSamplingRuntimeMetrics(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	if err := os.WriteFile(configPath, []byte("service:\n  pipelines: {}\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	receivedCredentials := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCredentials = r.Header.Get("Authorization") != "" ||
			r.Header.Get("X-API-Key") != "" ||
			r.Header.Get("X-Private") != ""
		_, _ = w.Write([]byte(`
# TYPE otelcol_process_uptime_seconds_total counter
otelcol_process_uptime_seconds_total{service_instance_id="private-instance"} 3600
# TYPE otelcol_process_cpu_seconds_seconds_total counter
otelcol_process_cpu_seconds_seconds_total{service_instance_id="private-instance",secret="private-cpu-label"} 120
# TYPE otelcol_process_memory_rss_bytes gauge
otelcol_process_memory_rss_bytes{service_instance_id="private-instance",secret="private-rss-label"} 268435456
# TYPE otelcol_process_runtime_heap_alloc_bytes gauge
otelcol_process_runtime_heap_alloc_bytes{service_instance_id="private-instance",secret="private-heap-label"} 134217728
# TYPE otelcol_process_runtime_total_alloc_bytes_total counter
otelcol_process_runtime_total_alloc_bytes_total{service_instance_id="private-instance",secret="private-total-alloc-label"} 1073741824
# TYPE otelcol_process_runtime_total_sys_memory_bytes gauge
otelcol_process_runtime_total_sys_memory_bytes{service_instance_id="private-instance",secret="private-sys-label"} 536870912
# TYPE otelcol_processor_tail_sampling_sampling_trace_dropped_too_early counter
otelcol_processor_tail_sampling_sampling_trace_dropped_too_early{processor="tail_sampling/private-a",service_instance_id="private-instance"} 4
otelcol_processor_tail_sampling_sampling_trace_dropped_too_early{processor="tail_sampling/private-b"} 3
# TYPE otelcol_processor_tail_sampling_traces_dropped_too_large counter
otelcol_processor_tail_sampling_traces_dropped_too_large{processor="tail_sampling/private-a"} 2
# TYPE otelcol_processor_tail_sampling_sampling_policy_evaluation_error counter
otelcol_processor_tail_sampling_sampling_policy_evaluation_error{policy="private-policy"} 5
# TYPE otelcol_exporter_enqueue_failed_log_records counter
otelcol_exporter_enqueue_failed_log_records{exporter="otlp/private-a"} 6
# TYPE otelcol_exporter_enqueue_failed_metric_points counter
otelcol_exporter_enqueue_failed_metric_points{exporter="otlp/private-a"} 7
# TYPE otelcol_exporter_enqueue_failed_spans counter
otelcol_exporter_enqueue_failed_spans{exporter="otlp/private-a"} 8
otelcol_exporter_enqueue_failed_spans{exporter="otlp/private-b"} 1
# TYPE otelcol_exporter_send_failed_log_records counter
otelcol_exporter_send_failed_log_records{exporter="otlp/private-a"} 9
# TYPE otelcol_exporter_send_failed_metric_points counter
otelcol_exporter_send_failed_metric_points{exporter="otlp/private-a"} 10
# TYPE otelcol_exporter_send_failed_spans_total counter
otelcol_exporter_send_failed_spans_total{exporter="otlp/private-a"} 11
# TYPE otelcol_exporter_sent_log_records counter
otelcol_exporter_sent_log_records{exporter="otlp/private-a"} 90
# TYPE otelcol_exporter_sent_metric_points_total counter
otelcol_exporter_sent_metric_points_total{exporter="otlp/private-a"} 80
# TYPE otelcol_exporter_sent_spans counter
otelcol_exporter_sent_spans{exporter="otlp/private-a"} 70
# TYPE otelcol_receiver_refused_log_records counter
otelcol_receiver_refused_log_records{receiver="otlp/private-receiver-a"} 12
# TYPE otelcol_receiver_refused_metric_points counter
otelcol_receiver_refused_metric_points{receiver="otlp/private-receiver-a"} 13
# TYPE otelcol_receiver_refused_spans_total counter
otelcol_receiver_refused_spans_total{receiver="otlp/private-receiver-a"} 14
otelcol_receiver_refused_spans_total{receiver="otlp/private-receiver-b"} 1
# TYPE otelcol_receiver_accepted_log_records counter
otelcol_receiver_accepted_log_records{receiver="otlp/private-receiver-a"} 90
# TYPE otelcol_receiver_accepted_metric_points_total counter
otelcol_receiver_accepted_metric_points_total{receiver="otlp/private-receiver-a"} 80
# TYPE otelcol_receiver_accepted_spans counter
otelcol_receiver_accepted_spans{receiver="otlp/private-receiver-a"} 70
# TYPE otelcol_scraper_errored_metric_points_total counter
otelcol_scraper_errored_metric_points_total{receiver="hostmetrics/private-scraper-a",scraper="cpu/private"} 15
otelcol_scraper_errored_metric_points_total{receiver="hostmetrics/private-scraper-b",scraper="disk/private"} 2
# TYPE otelcol_scraper_scraped_metric_points counter
otelcol_scraper_scraped_metric_points{receiver="hostmetrics/private-scraper-a",scraper="cpu/private"} 90
# TYPE otelcol_scraper_scraped_metric_points_total counter
otelcol_scraper_scraped_metric_points_total{receiver="hostmetrics/private-scraper-b",scraper="disk/private"} 80
# TYPE otelcol_exporter_queue_size gauge
otelcol_exporter_queue_size{exporter="otlp/private-queue-a",service_instance_id="private-queue-instance"} 10
otelcol_exporter_queue_size{exporter="otlp/private-queue-b",service_instance_id="private-queue-instance"} 2
otelcol_exporter_queue_size{exporter="otlp/private-unpaired-size"} 99
otelcol_exporter_queue_size{exporter="otlp/private-zero-capacity"} 1
# TYPE otelcol_exporter_queue_capacity gauge
otelcol_exporter_queue_capacity{service_instance_id="private-queue-instance",exporter="otlp/private-queue-a"} 10
otelcol_exporter_queue_capacity{service_instance_id="private-queue-instance",exporter="otlp/private-queue-b"} 10
otelcol_exporter_queue_capacity{exporter="otlp/private-unpaired-capacity"} 20
otelcol_exporter_queue_capacity{exporter="otlp/private-zero-capacity"} 0
private_unrelated_metric{secret="private-response-label"} 99
`))
	}))
	defer server.Close()

	item, err := NewOpenTelemetryCollectorConnectorWithTelemetryOptions(configPath, "", server.URL+"/private/metrics", "", HTTPOptions{
		BearerToken: "secret-token",
		APIKey:      "secret-api-key",
		Headers:     map[string]string{"X-Private": "secret-header"},
	})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	if receivedCredentials {
		t.Fatal("expected metrics request to omit connector credentials")
	}
	if snapshot.Partial {
		t.Fatal("runtime metrics enrichment must not make a valid topology partial")
	}
	collector := findOTelColResource(t, snapshot.Resources, model.ResourceTypeInstance, "OpenTelemetry Collector")
	if collector.Metadata[model.MetadataOTelCollectorRuntime] != "true" ||
		collector.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelProcessUptimeMetricsAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelProcessTelemetryObserved] != "true" ||
		collector.Metadata[model.MetadataOTelProcessTelemetryMissingCount] != "0" ||
		collector.Metadata[model.MetadataOTelRuntimeRestartEvaluable] != "false" ||
		collector.Metadata[model.MetadataOTelRuntimeRestartObserved] != "false" ||
		collector.Metadata[model.MetadataOTelTailSamplingDroppedTooEarly] != "7" ||
		collector.Metadata[model.MetadataOTelTailSamplingDroppedTooLarge] != "2" ||
		collector.Metadata[model.MetadataOTelTailSamplingPolicyEvalErrors] != "5" ||
		collector.Metadata[model.MetadataOTelExporterEnqueueFailedLogRecords] != "6" ||
		collector.Metadata[model.MetadataOTelExporterEnqueueFailedMetricPoints] != "7" ||
		collector.Metadata[model.MetadataOTelExporterEnqueueFailedSpans] != "9" ||
		collector.Metadata[model.MetadataOTelExporterSendFailedLogRecords] != "9" ||
		collector.Metadata[model.MetadataOTelExporterSendFailedMetricPoints] != "10" ||
		collector.Metadata[model.MetadataOTelExporterSendFailedSpans] != "11" ||
		collector.Metadata[model.MetadataOTelExporterSentMetricsAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelExporterSentTelemetryDelta] != "0" ||
		collector.Metadata[model.MetadataOTelExporterSendFailureRatioEvaluable] != "false" ||
		collector.Metadata[model.MetadataOTelExporterSendFailureRatioPercent] != "0" ||
		collector.Metadata[model.MetadataOTelReceiverRefusedLogRecords] != "12" ||
		collector.Metadata[model.MetadataOTelReceiverRefusedMetricPoints] != "13" ||
		collector.Metadata[model.MetadataOTelReceiverRefusedSpans] != "15" ||
		collector.Metadata[model.MetadataOTelReceiverAcceptedMetricsAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelReceiverAcceptedTelemetryDelta] != "0" ||
		collector.Metadata[model.MetadataOTelReceiverRefusalRatioEvaluable] != "false" ||
		collector.Metadata[model.MetadataOTelReceiverRefusalRatioPercent] != "0" ||
		collector.Metadata[model.MetadataOTelScraperErroredMetricPoints] != "17" ||
		collector.Metadata[model.MetadataOTelScraperScrapedMetricsAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelScraperScrapedMetricPointsDelta] != "0" ||
		collector.Metadata[model.MetadataOTelScraperErrorRatioEvaluable] != "false" ||
		collector.Metadata[model.MetadataOTelScraperErrorRatioPercent] != "0" ||
		collector.Metadata[model.MetadataOTelExporterQueueObservedCount] != "2" ||
		collector.Metadata[model.MetadataOTelExporterQueueSaturatedCount] != "1" ||
		collector.Metadata[model.MetadataOTelExporterQueueMaxUtilizationPercent] != "100" {
		t.Fatalf("unexpected runtime metric metadata: %#v", collector.Metadata)
	}
	if len(snapshot.Diagnostics) != 1 ||
		snapshot.Diagnostics[0].ID != "otelcol_runtime_metrics" ||
		snapshot.Diagnostics[0].Status != model.ExecutionStatusSucceeded {
		t.Fatalf("unexpected runtime metric diagnostic: %#v", snapshot.Diagnostics)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{server.URL, "private/metrics", "private-a", "private-b", "private-instance", "private-policy", "otlp/private-a", "otlp/private-b", "private-receiver-a", "private-receiver-b", "private-scraper-a", "private-scraper-b", "cpu/private", "disk/private", "private-queue-a", "private-queue-b", "private-queue-instance", "private-unpaired-size", "private-unpaired-capacity", "private-zero-capacity", "private-response-label", "private-cpu-label", "private-rss-label", "private-heap-label", "private-total-alloc-label", "private-sys-label", "secret-token", "secret-api-key", "secret-header", `"3600"`, `"268435456"`, `"134217728"`, `"1073741824"`, `"536870912"`} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesIncompleteProcessTelemetry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	if err := os.WriteFile(configPath, []byte("service:\n  pipelines: {}\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`
# TYPE otelcol_process_uptime counter
otelcol_process_uptime{service_instance_id="private-instance"} 3600
# TYPE otelcol_process_cpu_seconds_total counter
otelcol_process_cpu_seconds_total{service_instance_id="private-instance",secret="private-label"} 120
# TYPE otelcol_process_memory_rss gauge
otelcol_process_memory_rss{service_instance_id="private-instance",secret="private-invalid-rss"} -1
private_unrelated_metric{secret="private-unrelated-label"} 268435456
`))
	}))
	defer server.Close()

	item, err := NewOpenTelemetryCollectorConnectorWithTelemetryOptions(configPath, "", server.URL+"/private/process-metrics", "", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	collector := findOTelColResource(t, snapshot.Resources, model.ResourceTypeInstance, "OpenTelemetry Collector")
	if collector.Metadata[model.MetadataOTelProcessUptimeMetricsAvailable] != "true" ||
		collector.Metadata[model.MetadataOTelProcessTelemetryObserved] != "true" ||
		collector.Metadata[model.MetadataOTelProcessTelemetryMissingCount] != "4" {
		t.Fatalf("unexpected process telemetry summary: %#v", collector.Metadata)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{server.URL, "private/process-metrics", "private-instance", "private-label", "private-invalid-rss", "private-unrelated-label", `"3600"`, `"120"`, `"268435456"`} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorRuntimeMetricsFailureIsOptional(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	if err := os.WriteFile(configPath, []byte("service:\n  pipelines: {}\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for _, test := range []struct {
		name       string
		status     int
		body       string
		parseError string
		tooLarge   string
	}{
		{name: "unavailable", status: http.StatusInternalServerError},
		{name: "malformed", status: http.StatusOK, body: "not prometheus text", parseError: "true"},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", otelcolRuntimeMetricsBodyLimit+1), tooLarge: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			item, err := NewOpenTelemetryCollectorConnectorWithTelemetryOptions(configPath, "", server.URL, "", HTTPOptions{})
			if err != nil {
				t.Fatalf("new connector: %v", err)
			}
			snapshot, err := item.Sync(context.Background())
			if err != nil {
				t.Fatalf("sync connector: %v", err)
			}
			if snapshot.Partial {
				t.Fatal("optional runtime metrics failure must not make snapshot partial")
			}
			collector := findOTelColResource(t, snapshot.Resources, model.ResourceTypeInstance, "OpenTelemetry Collector")
			if collector.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "false" {
				t.Fatalf("unexpected metrics availability: %#v", collector.Metadata)
			}
			if len(snapshot.Diagnostics) != 1 ||
				snapshot.Diagnostics[0].Status != model.ExecutionStatusWarning ||
				snapshot.Diagnostics[0].Metadata["parse_error"] != test.parseError ||
				snapshot.Diagnostics[0].Metadata["response_too_large"] != test.tooLarge {
				t.Fatalf("unexpected diagnostic: %#v", snapshot.Diagnostics)
			}
		})
	}
}

func TestOTelColRuntimeCounterDeltaLifecycle(t *testing.T) {
	item := &OpenTelemetryCollectorConnector{}
	startedAt := time.Date(2026, time.July, 30, 10, 0, 0, 0, time.UTC)
	first := otelcolRuntimeMetrics{
		ProcessUptimeMetricsAvailable: true, ProcessUptimeSeconds: 3600,
		DroppedTooEarly: 4, DroppedTooLarge: 2, PolicyEvaluationErrors: 5,
		ExporterEnqueueFailedLogRecords: 6, ExporterEnqueueFailedMetricPoints: 7, ExporterEnqueueFailedSpans: 9,
		ExporterSendFailedLogRecords: 9, ExporterSendFailedMetricPoints: 10, ExporterSendFailedSpans: 11,
		ExporterSentMetricsAvailable: true, ExporterSentLogRecords: 90, ExporterSentMetricPoints: 80, ExporterSentSpans: 70,
		ReceiverRefusedLogRecords: 12, ReceiverRefusedMetricPoints: 13, ReceiverRefusedSpans: 15,
		ReceiverAcceptedMetricsAvailable: true, ReceiverAcceptedLogRecords: 90, ReceiverAcceptedMetricPoints: 80, ReceiverAcceptedSpans: 70,
		ScraperErroredMetricPoints: 17, ScraperScrapedMetricsAvailable: true, ScraperScrapedMetricPoints: 153,
	}
	item.applyRuntimeCounterDeltas(&first, startedAt)
	if first.CounterDeltaAvailable {
		t.Fatalf("first successful scrape must use cumulative fallback: %#v", first)
	}

	stable := first
	stable.ProcessUptimeSeconds = 3660
	item.applyRuntimeCounterDeltas(&stable, startedAt.Add(time.Minute))
	if !stable.CounterDeltaAvailable || stable.CounterDeltaIntervalSeconds != 60 ||
		!stable.RuntimeRestartEvaluable || stable.RuntimeRestartObserved ||
		stable.TailSamplingDropDelta != 0 || stable.TailSamplingPolicyEvalErrorDelta != 0 ||
		stable.ExporterEnqueueFailureDelta != 0 || stable.ExporterSendFailureDelta != 0 ||
		stable.ExporterSentTelemetryDelta != 0 || !stable.ExporterSendFailureRatioEvaluable ||
		stable.ExporterSendFailureRatioPercent != 0 ||
		stable.ReceiverAcceptedTelemetryDelta != 0 || !stable.ReceiverRefusalRatioEvaluable ||
		stable.ReceiverRefusalRatioPercent != 0 ||
		stable.ReceiverRefusedDelta != 0 || stable.ScraperErrorDelta != 0 ||
		stable.ScraperScrapedMetricPointsDelta != 0 || !stable.ScraperErrorRatioEvaluable ||
		stable.ScraperErrorRatioPercent != 0 {
		t.Fatalf("unchanged counters must produce zero deltas: %#v", stable)
	}

	growing := otelcolRuntimeMetrics{
		ProcessUptimeMetricsAvailable: true, ProcessUptimeSeconds: 5,
		DroppedTooEarly: 6, DroppedTooLarge: 3, PolicyEvaluationErrors: 9,
		ExporterEnqueueFailedLogRecords: 7, ExporterEnqueueFailedMetricPoints: 9, ExporterEnqueueFailedSpans: 12,
		ExporterSendFailedLogRecords: 10, ExporterSendFailedMetricPoints: 12, ExporterSendFailedSpans: 14,
		ExporterSentMetricsAvailable: true, ExporterSentLogRecords: 100, ExporterSentMetricPoints: 94, ExporterSentSpans: 100,
		ReceiverRefusedLogRecords: 14, ReceiverRefusedMetricPoints: 16, ReceiverRefusedSpans: 20,
		ReceiverAcceptedMetricsAvailable: true, ReceiverAcceptedLogRecords: 110, ReceiverAcceptedMetricPoints: 110, ReceiverAcceptedSpans: 110,
		ScraperErroredMetricPoints: 23, ScraperScrapedMetricsAvailable: true, ScraperScrapedMetricPoints: 207,
	}
	item.applyRuntimeCounterDeltas(&growing, startedAt.Add(2*time.Minute))
	if !growing.RuntimeRestartEvaluable || !growing.RuntimeRestartObserved ||
		growing.TailSamplingDropDelta != 3 || growing.TailSamplingPolicyEvalErrorDelta != 4 ||
		growing.ExporterEnqueueFailureDelta != 6 || growing.ExporterSendFailureDelta != 6 ||
		growing.ExporterSentTelemetryDelta != 54 || !growing.ExporterSendFailureRatioEvaluable ||
		growing.ExporterSendFailureRatioPercent != 10 ||
		growing.ReceiverAcceptedTelemetryDelta != 90 || !growing.ReceiverRefusalRatioEvaluable ||
		growing.ReceiverRefusalRatioPercent != 10 ||
		growing.ReceiverRefusedDelta != 10 || growing.ScraperErrorDelta != 6 ||
		growing.ScraperScrapedMetricPointsDelta != 54 || !growing.ScraperErrorRatioEvaluable ||
		growing.ScraperErrorRatioPercent != 10 {
		t.Fatalf("unexpected growing counter deltas: %#v", growing)
	}

	reset := otelcolRuntimeMetrics{
		ProcessUptimeMetricsAvailable: true, ProcessUptimeSeconds: 65,
		DroppedTooEarly: 1, DroppedTooLarge: 1, PolicyEvaluationErrors: 1,
		ExporterEnqueueFailedLogRecords: 1, ExporterEnqueueFailedMetricPoints: 1, ExporterEnqueueFailedSpans: 1,
		ExporterSendFailedLogRecords: 1, ExporterSendFailedMetricPoints: 1, ExporterSendFailedSpans: 1,
		ExporterSentMetricsAvailable: true, ExporterSentLogRecords: 9, ExporterSentMetricPoints: 9, ExporterSentSpans: 9,
		ReceiverRefusedLogRecords: 1, ReceiverRefusedMetricPoints: 1, ReceiverRefusedSpans: 1,
		ReceiverAcceptedMetricsAvailable: true, ReceiverAcceptedLogRecords: 9, ReceiverAcceptedMetricPoints: 9, ReceiverAcceptedSpans: 9,
		ScraperErroredMetricPoints: 1, ScraperScrapedMetricsAvailable: true, ScraperScrapedMetricPoints: 9,
	}
	item.applyRuntimeCounterDeltas(&reset, startedAt.Add(3*time.Minute))
	if !reset.RuntimeRestartEvaluable || reset.RuntimeRestartObserved ||
		reset.TailSamplingDropDelta != 2 || reset.TailSamplingPolicyEvalErrorDelta != 1 ||
		reset.ExporterEnqueueFailureDelta != 3 || reset.ExporterSendFailureDelta != 3 ||
		reset.ExporterSentTelemetryDelta != 27 || !reset.ExporterSendFailureRatioEvaluable ||
		reset.ExporterSendFailureRatioPercent != 10 ||
		reset.ReceiverAcceptedTelemetryDelta != 27 || !reset.ReceiverRefusalRatioEvaluable ||
		reset.ReceiverRefusalRatioPercent != 10 ||
		reset.ReceiverRefusedDelta != 3 || reset.ScraperErrorDelta != 1 ||
		reset.ScraperScrapedMetricPointsDelta != 9 || !reset.ScraperErrorRatioEvaluable ||
		reset.ScraperErrorRatioPercent != 10 {
		t.Fatalf("counter reset must use the post-reset value: %#v", reset)
	}
}

func TestOTelColReceiverRefusalRatioRequiresComparableAcceptedCounters(t *testing.T) {
	item := &OpenTelemetryCollectorConnector{}
	startedAt := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	first := otelcolRuntimeMetrics{
		ReceiverRefusedSpans:             10,
		ReceiverAcceptedMetricsAvailable: false,
	}
	item.applyRuntimeCounterDeltas(&first, startedAt)
	second := otelcolRuntimeMetrics{
		ReceiverRefusedSpans:             20,
		ReceiverAcceptedMetricsAvailable: true,
		ReceiverAcceptedSpans:            80,
	}
	item.applyRuntimeCounterDeltas(&second, startedAt.Add(time.Minute))
	if !second.CounterDeltaAvailable || second.ReceiverRefusalRatioEvaluable {
		t.Fatalf("first accepted-counter sample must not compare with an unavailable baseline: %#v", second)
	}
	third := otelcolRuntimeMetrics{
		ReceiverRefusedSpans:             30,
		ReceiverAcceptedMetricsAvailable: true,
		ReceiverAcceptedSpans:            170,
	}
	item.applyRuntimeCounterDeltas(&third, startedAt.Add(2*time.Minute))
	if !third.ReceiverRefusalRatioEvaluable ||
		third.ReceiverRefusedDelta != 10 ||
		third.ReceiverAcceptedTelemetryDelta != 90 ||
		third.ReceiverRefusalRatioPercent != 10 {
		t.Fatalf("unexpected comparable receiver-refusal ratio: %#v", third)
	}
}

func TestOTelColScraperErrorRatioRequiresComparableScrapedCounters(t *testing.T) {
	item := &OpenTelemetryCollectorConnector{}
	startedAt := time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC)
	first := otelcolRuntimeMetrics{
		ScraperErroredMetricPoints:     10,
		ScraperScrapedMetricsAvailable: false,
	}
	item.applyRuntimeCounterDeltas(&first, startedAt)
	second := otelcolRuntimeMetrics{
		ScraperErroredMetricPoints:     20,
		ScraperScrapedMetricsAvailable: true,
		ScraperScrapedMetricPoints:     80,
	}
	item.applyRuntimeCounterDeltas(&second, startedAt.Add(time.Minute))
	if !second.CounterDeltaAvailable || second.ScraperErrorRatioEvaluable {
		t.Fatalf("first scraped-counter sample must not compare with an unavailable baseline: %#v", second)
	}
	third := otelcolRuntimeMetrics{
		ScraperErroredMetricPoints:     30,
		ScraperScrapedMetricsAvailable: true,
		ScraperScrapedMetricPoints:     170,
	}
	item.applyRuntimeCounterDeltas(&third, startedAt.Add(2*time.Minute))
	if !third.ScraperErrorRatioEvaluable ||
		third.ScraperErrorDelta != 10 ||
		third.ScraperScrapedMetricPointsDelta != 90 ||
		third.ScraperErrorRatioPercent != 10 {
		t.Fatalf("unexpected comparable scraper error ratio: %#v", third)
	}
}

func TestOTelColRuntimeRestartRequiresComparableUptimeCounters(t *testing.T) {
	item := &OpenTelemetryCollectorConnector{}
	startedAt := time.Date(2026, time.July, 30, 14, 0, 0, 0, time.UTC)
	first := otelcolRuntimeMetrics{ProcessUptimeMetricsAvailable: false}
	item.applyRuntimeCounterDeltas(&first, startedAt)
	second := otelcolRuntimeMetrics{
		ProcessUptimeMetricsAvailable: true,
		ProcessUptimeSeconds:          100,
	}
	item.applyRuntimeCounterDeltas(&second, startedAt.Add(time.Minute))
	if !second.CounterDeltaAvailable || second.RuntimeRestartEvaluable || second.RuntimeRestartObserved {
		t.Fatalf("first uptime sample must not compare with an unavailable baseline: %#v", second)
	}
	third := otelcolRuntimeMetrics{
		ProcessUptimeMetricsAvailable: true,
		ProcessUptimeSeconds:          160,
	}
	item.applyRuntimeCounterDeltas(&third, startedAt.Add(2*time.Minute))
	if !third.RuntimeRestartEvaluable || third.RuntimeRestartObserved {
		t.Fatalf("increasing uptime must be evaluable without a restart: %#v", third)
	}
	fourth := otelcolRuntimeMetrics{
		ProcessUptimeMetricsAvailable: true,
		ProcessUptimeSeconds:          5,
	}
	item.applyRuntimeCounterDeltas(&fourth, startedAt.Add(3*time.Minute))
	if !fourth.RuntimeRestartEvaluable || !fourth.RuntimeRestartObserved {
		t.Fatalf("uptime reset must prove a runtime restart: %#v", fourth)
	}
}

func TestOTelColExporterSendFailureRatioRequiresComparableSentCounters(t *testing.T) {
	item := &OpenTelemetryCollectorConnector{}
	startedAt := time.Date(2026, time.July, 30, 11, 0, 0, 0, time.UTC)
	first := otelcolRuntimeMetrics{
		ExporterSendFailedSpans:      10,
		ExporterSentMetricsAvailable: false,
	}
	item.applyRuntimeCounterDeltas(&first, startedAt)
	second := otelcolRuntimeMetrics{
		ExporterSendFailedSpans:      20,
		ExporterSentMetricsAvailable: true,
		ExporterSentSpans:            80,
	}
	item.applyRuntimeCounterDeltas(&second, startedAt.Add(time.Minute))
	if !second.CounterDeltaAvailable || second.ExporterSendFailureRatioEvaluable {
		t.Fatalf("first sent-counter sample must not compare with an unavailable baseline: %#v", second)
	}
	third := otelcolRuntimeMetrics{
		ExporterSendFailedSpans:      30,
		ExporterSentMetricsAvailable: true,
		ExporterSentSpans:            170,
	}
	item.applyRuntimeCounterDeltas(&third, startedAt.Add(2*time.Minute))
	if !third.ExporterSendFailureRatioEvaluable ||
		third.ExporterSendFailureDelta != 10 ||
		third.ExporterSentTelemetryDelta != 90 ||
		third.ExporterSendFailureRatioPercent != 10 {
		t.Fatalf("unexpected comparable send-failure ratio: %#v", third)
	}
}

func TestOTelColRuntimeCounterDeltaPreservesBaselineAcrossFailure(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requestCount.Add(1) {
		case 1:
			_, _ = w.Write([]byte("# TYPE otelcol_process_uptime counter\notelcol_process_uptime 100\n# TYPE otelcol_scraper_errored_metric_points_total counter\notelcol_scraper_errored_metric_points_total 10\n# TYPE otelcol_scraper_scraped_metric_points_total counter\notelcol_scraper_scraped_metric_points_total 90\n"))
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			_, _ = w.Write([]byte("# TYPE otelcol_process_uptime counter\notelcol_process_uptime 10\n# TYPE otelcol_scraper_errored_metric_points_total counter\notelcol_scraper_errored_metric_points_total 12\n# TYPE otelcol_scraper_scraped_metric_points_total counter\notelcol_scraper_scraped_metric_points_total 108\n"))
		}
	}))
	defer server.Close()
	item := &OpenTelemetryCollectorConnector{metricsURL: server.URL, healthClient: server.Client()}

	first := item.runtimeMetrics(context.Background())
	failed := item.runtimeMetrics(context.Background())
	third := item.runtimeMetrics(context.Background())
	if !first.Available || first.CounterDeltaAvailable {
		t.Fatalf("unexpected first scrape: %#v", first)
	}
	if failed.Available || failed.CounterDeltaAvailable {
		t.Fatalf("failed scrape must not expose delta evidence: %#v", failed)
	}
	if !third.Available || !third.CounterDeltaAvailable ||
		third.ScraperErrorDelta != 2 ||
		third.ScraperScrapedMetricPointsDelta != 18 ||
		!third.ScraperErrorRatioEvaluable ||
		third.ScraperErrorRatioPercent != 10 ||
		!third.RuntimeRestartEvaluable ||
		!third.RuntimeRestartObserved {
		t.Fatalf("failed scrape must not advance the successful baseline: %#v", third)
	}
}

func TestOpenTelemetryCollectorConnectorNormalizesTailStorageFeatureGate(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-tail-storage.yaml")
	content := []byte(`
receivers:
  otlp:
processors:
  tail_sampling/main:
    tail_storage: file_storage/private-tail-buffer
    policies:
      - name: private-policy
        type: status_code
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [tail_sampling/main]
      exporters: [debug]
`)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write Collector config: %v", err)
	}
	tests := []struct {
		name            string
		spec            string
		evaluable       string
		enabled         string
		recordEvaluable string
		recordEnabled   string
		detailedCount   string
	}{
		{name: "unknown", evaluable: "false", recordEvaluable: "false", detailedCount: "0"},
		{name: "defaults", spec: "defaults", evaluable: "true", enabled: "false", recordEvaluable: "true", recordEnabled: "false", detailedCount: "0"},
		{name: "tail-storage-enabled", spec: "+" + otelcolTailStorageFeatureGate, evaluable: "true", enabled: "true", recordEvaluable: "true", recordEnabled: "false", detailedCount: "0"},
		{name: "tail-storage-explicitly-disabled", spec: "--feature-gates=+private.gate,-" + otelcolTailStorageFeatureGate, evaluable: "true", enabled: "false", recordEvaluable: "true", recordEnabled: "false", detailedCount: "0"},
		{name: "record-policy-enabled", spec: "+" + otelcolRecordPolicyFeatureGate, evaluable: "true", enabled: "false", recordEvaluable: "true", recordEnabled: "true", detailedCount: "0"},
		{name: "one-detailed-metric-enabled", spec: "+" + otelcolMetricStatCountSpansFeatureGate, evaluable: "true", enabled: "false", recordEvaluable: "true", recordEnabled: "false", detailedCount: "1"},
		{name: "both-detailed-metrics-enabled", spec: "+" + otelcolMetricStatCountSpansFeatureGate + ",+" + otelcolMetricStatCountBytesFeatureGate, evaluable: "true", enabled: "false", recordEvaluable: "true", recordEnabled: "false", detailedCount: "2"},
		{name: "both-enabled", spec: "+" + otelcolTailStorageFeatureGate + ",+" + otelcolRecordPolicyFeatureGate, evaluable: "true", enabled: "true", recordEvaluable: "true", recordEnabled: "true", detailedCount: "0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item, err := NewOpenTelemetryCollectorConnectorWithGovernanceOptions(configPath, "", test.spec, HTTPOptions{})
			if err != nil {
				t.Fatalf("create connector: %v", err)
			}
			snapshot, err := item.Sync(context.Background())
			if err != nil {
				t.Fatalf("sync connector: %v", err)
			}
			processor := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/main")
			if processor.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] != "true" ||
				processor.Metadata[model.MetadataOTelTailSamplingTailStorageGateEvaluable] != test.evaluable {
				t.Fatalf("unexpected tail-storage gate summary: %#v", processor.Metadata)
			}
			if test.enabled == "" {
				if _, exists := processor.Metadata[model.MetadataOTelTailSamplingTailStorageGateEnabled]; exists {
					t.Fatalf("unknown gate state must not receive enabled metadata: %#v", processor.Metadata)
				}
			} else if processor.Metadata[model.MetadataOTelTailSamplingTailStorageGateEnabled] != test.enabled {
				t.Fatalf("unexpected tail-storage gate state: %#v", processor.Metadata)
			}
			if processor.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEvaluable] != test.recordEvaluable {
				t.Fatalf("unexpected record-policy gate summary: %#v", processor.Metadata)
			}
			if test.recordEnabled == "" {
				if _, exists := processor.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEnabled]; exists {
					t.Fatalf("unknown record-policy gate must not receive enabled metadata: %#v", processor.Metadata)
				}
			} else if processor.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEnabled] != test.recordEnabled {
				t.Fatalf("unexpected record-policy gate state: %#v", processor.Metadata)
			}
			if processor.Metadata[model.MetadataOTelTailSamplingDetailedMetricsEnabledCnt] != test.detailedCount {
				t.Fatalf("unexpected detailed-metric gate count: %#v", processor.Metadata)
			}
			encoded, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatalf("marshal snapshot: %v", err)
			}
			for _, privateValue := range []string{"private-tail-buffer", "private-policy", "private.gate", otelcolRecordPolicyFeatureGate, otelcolMetricStatCountSpansFeatureGate, otelcolMetricStatCountBytesFeatureGate} {
				if strings.Contains(string(encoded), privateValue) {
					t.Fatalf("snapshot leaked %q: %s", privateValue, encoded)
				}
			}
		})
	}
}

func TestOpenTelemetryCollectorConnectorNormalizesTailStorageExtensionAvailability(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-tail-storage-extensions.yaml")
	content := []byte(`
receivers:
  otlp:
processors:
  tail_sampling/ready:
    tail_storage: file_storage/private-ready
  tail_sampling/declared-disabled:
    tail_storage: file_storage/private-disabled
  tail_sampling/missing:
    tail_storage: file_storage/private-missing
  tail_sampling/dynamic:
    tail_storage: ${PRIVATE_TAIL_STORAGE}
extensions:
  file_storage/private-ready:
  file_storage/private-disabled:
exporters:
  debug:
service:
  extensions: [file_storage/private-ready]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [tail_sampling/ready, tail_sampling/declared-disabled, tail_sampling/missing, tail_sampling/dynamic]
      exporters: [debug]
`)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write Collector config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnectorWithGovernanceOptions(configPath, "", "defaults", HTTPOptions{})
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	tests := []struct {
		name      string
		evaluable string
		ready     string
	}{
		{name: "tail_sampling/ready", evaluable: "true", ready: "true"},
		{name: "tail_sampling/declared-disabled", evaluable: "true", ready: "false"},
		{name: "tail_sampling/missing", evaluable: "true", ready: "false"},
		{name: "tail_sampling/dynamic", evaluable: "false"},
	}
	for _, test := range tests {
		processor := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, test.name)
		if processor.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingTailStorageRefEvaluable] != test.evaluable {
			t.Fatalf("unexpected tail-storage reference summary for %s: %#v", test.name, processor.Metadata)
		}
		if test.ready == "" {
			if _, exists := processor.Metadata[model.MetadataOTelTailSamplingTailStorageExtensionReady]; exists {
				t.Fatalf("dynamic reference must not receive availability metadata: %#v", processor.Metadata)
			}
		} else if processor.Metadata[model.MetadataOTelTailSamplingTailStorageExtensionReady] != test.ready {
			t.Fatalf("unexpected extension availability for %s: %#v", test.name, processor.Metadata)
		}
		encodedProcessor, err := json.Marshal(processor)
		if err != nil {
			t.Fatalf("marshal processor: %v", err)
		}
		for _, privateValue := range []string{"file_storage/private-ready", "file_storage/private-disabled", "file_storage/private-missing", "PRIVATE_TAIL_STORAGE"} {
			if strings.Contains(string(encodedProcessor), privateValue) {
				t.Fatalf("processor leaked tail-storage reference %q: %s", privateValue, encodedProcessor)
			}
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{"file_storage/private-missing", "PRIVATE_TAIL_STORAGE"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorRejectsInvalidFeatureGateEvidence(t *testing.T) {
	for _, spec := range []string{"enabled", "+", "--feature-gates=", "+valid, private"} {
		if _, err := NewOpenTelemetryCollectorConnectorWithGovernanceOptions("/tmp/otelcol.yaml", "", spec, HTTPOptions{}); err == nil {
			t.Fatalf("expected feature gate spec %q to fail", spec)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSyncsConfigTopology(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	content := `
receivers:
  otlp:
    protocols:
      grpc:
  prometheus/app:
    config:
      scrape_configs: []
processors:
  batch:
  memory_limiter:
  transform/tenant:
exporters:
  otlphttp/tempo:
    endpoint: https://secret-backend.example/v1/traces
    headers:
      Authorization: secret-exporter-token
    sending_queue:
      enabled: false
    retry_on_failure:
      enabled: false
    tls:
      insecure: true
      insecure_skip_verify: true
  prometheusremotewrite/main:
    sending_queue:
      enabled: "${env:QUEUE_ENABLED}"
  debug/unused:
service:
  extensions: [health_check, zpages]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp/tempo]
    metrics/main:
      receivers:
        - otlp
        - prometheus/app
      processors:
        - batch
      exporters:
        - prometheusremotewrite/main
extensions:
  health_check:
    endpoint: 127.0.0.1:13133
  zpages:
    endpoint: 0.0.0.0:55679
  pprof/unused:
    endpoint: ${env:PPROF_ENDPOINT}
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	connector, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeProcessor, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeExporter, 3)
	assertResourceCount(t, snapshot, model.ResourceTypePipeline, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeExtension, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	if len(snapshot.Relationships) != 10 {
		t.Fatalf("expected 10 relationships, got %#v", snapshot.Relationships)
	}
	var tracesPipeline model.Resource
	var collectorInstance model.Resource
	var tempoExporter model.Resource
	var prometheusExporter model.Resource
	extensions := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		if resource.Source.System != "otelcol" || resource.Source.Instance != configPath {
			t.Fatalf("expected otelcol source identity, got %#v", resource.Source)
		}
		if resource.Type == model.ResourceTypePipeline && resource.Name == "traces" {
			tracesPipeline = resource
		}
		if resource.Name == "otlphttp/tempo" && resource.Metadata[model.MetadataComponentType] != "otlphttp" {
			t.Fatalf("expected component type metadata, got %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeExporter && resource.Name == "otlphttp/tempo" {
			tempoExporter = resource
		}
		if resource.Type == model.ResourceTypeExporter && resource.Name == "prometheusremotewrite/main" {
			prometheusExporter = resource
		}
		if resource.Type == model.ResourceTypeExtension {
			extensions[resource.Name] = resource
		}
		if resource.Type == model.ResourceTypeInstance {
			collectorInstance = resource
		}
	}
	if tracesPipeline.Metadata[model.MetadataPipelineSignal] != "traces" ||
		tracesPipeline.Metadata[model.MetadataPipelineReceivers] != "otlp" ||
		tracesPipeline.Metadata[model.MetadataPipelineProcessors] != "memory_limiter,batch" ||
		tracesPipeline.Metadata[model.MetadataPipelineExporters] != "otlphttp/tempo" {
		t.Fatalf("expected pipeline metadata, got %#v", tracesPipeline.Metadata)
	}
	if collectorInstance.Metadata[model.MetadataOTelCollectorConfigInstance] != "true" ||
		collectorInstance.Metadata[model.MetadataOTelPipelineCount] != "2" ||
		collectorInstance.Metadata[model.MetadataOTelHealthCheckEnabled] != "true" {
		t.Fatalf("expected collector instance metadata, got %#v", collectorInstance.Metadata)
	}
	if tempoExporter.Metadata[model.MetadataOTelExporterSendingQueueEnabled] != "false" ||
		tempoExporter.Metadata[model.MetadataOTelExporterRetryOnFailureEnabled] != "false" ||
		tempoExporter.Metadata[model.MetadataOTelExporterTLSInsecure] != "true" ||
		tempoExporter.Metadata[model.MetadataOTelExporterTLSInsecureSkipVerify] != "true" {
		t.Fatalf("expected exporter safety booleans, got %#v", tempoExporter.Metadata)
	}
	if _, exists := prometheusExporter.Metadata[model.MetadataOTelExporterSendingQueueEnabled]; exists {
		t.Fatalf("environment-derived queue setting must remain unevaluable, got %#v", prometheusExporter.Metadata)
	}
	if extensions["zpages"].Metadata[model.MetadataOTelEndpointPublic] != "true" ||
		extensions["zpages"].Metadata[model.MetadataOTelExtensionEnabled] != "true" {
		t.Fatalf("expected enabled public zpages metadata, got %#v", extensions["zpages"].Metadata)
	}
	if extensions["pprof/unused"].Metadata[model.MetadataOTelEndpointExposureEvaluable] != "false" ||
		extensions["pprof/unused"].Metadata[model.MetadataOTelExtensionEnabled] != "false" {
		t.Fatalf("expected unevaluable disabled pprof metadata, got %#v", extensions["pprof/unused"].Metadata)
	}
	for _, resource := range snapshot.Resources {
		for _, value := range resource.Metadata {
			if strings.Contains(value, "55679") ||
				strings.Contains(value, "PPROF_ENDPOINT") ||
				strings.Contains(value, "secret-backend") ||
				strings.Contains(value, "secret-exporter-token") ||
				strings.Contains(value, "QUEUE_ENABLED") {
				t.Fatalf("endpoint leaked into resource metadata: %#v", resource)
			}
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesOTLPReceiverExposure(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-receiver-security.yaml")
	content := `
receivers:
  otlp/public:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: "[::]:4318"
        auth:
          authenticator: oidc/secret-name
        tls:
          cert_file: /secret/tls/server.crt
          key_file: /secret/tls/server.key
      custom:
        endpoint: 0.0.0.0:9999
  otlp/loopback:
    protocols:
      grpc:
        endpoint: 127.0.0.1:14317
  otlp/dynamic:
    protocols:
      grpc:
        endpoint: "${env:OTLP_ENDPOINT}"
  prometheus:
    config:
      scrape_configs: []
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp/public, otlp/loopback, otlp/dynamic]
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	public := findOTelColResource(t, snapshot.Resources, model.ResourceTypeReceiver, "otlp/public")
	if public.Metadata[model.MetadataOTelReceiverNetworkSafety] != "true" ||
		public.Metadata[model.MetadataOTelReceiverProtocolCount] != "2" ||
		public.Metadata[model.MetadataOTelReceiverEndpointConfiguredCount] != "2" ||
		public.Metadata[model.MetadataOTelReceiverEndpointEvaluableCount] != "2" ||
		public.Metadata[model.MetadataOTelReceiverPublicEndpointCount] != "2" ||
		public.Metadata[model.MetadataOTelReceiverPublicUnauthenticatedCnt] != "1" ||
		public.Metadata[model.MetadataOTelReceiverPublicPlaintextCount] != "1" {
		t.Fatalf("unexpected public OTLP receiver summary: %#v", public.Metadata)
	}
	loopback := findOTelColResource(t, snapshot.Resources, model.ResourceTypeReceiver, "otlp/loopback")
	if loopback.Metadata[model.MetadataOTelReceiverEndpointEvaluableCount] != "1" ||
		loopback.Metadata[model.MetadataOTelReceiverPublicEndpointCount] != "0" ||
		loopback.Metadata[model.MetadataOTelReceiverPublicUnauthenticatedCnt] != "0" ||
		loopback.Metadata[model.MetadataOTelReceiverPublicPlaintextCount] != "0" {
		t.Fatalf("unexpected loopback OTLP receiver summary: %#v", loopback.Metadata)
	}
	dynamic := findOTelColResource(t, snapshot.Resources, model.ResourceTypeReceiver, "otlp/dynamic")
	if dynamic.Metadata[model.MetadataOTelReceiverEndpointConfiguredCount] != "1" ||
		dynamic.Metadata[model.MetadataOTelReceiverEndpointEvaluableCount] != "0" ||
		dynamic.Metadata[model.MetadataOTelReceiverPublicEndpointCount] != "0" {
		t.Fatalf("environment endpoint must remain exposure-unevaluable: %#v", dynamic.Metadata)
	}
	prometheus := findOTelColResource(t, snapshot.Resources, model.ResourceTypeReceiver, "prometheus")
	if _, exists := prometheus.Metadata[model.MetadataOTelReceiverNetworkSafety]; exists {
		t.Fatalf("non-OTLP receiver must not receive an OTLP safety marker: %#v", prometheus.Metadata)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, secret := range []string{"0.0.0.0:4317", "[::]:4318", "oidc/secret-name", "/secret/tls", "OTLP_ENDPOINT"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("receiver safety snapshot leaked %q: %s", secret, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesMemoryLimiterSafety(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-memory-limiter.yaml")
	content := `
receivers:
  otlp:
processors:
  memory_limiter/mib:
    limit_mib: 987654321
    spike_limit_mib: 123456789
  memory_limiter/percentage:
    limit_percentage: 80
    spike_limit_percentage: 20
  memory_limiter/missing:
    check_interval: 1s
  memory_limiter/invalid:
    limit_percentage: 987
    spike_limit_percentage: 999
  memory_limiter/dynamic:
    limit_mib: "${env:MEMORY_LIMIT_MIB}"
  batch:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors:
        - memory_limiter/mib
        - memory_limiter/percentage
        - memory_limiter/missing
        - memory_limiter/invalid
        - memory_limiter/dynamic
        - batch
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	for _, name := range []string{"memory_limiter/mib", "memory_limiter/percentage"} {
		processor := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if processor.Metadata[model.MetadataOTelMemoryLimiterConfig] != "true" ||
			processor.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount] != "0" {
			t.Fatalf("unexpected valid memory limiter summary for %s: %#v", name, processor.Metadata)
		}
	}
	missing := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "memory_limiter/missing")
	if missing.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] != "false" ||
		missing.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] != "true" ||
		missing.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount] != "0" {
		t.Fatalf("unexpected missing-limit summary: %#v", missing.Metadata)
	}
	invalid := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "memory_limiter/invalid")
	if invalid.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] != "true" ||
		invalid.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] != "true" ||
		invalid.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount] != "2" {
		t.Fatalf("unexpected invalid-limit summary: %#v", invalid.Metadata)
	}
	dynamic := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "memory_limiter/dynamic")
	if dynamic.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] != "true" ||
		dynamic.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] != "false" ||
		dynamic.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount] != "0" {
		t.Fatalf("environment-derived limit must remain unevaluable: %#v", dynamic.Metadata)
	}
	batch := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch")
	if _, exists := batch.Metadata[model.MetadataOTelMemoryLimiterConfig]; exists {
		t.Fatalf("non-memory processor must not receive a memory limiter marker: %#v", batch.Metadata)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{"987654321", "123456789", "MEMORY_LIMIT_MIB"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("memory limiter snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesBatchSafety(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-batch.yaml")
	content := `
receivers:
  otlp:
processors:
  batch/default:
  batch/limited:
    timeout: 0s
    send_batch_max_size: 987654321
  batch/pass-through:
    timeout: 0s
  batch/invalid:
    send_batch_size: 876543210
    send_batch_max_size: 765432109
    timeout: -1s
  batch/dynamic:
    timeout: "${env:PRIVATE_BATCH_TIMEOUT}"
    send_batch_max_size: "${env:PRIVATE_BATCH_MAX_SIZE}"
  batch/malformed:
    timeout: definitely-not-a-duration
  attributes:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch/default, batch/limited, batch/pass-through, batch/invalid, batch/dynamic, batch/malformed, attributes]
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	defaultBatch := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch/default")
	if defaultBatch.Metadata[model.MetadataOTelBatchConfig] != "true" ||
		defaultBatch.Metadata[model.MetadataOTelBatchConfigIssueCount] != "0" ||
		defaultBatch.Metadata[model.MetadataOTelBatchPassThroughEvaluable] != "true" ||
		defaultBatch.Metadata[model.MetadataOTelBatchPassThrough] != "false" {
		t.Fatalf("unexpected default batch summary: %#v", defaultBatch.Metadata)
	}
	limited := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch/limited")
	if limited.Metadata[model.MetadataOTelBatchConfigIssueCount] != "0" ||
		limited.Metadata[model.MetadataOTelBatchPassThroughEvaluable] != "true" ||
		limited.Metadata[model.MetadataOTelBatchPassThrough] != "false" {
		t.Fatalf("zero-timeout max-size mode must retain splitting responsibility: %#v", limited.Metadata)
	}
	passThrough := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch/pass-through")
	if passThrough.Metadata[model.MetadataOTelBatchConfigIssueCount] != "0" ||
		passThrough.Metadata[model.MetadataOTelBatchPassThroughEvaluable] != "true" ||
		passThrough.Metadata[model.MetadataOTelBatchPassThrough] != "true" {
		t.Fatalf("unexpected pass-through batch summary: %#v", passThrough.Metadata)
	}
	invalid := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch/invalid")
	if invalid.Metadata[model.MetadataOTelBatchConfigIssueCount] != "2" ||
		invalid.Metadata[model.MetadataOTelBatchPassThrough] != "false" {
		t.Fatalf("unexpected invalid batch summary: %#v", invalid.Metadata)
	}
	dynamic := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch/dynamic")
	if dynamic.Metadata[model.MetadataOTelBatchConfigIssueCount] != "0" ||
		dynamic.Metadata[model.MetadataOTelBatchPassThroughEvaluable] != "false" ||
		dynamic.Metadata[model.MetadataOTelBatchPassThrough] != "false" {
		t.Fatalf("dynamic batch settings must remain unevaluable: %#v", dynamic.Metadata)
	}
	malformed := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "batch/malformed")
	if malformed.Metadata[model.MetadataOTelBatchConfigIssueCount] != "1" ||
		malformed.Metadata[model.MetadataOTelBatchPassThroughEvaluable] != "false" {
		t.Fatalf("malformed literal timeout must be an explicit issue: %#v", malformed.Metadata)
	}
	attributes := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "attributes")
	if _, exists := attributes.Metadata[model.MetadataOTelBatchConfig]; exists {
		t.Fatalf("non-batch processor must not receive batch metadata: %#v", attributes.Metadata)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{"987654321", "876543210", "765432109", "PRIVATE_BATCH_TIMEOUT", "PRIVATE_BATCH_MAX_SIZE", "definitely-not-a-duration"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("batch snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesTailSamplingSafety(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-tail-sampling.yaml")
	content := `
receivers:
  otlp:
processors:
  tail_sampling/valid:
    sampling_strategy: span-ingest
    policies:
      - name: private-error-policy
        type: status_code
        status_code:
          status_codes: [ERROR]
  tail_sampling/missing:
  tail_sampling/empty:
    policies: []
  tail_sampling/dynamic:
    sampling_strategy: "${env:PRIVATE_SAMPLING_STRATEGY}"
    policies: "${env:PRIVATE_SAMPLING_POLICIES}"
  tail_sampling/invalid-strategy:
    sampling_strategy: private-future-strategy
    policies:
      - name: private-always
        type: always_sample
  tail_sampling/full-capture:
    policies:
      - name: private-catch-all
        type: always_sample
      - name: private-errors
        type: status_code
        status_code:
          status_codes: [ERROR]
  tail_sampling/drop-guarded:
    policies:
      - name: private-catch-all-with-drop
        type: always_sample
      - name: private-drop
        type: drop
        drop:
          drop_sub_policy: []
  tail_sampling/dynamic-type:
    policies:
      - name: private-dynamic-type
        type: "${env:PRIVATE_POLICY_TYPE}"
  tail_sampling/invalid-policy-names:
    policies:
      - type: status_code
      - name:
        type: latency
      - name:
          private: malformed
        type: span_count
      - name: private-duplicate-policy
        type: always_sample
      - name: private-duplicate-policy
        type: status_code
  tail_sampling/dynamic-policy-names:
    policies:
      - name: "${env:PRIVATE_POLICY_NAME}"
        type: status_code
      - name: "${env:PRIVATE_POLICY_NAME}"
        type: latency
  tail_sampling/span-ingest-rate:
    sampling_strategy: span-ingest
    policies:
      - name: private-rate-policy
        type: rate_limiting
  tail_sampling/span-ingest-bytes:
    sampling_strategy: span-ingest
    policies:
      - name: private-bytes-policy
        type: bytes_limiting
  tail_sampling/span-ingest-latency-upper:
    sampling_strategy: span-ingest
    policies:
      - name: private-latency-upper-policy
        type: latency
        latency:
          upper_threshold_ms: 987654321
  tail_sampling/span-ingest-latency-lower:
    sampling_strategy: span-ingest
    policies:
      - name: private-latency-lower-policy
        type: latency
        latency:
          threshold_ms: 123456789
  tail_sampling/span-ingest-span-max:
    sampling_strategy: span-ingest
    policies:
      - name: private-span-max-policy
        type: span_count
        span_count:
          max_spans: 765432109
  tail_sampling/span-ingest-span-min:
    sampling_strategy: span-ingest
    policies:
      - name: private-span-min-policy
        type: span_count
        span_count:
          min_spans: 456789012
  tail_sampling/span-ingest-nested:
    sampling_strategy: span-ingest
    policies:
      - name: private-and-policy
        type: and
        and:
          and_sub_policy:
            - name: private-nested-rate-policy
              type: rate_limiting
      - name: private-drop-policy
        type: drop
        drop:
          drop_sub_policy:
            - name: private-nested-bytes-policy
              type: bytes_limiting
      - name: private-not-policy
        type: not
        not:
          not_sub_policy:
            name: private-nested-latency-policy
            type: latency
            latency:
              upper_threshold_ms: 345678901
      - name: private-composite-policy
        type: composite
        composite:
          composite_sub_policy:
            - name: private-nested-span-policy
              type: span_count
              span_count:
                max_spans: 234567890
  tail_sampling/trace-complete-rate:
    policies:
      - name: private-trace-complete-rate
        type: rate_limiting
  tail_sampling/dynamic-strategy-rate:
    sampling_strategy: "${env:PRIVATE_DYNAMIC_STRATEGY}"
    policies:
      - name: private-dynamic-strategy-rate
        type: rate_limiting
  tail_sampling/span-ingest-dynamic-type:
    sampling_strategy: span-ingest
    policies:
      - name: private-dynamic-stateful-type
        type: "${env:PRIVATE_STATEFUL_POLICY_TYPE}"
  tail_sampling/malformed-policies:
    policies: private-not-a-list
  tail_sampling/drop-pending:
    drop_pending_traces_on_shutdown: true
  tail_sampling/keep-pending:
    drop_pending_traces_on_shutdown: false
  tail_sampling/dynamic-drop-pending:
    drop_pending_traces_on_shutdown: "${env:PRIVATE_DROP_PENDING}"
  tail_sampling/invalid-drop-pending:
    drop_pending_traces_on_shutdown: private-invalid-bool
  tail_sampling/zero-capacity:
    num_traces: 0
  tail_sampling/positive-capacity:
    num_traces: 18446744073709551615
  tail_sampling/dynamic-capacity:
    num_traces: "${env:PRIVATE_NUM_TRACES}"
  tail_sampling/invalid-capacity:
    num_traces: -1
  tail_sampling/undersized-cache:
    num_traces: 98765
    decision_cache:
      sampled_cache_size: 98765
      non_sampled_cache_size: 12345
  tail_sampling/adequate-cache:
    num_traces: 100
    decision_cache:
      sampled_cache_size: 1000
      non_sampled_cache_size: 0
  tail_sampling/default-capacity-cache:
    decision_cache:
      sampled_cache_size: 50000
  tail_sampling/dynamic-cache:
    decision_cache:
      sampled_cache_size: "${env:PRIVATE_SAMPLED_CACHE_SIZE}"
  tail_sampling/invalid-cache:
    decision_cache:
      non_sampled_cache_size: -1
  tail_sampling/valid-core-options:
    decision_wait: 0s
    decision_wait_after_root_received: 1s
    block_on_overflow: true
    sample_on_first_match: false
    expected_new_traces_per_sec: 0
    maximum_trace_size_bytes: 18446744073709551615
  tail_sampling/unbounded-trace-size:
    maximum_trace_size_bytes: 0
  tail_sampling/overflow-eviction:
    block_on_overflow: false
  tail_sampling/dynamic-core-options:
    decision_wait: "${env:PRIVATE_DECISION_WAIT}"
    decision_wait_after_root_received: "${env:PRIVATE_ROOT_WAIT}"
    block_on_overflow: "${env:PRIVATE_BLOCK_OVERFLOW}"
    sample_on_first_match: "${env:PRIVATE_FIRST_MATCH}"
    expected_new_traces_per_sec: "${env:PRIVATE_TRACE_RATE}"
    maximum_trace_size_bytes: "${env:PRIVATE_MAX_TRACE_SIZE}"
  tail_sampling/invalid-core-options:
    decision_wait: private-invalid-duration
    decision_wait_after_root_received: -1s
    block_on_overflow: private-invalid-block
    sample_on_first_match: [true]
    expected_new_traces_per_sec: -1
    maximum_trace_size_bytes: private-invalid-size
  attributes:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [tail_sampling/valid, tail_sampling/missing, tail_sampling/empty, tail_sampling/dynamic, tail_sampling/invalid-strategy, tail_sampling/full-capture, tail_sampling/drop-guarded, tail_sampling/dynamic-type, tail_sampling/invalid-policy-names, tail_sampling/dynamic-policy-names, tail_sampling/span-ingest-rate, tail_sampling/span-ingest-bytes, tail_sampling/span-ingest-latency-upper, tail_sampling/span-ingest-latency-lower, tail_sampling/span-ingest-span-max, tail_sampling/span-ingest-span-min, tail_sampling/span-ingest-nested, tail_sampling/trace-complete-rate, tail_sampling/dynamic-strategy-rate, tail_sampling/span-ingest-dynamic-type, tail_sampling/malformed-policies, tail_sampling/drop-pending, tail_sampling/keep-pending, tail_sampling/dynamic-drop-pending, tail_sampling/invalid-drop-pending, tail_sampling/zero-capacity, tail_sampling/positive-capacity, tail_sampling/dynamic-capacity, tail_sampling/invalid-capacity, tail_sampling/undersized-cache, tail_sampling/adequate-cache, tail_sampling/default-capacity-cache, tail_sampling/dynamic-cache, tail_sampling/invalid-cache, tail_sampling/valid-core-options, tail_sampling/unbounded-trace-size, tail_sampling/overflow-eviction, tail_sampling/dynamic-core-options, tail_sampling/invalid-core-options, attributes]
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	valid := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/valid")
	if valid.Metadata[model.MetadataOTelTailSamplingConfig] != "true" ||
		valid.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelTailSamplingPolicyCount] != "1" ||
		valid.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "0" ||
		valid.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelTailSamplingFullCapture] != "false" ||
		valid.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] != "false" ||
		valid.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] != "false" ||
		valid.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] != "0" {
		t.Fatalf("unexpected valid tail-sampling summary: %#v", valid.Metadata)
	}
	for _, name := range []string{"tail_sampling/missing", "tail_sampling/empty"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelTailSamplingPolicyCount] != "0" ||
			resource.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "0" {
			t.Fatalf("unexpected empty tail-sampling summary for %s: %#v", name, resource.Metadata)
		}
	}
	dynamic := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic")
	if dynamic.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] != "false" ||
		dynamic.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "0" {
		t.Fatalf("dynamic tail-sampling settings must remain unevaluable: %#v", dynamic.Metadata)
	}
	if _, exists := dynamic.Metadata[model.MetadataOTelTailSamplingPolicyCount]; exists {
		t.Fatalf("dynamic policy source must not receive a fabricated count: %#v", dynamic.Metadata)
	}
	invalidStrategy := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/invalid-strategy")
	if invalidStrategy.Metadata[model.MetadataOTelTailSamplingPolicyCount] != "1" ||
		invalidStrategy.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "1" {
		t.Fatalf("unexpected invalid strategy summary: %#v", invalidStrategy.Metadata)
	}
	fullCapture := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/full-capture")
	if fullCapture.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] != "true" ||
		fullCapture.Metadata[model.MetadataOTelTailSamplingFullCapture] != "true" {
		t.Fatalf("unexpected deterministic full-capture summary: %#v", fullCapture.Metadata)
	}
	dropGuarded := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/drop-guarded")
	if dropGuarded.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] != "true" ||
		dropGuarded.Metadata[model.MetadataOTelTailSamplingFullCapture] != "false" {
		t.Fatalf("top-level drop must suppress deterministic full capture: %#v", dropGuarded.Metadata)
	}
	dynamicType := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic-type")
	if dynamicType.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] != "false" {
		t.Fatalf("dynamic policy type must remain unevaluable: %#v", dynamicType.Metadata)
	}
	if _, exists := dynamicType.Metadata[model.MetadataOTelTailSamplingFullCapture]; exists {
		t.Fatalf("dynamic policy type must not receive a fabricated full-capture result: %#v", dynamicType.Metadata)
	}
	invalidPolicyNames := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/invalid-policy-names")
	if invalidPolicyNames.Metadata[model.MetadataOTelTailSamplingPolicyCount] != "5" ||
		invalidPolicyNames.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "4" {
		t.Fatalf("unexpected invalid policy-name summary: %#v", invalidPolicyNames.Metadata)
	}
	dynamicPolicyNames := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic-policy-names")
	if dynamicPolicyNames.Metadata[model.MetadataOTelTailSamplingPolicyCount] != "2" ||
		dynamicPolicyNames.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "0" {
		t.Fatalf("dynamic policy names must remain unevaluable without an issue: %#v", dynamicPolicyNames.Metadata)
	}
	for _, name := range []string{
		"tail_sampling/span-ingest-rate",
		"tail_sampling/span-ingest-bytes",
		"tail_sampling/span-ingest-latency-upper",
		"tail_sampling/span-ingest-span-max",
	} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "1" {
			t.Fatalf("expected one span-ingest stateful-policy issue for %s: %#v", name, resource.Metadata)
		}
	}
	nestedStateful := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/span-ingest-nested")
	if nestedStateful.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "4" {
		t.Fatalf("expected all nested wrapper policies to propagate statefulness: %#v", nestedStateful.Metadata)
	}
	for _, name := range []string{
		"tail_sampling/span-ingest-latency-lower",
		"tail_sampling/span-ingest-span-min",
		"tail_sampling/trace-complete-rate",
		"tail_sampling/dynamic-strategy-rate",
		"tail_sampling/span-ingest-dynamic-type",
	} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "0" {
			t.Fatalf("expected compatible or unevaluable stateful-policy summary for %s: %#v", name, resource.Metadata)
		}
	}
	malformedPolicies := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/malformed-policies")
	if malformedPolicies.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] != "false" ||
		malformedPolicies.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "1" {
		t.Fatalf("unexpected malformed policies summary: %#v", malformedPolicies.Metadata)
	}
	dropPending := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/drop-pending")
	if dropPending.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] != "true" ||
		dropPending.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] != "true" {
		t.Fatalf("unexpected drop-pending summary: %#v", dropPending.Metadata)
	}
	keepPending := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/keep-pending")
	if keepPending.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] != "true" ||
		keepPending.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] != "false" {
		t.Fatalf("unexpected keep-pending summary: %#v", keepPending.Metadata)
	}
	dynamicDropPending := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic-drop-pending")
	if dynamicDropPending.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] != "false" {
		t.Fatalf("dynamic drop-pending value must remain unevaluable: %#v", dynamicDropPending.Metadata)
	}
	if _, exists := dynamicDropPending.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown]; exists {
		t.Fatalf("dynamic drop-pending value must not receive a fabricated result: %#v", dynamicDropPending.Metadata)
	}
	invalidDropPending := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/invalid-drop-pending")
	if invalidDropPending.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] != "false" ||
		invalidDropPending.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "1" {
		t.Fatalf("invalid drop-pending value must join invalid config: %#v", invalidDropPending.Metadata)
	}
	zeroCapacity := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/zero-capacity")
	if zeroCapacity.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] != "true" ||
		zeroCapacity.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] != "true" {
		t.Fatalf("unexpected zero-capacity summary: %#v", zeroCapacity.Metadata)
	}
	positiveCapacity := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/positive-capacity")
	if positiveCapacity.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] != "true" ||
		positiveCapacity.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] != "false" {
		t.Fatalf("full uint64 capacity must remain valid: %#v", positiveCapacity.Metadata)
	}
	dynamicCapacity := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic-capacity")
	if dynamicCapacity.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] != "false" {
		t.Fatalf("dynamic capacity must remain unevaluable: %#v", dynamicCapacity.Metadata)
	}
	if _, exists := dynamicCapacity.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity]; exists {
		t.Fatalf("dynamic capacity must not receive a fabricated result: %#v", dynamicCapacity.Metadata)
	}
	invalidCapacity := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/invalid-capacity")
	if invalidCapacity.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] != "false" ||
		invalidCapacity.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "1" {
		t.Fatalf("invalid capacity must join invalid config: %#v", invalidCapacity.Metadata)
	}
	undersizedCache := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/undersized-cache")
	if undersizedCache.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] != "true" ||
		undersizedCache.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] != "2" {
		t.Fatalf("unexpected undersized decision-cache summary: %#v", undersizedCache.Metadata)
	}
	for _, name := range []string{"tail_sampling/adequate-cache"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] != "0" {
			t.Fatalf("adequate or disabled cache must remain healthy for %s: %#v", name, resource.Metadata)
		}
	}
	defaultCapacityCache := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/default-capacity-cache")
	if defaultCapacityCache.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] != "1" {
		t.Fatalf("default num_traces must participate in cache comparison: %#v", defaultCapacityCache.Metadata)
	}
	dynamicCache := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic-cache")
	if dynamicCache.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] != "false" {
		t.Fatalf("dynamic decision cache must remain unevaluable: %#v", dynamicCache.Metadata)
	}
	if _, exists := dynamicCache.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt]; exists {
		t.Fatalf("dynamic decision cache must not receive a fabricated count: %#v", dynamicCache.Metadata)
	}
	invalidCache := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/invalid-cache")
	if invalidCache.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] != "false" ||
		invalidCache.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "1" {
		t.Fatalf("invalid decision cache must join invalid config: %#v", invalidCache.Metadata)
	}
	for _, name := range []string{"tail_sampling/valid-core-options", "tail_sampling/dynamic-core-options"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "0" {
			t.Fatalf("valid or dynamic core options must not create issues for %s: %#v", name, resource.Metadata)
		}
	}
	validCoreOptions := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/valid-core-options")
	if validCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] != "true" ||
		validCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] != "true" ||
		validCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded] != "false" {
		t.Fatalf("positive maximum trace size must retain protection: %#v", validCoreOptions.Metadata)
	}
	if validCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] != "true" ||
		validCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] != "true" ||
		validCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled] != "true" {
		t.Fatalf("explicit block on overflow must retain backpressure: %#v", validCoreOptions.Metadata)
	}
	unboundedTraceSize := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/unbounded-trace-size")
	if unboundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] != "true" ||
		unboundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] != "true" ||
		unboundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded] != "true" {
		t.Fatalf("explicit zero maximum trace size must disable protection: %#v", unboundedTraceSize.Metadata)
	}
	dynamicCoreOptions := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/dynamic-core-options")
	if dynamicCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] != "true" ||
		dynamicCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] != "false" {
		t.Fatalf("dynamic maximum trace size must remain unevaluable: %#v", dynamicCoreOptions.Metadata)
	}
	if _, exists := dynamicCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded]; exists {
		t.Fatalf("dynamic maximum trace size must not receive a fabricated state: %#v", dynamicCoreOptions.Metadata)
	}
	missingCoreOption := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/valid")
	if missingCoreOption.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] != "false" ||
		missingCoreOption.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] != "false" ||
		missingCoreOption.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] != "false" ||
		missingCoreOption.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] != "false" {
		t.Fatalf("omitted maximum trace size must remain an unconfigured default: %#v", missingCoreOption.Metadata)
	}
	overflowEviction := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/overflow-eviction")
	if overflowEviction.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] != "true" ||
		overflowEviction.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] != "true" ||
		overflowEviction.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled] != "false" {
		t.Fatalf("explicit false block-on-overflow must retain eviction behavior: %#v", overflowEviction.Metadata)
	}
	if dynamicCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] != "true" ||
		dynamicCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] != "false" {
		t.Fatalf("dynamic block-on-overflow must remain unevaluable: %#v", dynamicCoreOptions.Metadata)
	}
	if _, exists := dynamicCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled]; exists {
		t.Fatalf("dynamic block-on-overflow must not receive fabricated state: %#v", dynamicCoreOptions.Metadata)
	}
	invalidCoreOptions := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "tail_sampling/invalid-core-options")
	if invalidCoreOptions.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] != "6" ||
		invalidCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] != "true" ||
		invalidCoreOptions.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] != "false" ||
		invalidCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] != "true" ||
		invalidCoreOptions.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] != "false" {
		t.Fatalf("expected six invalid core-option issues: %#v", invalidCoreOptions.Metadata)
	}
	attributes := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "attributes")
	if _, exists := attributes.Metadata[model.MetadataOTelTailSamplingConfig]; exists {
		t.Fatalf("non-tail-sampling processor must not receive tail metadata: %#v", attributes.Metadata)
	}
	privacySnapshot := snapshot
	privacySnapshot.Resources = append([]model.Resource(nil), snapshot.Resources...)
	for index := range privacySnapshot.Resources {
		privacySnapshot.Resources[index].Source.Instance = ""
	}
	encoded, err := json.Marshal(privacySnapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{
		"private-error-policy",
		"PRIVATE_SAMPLING_STRATEGY",
		"PRIVATE_SAMPLING_POLICIES",
		"private-future-strategy",
		"private-always",
		"private-catch-all",
		"private-errors",
		"private-drop",
		"private-dynamic-type",
		"PRIVATE_POLICY_TYPE",
		"PRIVATE_DROP_PENDING",
		"private-invalid-bool",
		"PRIVATE_NUM_TRACES",
		"18446744073709551615",
		"98765",
		"12345",
		"PRIVATE_SAMPLED_CACHE_SIZE",
		"PRIVATE_DECISION_WAIT",
		"PRIVATE_ROOT_WAIT",
		"PRIVATE_BLOCK_OVERFLOW",
		"PRIVATE_FIRST_MATCH",
		"PRIVATE_TRACE_RATE",
		"PRIVATE_MAX_TRACE_SIZE",
		"private-invalid-duration",
		"private-invalid-block",
		"private-invalid-size",
		"private-duplicate-policy",
		"PRIVATE_POLICY_NAME",
		"private-rate-policy",
		"private-bytes-policy",
		"private-latency-upper-policy",
		"987654321",
		"private-latency-lower-policy",
		"123456789",
		"private-span-max-policy",
		"765432109",
		"private-span-min-policy",
		"456789012",
		"private-and-policy",
		"private-nested-rate-policy",
		"private-drop-policy",
		"private-nested-bytes-policy",
		"private-not-policy",
		"private-nested-latency-policy",
		"345678901",
		"private-composite-policy",
		"private-nested-span-policy",
		"234567890",
		"private-trace-complete-rate",
		"PRIVATE_DYNAMIC_STRATEGY",
		"private-dynamic-strategy-rate",
		"private-dynamic-stateful-type",
		"PRIVATE_STATEFUL_POLICY_TYPE",
		"private-not-a-list",
		"status_codes",
	} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("tail-sampling snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesProbabilisticSamplingSafety(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-probabilistic-sampling.yaml")
	content := `
receivers:
  otlp:
processors:
  probabilistic_sampler/full:
    sampling_percentage: 100
  probabilistic_sampler/over:
    sampling_percentage: 125
  probabilistic_sampler/missing:
  probabilistic_sampler/zero:
    sampling_percentage: 0
  probabilistic_sampler/fraction:
    sampling_percentage: "12.345678"
  probabilistic_sampler/dynamic:
    sampling_percentage: "${env:PRIVATE_SAMPLING_PERCENTAGE}"
  probabilistic_sampler/negative:
    sampling_percentage: -765.432
  probabilistic_sampler/not-a-number:
    sampling_percentage: private-not-a-number
  probabilistic_sampler/nan:
    sampling_percentage: .nan
  probabilistic_sampler/too-small:
    sampling_percentage: 1e-20
  attributes:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [probabilistic_sampler/full, probabilistic_sampler/over, probabilistic_sampler/missing, probabilistic_sampler/zero, probabilistic_sampler/fraction, probabilistic_sampler/dynamic, probabilistic_sampler/negative, probabilistic_sampler/not-a-number, probabilistic_sampler/nan, probabilistic_sampler/too-small, attributes]
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	for _, name := range []string{"probabilistic_sampler/full", "probabilistic_sampler/over"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelProbabilisticSamplerConfig] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticFullCapture] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticDropAll] != "false" ||
			resource.Metadata[model.MetadataOTelProbabilisticConfigIssueCount] != "0" {
			t.Fatalf("unexpected full-capture summary for %s: %#v", name, resource.Metadata)
		}
	}
	for _, name := range []string{"probabilistic_sampler/missing", "probabilistic_sampler/zero"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticFullCapture] != "false" ||
			resource.Metadata[model.MetadataOTelProbabilisticDropAll] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticConfigIssueCount] != "0" {
			t.Fatalf("unexpected drop-all summary for %s: %#v", name, resource.Metadata)
		}
	}
	fraction := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/fraction")
	if fraction.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "true" ||
		fraction.Metadata[model.MetadataOTelProbabilisticFullCapture] != "false" ||
		fraction.Metadata[model.MetadataOTelProbabilisticDropAll] != "false" {
		t.Fatalf("unexpected bounded sampling summary: %#v", fraction.Metadata)
	}
	dynamic := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/dynamic")
	if dynamic.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "false" ||
		dynamic.Metadata[model.MetadataOTelProbabilisticConfigIssueCount] != "0" {
		t.Fatalf("dynamic percentage must remain unevaluable: %#v", dynamic.Metadata)
	}
	for _, key := range []string{model.MetadataOTelProbabilisticFullCapture, model.MetadataOTelProbabilisticDropAll} {
		if _, exists := dynamic.Metadata[key]; exists {
			t.Fatalf("dynamic percentage must not receive %s: %#v", key, dynamic.Metadata)
		}
	}
	for _, name := range []string{"probabilistic_sampler/negative", "probabilistic_sampler/not-a-number", "probabilistic_sampler/nan", "probabilistic_sampler/too-small"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "false" ||
			resource.Metadata[model.MetadataOTelProbabilisticConfigIssueCount] != "1" {
			t.Fatalf("unexpected invalid percentage summary for %s: %#v", name, resource.Metadata)
		}
	}
	attributes := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "attributes")
	if _, exists := attributes.Metadata[model.MetadataOTelProbabilisticSamplerConfig]; exists {
		t.Fatalf("non-probabilistic processor must not receive sampling metadata: %#v", attributes.Metadata)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{"12.345678", "PRIVATE_SAMPLING_PERCENTAGE", "-765.432", "private-not-a-number", "1e-20"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("probabilistic-sampling snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOpenTelemetryCollectorConnectorSummarizesProbabilisticSamplingOptions(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-probabilistic-options.yaml")
	content := `
receivers:
  otlp:
processors:
  probabilistic_sampler/defaults:
    sampling_percentage: 10
  probabilistic_sampler/valid:
    sampling_percentage: 10
    mode: proportional
    sampling_precision: 14
    attribute_source: record
    from_attribute: private-log-key
    fail_closed: true
    hash_seed: 4294967295
  probabilistic_sampler/record-default-mode:
    sampling_percentage: 10
    attribute_source: record
    from_attribute: private-default-log-key
  probabilistic_sampler/record-hash-mode:
    sampling_percentage: 10
    mode: hash_seed
    attribute_source: record
    from_attribute: private-hash-log-key
  probabilistic_sampler/invalid-mode:
    mode: private-future-mode
  probabilistic_sampler/invalid-precision-zero:
    sampling_precision: 0
  probabilistic_sampler/invalid-precision-high:
    sampling_precision: private-precision-765
  probabilistic_sampler/invalid-source:
    attribute_source: private-source
  probabilistic_sampler/invalid-seed-negative:
    hash_seed: -765
  probabilistic_sampler/invalid-seed-high:
    hash_seed: 4294967296
  probabilistic_sampler/invalid-seed-text:
    hash_seed: private-seed
  probabilistic_sampler/fail-open:
    fail_closed: false
  probabilistic_sampler/dynamic:
    mode: "${env:PRIVATE_MODE}"
    sampling_precision: "${env:PRIVATE_PRECISION}"
    attribute_source: "${env:PRIVATE_SOURCE}"
    fail_closed: "${env:PRIVATE_FAIL_CLOSED}"
    hash_seed: "${env:PRIVATE_HASH_SEED}"
  probabilistic_sampler/malformed-fail-closed:
    fail_closed: "false"
  probabilistic_sampler/record-missing:
    sampling_percentage: 10
    attribute_source: record
  probabilistic_sampler/record-dynamic-from:
    sampling_percentage: 10
    attribute_source: record
    from_attribute: "${env:PRIVATE_FROM_ATTRIBUTE}"
  probabilistic_sampler/source-dynamic:
    sampling_percentage: 10
    attribute_source: "${env:PRIVATE_ATTRIBUTE_SOURCE}"
  probabilistic_sampler/from-malformed:
    sampling_percentage: 10
    from_attribute:
      private: value
  attributes:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [probabilistic_sampler/defaults, probabilistic_sampler/valid, probabilistic_sampler/invalid-mode, probabilistic_sampler/invalid-precision-zero, probabilistic_sampler/invalid-precision-high, probabilistic_sampler/invalid-source, probabilistic_sampler/invalid-seed-negative, probabilistic_sampler/invalid-seed-high, probabilistic_sampler/invalid-seed-text, probabilistic_sampler/fail-open, probabilistic_sampler/dynamic, probabilistic_sampler/malformed-fail-closed, attributes]
      exporters: [debug]
    logs:
      receivers: [otlp]
      processors: [probabilistic_sampler/valid, probabilistic_sampler/record-default-mode, probabilistic_sampler/record-hash-mode, probabilistic_sampler/record-missing, probabilistic_sampler/record-dynamic-from, probabilistic_sampler/source-dynamic, probabilistic_sampler/from-malformed]
      exporters: [debug]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	item, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}
	for _, name := range []string{"probabilistic_sampler/defaults", "probabilistic_sampler/valid"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] != "0" ||
			resource.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticFailClosed] != "true" {
			t.Fatalf("unexpected valid option summary for %s: %#v", name, resource.Metadata)
		}
	}
	defaults := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/defaults")
	if defaults.Metadata[model.MetadataOTelProbabilisticUsedByLogs] != "false" {
		t.Fatalf("traces-only sampler must not be marked as logs usage: %#v", defaults.Metadata)
	}
	valid := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/valid")
	if valid.Metadata[model.MetadataOTelProbabilisticUsedByLogs] != "true" ||
		valid.Metadata[model.MetadataOTelProbabilisticAttributeSourceEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] != "true" ||
		valid.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] != "true" ||
		valid.Metadata[model.MetadataOTelProbabilisticModeEvaluable] != "true" ||
		valid.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible] != "false" {
		t.Fatalf("unexpected valid record-source summary: %#v", valid.Metadata)
	}
	for _, name := range []string{"probabilistic_sampler/record-default-mode", "probabilistic_sampler/record-hash-mode"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelProbabilisticModeEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible] != "true" {
			t.Fatalf("expected compatible record-source mode for %s: %#v", name, resource.Metadata)
		}
	}
	recordMissing := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/record-missing")
	if recordMissing.Metadata[model.MetadataOTelProbabilisticUsedByLogs] != "true" ||
		recordMissing.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] != "true" ||
		recordMissing.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] != "true" ||
		recordMissing.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] != "false" {
		t.Fatalf("unexpected missing record-source attribute summary: %#v", recordMissing.Metadata)
	}
	dynamicFrom := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/record-dynamic-from")
	if dynamicFrom.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] != "false" {
		t.Fatalf("dynamic from_attribute must remain unevaluable: %#v", dynamicFrom.Metadata)
	}
	if _, exists := dynamicFrom.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured]; exists {
		t.Fatalf("dynamic from_attribute must not receive configured metadata: %#v", dynamicFrom.Metadata)
	}
	dynamicSource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/source-dynamic")
	if dynamicSource.Metadata[model.MetadataOTelProbabilisticAttributeSourceEvaluable] != "false" {
		t.Fatalf("dynamic attribute_source must remain unevaluable: %#v", dynamicSource.Metadata)
	}
	malformedFrom := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/from-malformed")
	if malformedFrom.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] != "1" ||
		malformedFrom.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] != "false" {
		t.Fatalf("unexpected malformed from_attribute summary: %#v", malformedFrom.Metadata)
	}
	for _, name := range []string{"probabilistic_sampler/invalid-mode", "probabilistic_sampler/invalid-precision-zero", "probabilistic_sampler/invalid-precision-high", "probabilistic_sampler/invalid-source", "probabilistic_sampler/invalid-seed-negative", "probabilistic_sampler/invalid-seed-high", "probabilistic_sampler/invalid-seed-text"} {
		resource := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, name)
		if resource.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] != "1" {
			t.Fatalf("unexpected invalid option summary for %s: %#v", name, resource.Metadata)
		}
	}
	failOpen := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/fail-open")
	if failOpen.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] != "0" ||
		failOpen.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] != "true" ||
		failOpen.Metadata[model.MetadataOTelProbabilisticFailClosed] != "false" {
		t.Fatalf("unexpected fail-open summary: %#v", failOpen.Metadata)
	}
	dynamic := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/dynamic")
	if dynamic.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] != "0" ||
		dynamic.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] != "false" ||
		dynamic.Metadata[model.MetadataOTelProbabilisticModeEvaluable] != "false" {
		t.Fatalf("dynamic options must remain unevaluable: %#v", dynamic.Metadata)
	}
	if _, exists := dynamic.Metadata[model.MetadataOTelProbabilisticFailClosed]; exists {
		t.Fatalf("dynamic fail_closed must not receive a value: %#v", dynamic.Metadata)
	}
	if _, exists := dynamic.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible]; exists {
		t.Fatalf("dynamic mode must not receive compatibility metadata: %#v", dynamic.Metadata)
	}
	malformed := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "probabilistic_sampler/malformed-fail-closed")
	if malformed.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] != "1" ||
		malformed.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] != "false" {
		t.Fatalf("unexpected malformed fail_closed summary: %#v", malformed.Metadata)
	}
	attributes := findOTelColResource(t, snapshot.Resources, model.ResourceTypeProcessor, "attributes")
	if _, exists := attributes.Metadata[model.MetadataOTelProbabilisticOptionIssueCount]; exists {
		t.Fatalf("non-probabilistic processor must not receive option metadata: %#v", attributes.Metadata)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, privateValue := range []string{"private-future-mode", "private-source", "private-precision-765", "-765", "4294967296", "private-seed", "private-log-key", "private-default-log-key", "private-hash-log-key", "PRIVATE_MODE", "PRIVATE_PRECISION", "PRIVATE_SOURCE", "PRIVATE_FAIL_CLOSED", "PRIVATE_HASH_SEED", "PRIVATE_FROM_ATTRIBUTE", "PRIVATE_ATTRIBUTE_SOURCE"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("probabilistic option snapshot leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestParseOTelColConfigTopologyStripsComments(t *testing.T) {
	topology, err := parseOTelColConfigTopology(`
receivers:
  otlp: # main receiver
exporters:
  "debug/test":
service:
  pipelines:
    logs:
      receivers: [otlp] # inline comment
      exporters:
        - "debug/test"
`, otelcolFeatureGateState{}, otelcolFeatureGateState{}, 0)
	if err != nil {
		t.Fatalf("parse topology: %v", err)
	}
	if len(topology.Receivers) != 1 || topology.Receivers[0] != "otlp" {
		t.Fatalf("expected receiver, got %#v", topology.Receivers)
	}
	if len(topology.Exporters) != 1 || topology.Exporters[0] != "debug/test" {
		t.Fatalf("expected quoted exporter key to be preserved, got %#v", topology.Exporters)
	}
	if len(topology.Pipelines) != 1 || topology.Pipelines[0].Exporters[0] != "debug/test" {
		t.Fatalf("expected pipeline exporter, got %#v", topology.Pipelines)
	}
}

func TestOpenTelemetryCollectorConnectorModelsConnectorsAcrossPipelines(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol-connectors.yaml")
	content := `
receivers:
  otlp:
  bridge:
processors:
  batch:
exporters:
  otlphttp/backend:
  bridge:
connectors:
  spanmetrics:
  count/one-sided:
  bridge:
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [spanmetrics, bridge]
    metrics:
      receivers: [spanmetrics, bridge, count/one-sided]
      processors: [batch]
      exporters: [otlphttp/backend]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	connector, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync connector: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeExporter, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeTelemetryConnector, 3)
	assertResourceCount(t, snapshot, model.ResourceTypePipeline, 2)
	if len(snapshot.Relationships) != 9 {
		t.Fatalf("expected nine pipeline relationships, got %#v", snapshot.Relationships)
	}

	resources := make(map[string]model.Resource, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		resources[string(resource.Type)+":"+resource.Name] = resource
	}
	spanmetrics := resources[string(model.ResourceTypeTelemetryConnector)+":spanmetrics"]
	if spanmetrics.Metadata[model.MetadataOTelConnectorReceiverUsage] != "1" ||
		spanmetrics.Metadata[model.MetadataOTelConnectorExporterUsage] != "1" {
		t.Fatalf("expected balanced spanmetrics usage, got %#v", spanmetrics.Metadata)
	}
	oneSided := resources[string(model.ResourceTypeTelemetryConnector)+":count/one-sided"]
	if oneSided.Metadata[model.MetadataOTelConnectorReceiverUsage] != "1" ||
		oneSided.Metadata[model.MetadataOTelConnectorExporterUsage] != "0" {
		t.Fatalf("expected receiver-only connector usage, got %#v", oneSided.Metadata)
	}
	bridge := resources[string(model.ResourceTypeTelemetryConnector)+":bridge"]
	if bridge.Metadata[model.MetadataOTelConnectorReceiverUsage] != "0" ||
		bridge.Metadata[model.MetadataOTelConnectorExporterUsage] != "0" {
		t.Fatalf("expected same-name ordinary components to win over connector references, got %#v", bridge.Metadata)
	}

	spanmetricsIncoming := 0
	for _, relationship := range snapshot.Relationships {
		if relationship.ToID == spanmetrics.ID && relationship.Type == model.RelationshipUses {
			spanmetricsIncoming++
		}
	}
	if spanmetricsIncoming != 2 {
		t.Fatalf("expected both pipelines to use one spanmetrics resource, got %d relationships", spanmetricsIncoming)
	}
}

func TestOpenTelemetryCollectorConnectorRejectsInvalidYAML(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "otelcol.yaml")
	if err := os.WriteFile(configPath, []byte("service:\n  pipelines: [\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	connector, err := NewOpenTelemetryCollectorConnector(configPath)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "parse otelcol config") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestOTelColEndpointExposure(t *testing.T) {
	for _, test := range []struct {
		name       string
		endpoint   string
		configured bool
		evaluable  bool
		public     bool
	}{
		{name: "ipv4 wildcard", endpoint: "0.0.0.0:1777", configured: true, evaluable: true, public: true},
		{name: "ipv6 wildcard", endpoint: "[::]:1777", configured: true, evaluable: true, public: true},
		{name: "empty host", endpoint: ":1777", configured: true, evaluable: true, public: true},
		{name: "loopback", endpoint: "127.0.0.1:1777", configured: true, evaluable: true},
		{name: "url loopback", endpoint: "http://localhost:1777", configured: true, evaluable: true},
		{name: "environment", endpoint: "${env:PPROF_ENDPOINT}", configured: true},
		{name: "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evaluable, public := otelcolEndpointExposure(test.endpoint, test.configured)
			if evaluable != test.evaluable || public != test.public {
				t.Fatalf("got evaluable=%v public=%v, want evaluable=%v public=%v", evaluable, public, test.evaluable, test.public)
			}
		})
	}
}

func findOTelColResource(t *testing.T, resources []model.Resource, resourceType model.ResourceType, name string) model.Resource {
	t.Helper()
	for _, resource := range resources {
		if resource.Type == resourceType && resource.Name == name {
			return resource
		}
	}
	t.Fatalf("resource %s/%q not found in %#v", resourceType, name, resources)
	return model.Resource{}
}
