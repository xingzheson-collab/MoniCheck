package connector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"gopkg.in/yaml.v3"

	"monicheck/internal/model"
)

const (
	otelcolSystem                                 = "otelcol"
	otelcolMinimumProbabilisticSamplingPercentage = 100.0 / (1 << 56)
	otelcolTailStorageFeatureGate                 = "processor.tailsamplingprocessor.tailstorageextension"
	otelcolRecordPolicyFeatureGate                = "processor.tailsamplingprocessor.recordpolicy"
	otelcolMetricStatCountBytesFeatureGate        = "processor.tailsamplingprocessor.metricstatcountbytessampled"
	otelcolMetricStatCountSpansFeatureGate        = "processor.tailsamplingprocessor.metricstatcountspanssampled"
)

type OpenTelemetryCollectorConnector struct {
	configPath                  string
	healthURL                   string
	metricsURL                  string
	healthClient                *http.Client
	tailStorageGateState        otelcolFeatureGateState
	recordPolicyGateState       otelcolFeatureGateState
	detailedMetricsEnabledCount int
	runtimeMetricsMu            sync.Mutex
	runtimeCounterBaseline      otelcolRuntimeCounterSnapshot
	runtimeCounterBaselineAt    time.Time
	runtimeCounterBaselineSet   bool
}

func NewOpenTelemetryCollectorConnector(configPath string) (*OpenTelemetryCollectorConnector, error) {
	return newOpenTelemetryCollectorConnector(configPath, "", "", "", HTTPOptions{})
}

func NewOpenTelemetryCollectorConnectorWithRuntimeOptions(configPath string, healthURL string, options HTTPOptions) (*OpenTelemetryCollectorConnector, error) {
	return newOpenTelemetryCollectorConnector(configPath, healthURL, "", "", options)
}

func NewOpenTelemetryCollectorConnectorWithGovernanceOptions(configPath string, healthURL string, featureGates string, options HTTPOptions) (*OpenTelemetryCollectorConnector, error) {
	return newOpenTelemetryCollectorConnector(configPath, healthURL, "", featureGates, options)
}

func NewOpenTelemetryCollectorConnectorWithTelemetryOptions(configPath string, healthURL string, metricsURL string, featureGates string, options HTTPOptions) (*OpenTelemetryCollectorConnector, error) {
	return newOpenTelemetryCollectorConnector(configPath, healthURL, metricsURL, featureGates, options)
}

func ValidateOpenTelemetryCollectorFeatureGates(featureGates string) error {
	_, err := parseOTelColFeatureGateState(featureGates, otelcolTailStorageFeatureGate, false)
	return err
}

func newOpenTelemetryCollectorConnector(configPath string, healthURL string, metricsURL string, featureGates string, options HTTPOptions) (*OpenTelemetryCollectorConnector, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, fmt.Errorf("otelcol config path is empty")
	}
	healthURL = strings.TrimSpace(healthURL)
	if err := validateOTelColRuntimeURL(healthURL, "health"); err != nil {
		return nil, err
	}
	metricsURL = strings.TrimSpace(metricsURL)
	if err := validateOTelColRuntimeURL(metricsURL, "metrics"); err != nil {
		return nil, err
	}
	tailStorageGateState, err := parseOTelColFeatureGateState(featureGates, otelcolTailStorageFeatureGate, false)
	if err != nil {
		return nil, err
	}
	recordPolicyGateState, err := parseOTelColFeatureGateState(featureGates, otelcolRecordPolicyFeatureGate, false)
	if err != nil {
		return nil, err
	}
	detailedMetricsEnabledCount := 0
	for _, gate := range []string{otelcolMetricStatCountBytesFeatureGate, otelcolMetricStatCountSpansFeatureGate} {
		state, parseErr := parseOTelColFeatureGateState(featureGates, gate, false)
		if parseErr != nil {
			return nil, parseErr
		}
		if state.Evaluable && state.Enabled {
			detailedMetricsEnabledCount++
		}
	}
	options.BearerToken = ""
	options.Username = ""
	options.Password = ""
	options.APIKey = ""
	options.Headers = nil
	healthClient, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &OpenTelemetryCollectorConnector{
		configPath:                  configPath,
		healthURL:                   healthURL,
		metricsURL:                  metricsURL,
		healthClient:                healthClient,
		tailStorageGateState:        tailStorageGateState,
		recordPolicyGateState:       recordPolicyGateState,
		detailedMetricsEnabledCount: detailedMetricsEnabledCount,
	}, nil
}

func validateOTelColRuntimeURL(value string, kind string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid otelcol %s url %q", kind, value)
	}
	return nil
}

func (c *OpenTelemetryCollectorConnector) ID() string {
	return "otelcol"
}

func (c *OpenTelemetryCollectorConnector) Name() string {
	return "OpenTelemetry Collector Connector"
}

func (c *OpenTelemetryCollectorConnector) Sync(ctx context.Context) (Snapshot, error) {
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	content, err := os.ReadFile(c.configPath)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := otelcolSnapshotFromConfig(string(content), c.configPath, c.tailStorageGateState, c.recordPolicyGateState, c.detailedMetricsEnabledCount, time.Now().UTC())
	if err != nil {
		return Snapshot{}, err
	}
	health := c.health(ctx)
	if health.Configured {
		snapshot.Diagnostics = append(snapshot.Diagnostics, otelcolHealthDiagnostic(health))
		if !health.Available {
			snapshot.Partial = true
		}
	}
	runtimeMetrics := c.runtimeMetrics(ctx)
	if runtimeMetrics.Configured {
		snapshot.Diagnostics = append(snapshot.Diagnostics, otelcolRuntimeMetricsDiagnostic(runtimeMetrics))
	}
	for index := range snapshot.Resources {
		resource := &snapshot.Resources[index]
		if resource.Type != model.ResourceTypeInstance ||
			resource.Source.System != otelcolSystem ||
			resource.Metadata[model.MetadataOTelCollectorConfigInstance] != "true" {
			continue
		}
		if health.Available {
			resource.Metadata[model.MetadataOTelCollectorRuntime] = "true"
			resource.Metadata[model.MetadataOTelRuntimeHealthAvailable] = "true"
			resource.Metadata[model.MetadataOTelRuntimeHealthy] = strconv.FormatBool(health.Healthy)
			resource.Metadata[model.MetadataOTelRuntimeHealthSource] = "http_status"
		}
		if runtimeMetrics.Configured {
			resource.Metadata[model.MetadataOTelRuntimeMetricsAvailable] = strconv.FormatBool(runtimeMetrics.Available)
		}
		if runtimeMetrics.Available {
			resource.Metadata[model.MetadataOTelCollectorRuntime] = "true"
			resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = strconv.FormatBool(runtimeMetrics.CounterDeltaAvailable)
			resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = formatOTelColMetricValue(runtimeMetrics.CounterDeltaIntervalSeconds)
			resource.Metadata[model.MetadataOTelProcessUptimeMetricsAvailable] = strconv.FormatBool(runtimeMetrics.ProcessUptimeMetricsAvailable)
			resource.Metadata[model.MetadataOTelProcessTelemetryObserved] = strconv.FormatBool(runtimeMetrics.ProcessTelemetryObserved)
			resource.Metadata[model.MetadataOTelProcessTelemetryMissingCount] = strconv.Itoa(runtimeMetrics.ProcessTelemetryMissingCount)
			resource.Metadata[model.MetadataOTelRuntimeRestartEvaluable] = strconv.FormatBool(runtimeMetrics.RuntimeRestartEvaluable)
			resource.Metadata[model.MetadataOTelRuntimeRestartObserved] = strconv.FormatBool(runtimeMetrics.RuntimeRestartObserved)
			resource.Metadata[model.MetadataOTelTailSamplingDropDelta] = formatOTelColMetricValue(runtimeMetrics.TailSamplingDropDelta)
			resource.Metadata[model.MetadataOTelTailSamplingPolicyEvalErrorDelta] = formatOTelColMetricValue(runtimeMetrics.TailSamplingPolicyEvalErrorDelta)
			resource.Metadata[model.MetadataOTelExporterEnqueueFailureDelta] = formatOTelColMetricValue(runtimeMetrics.ExporterEnqueueFailureDelta)
			resource.Metadata[model.MetadataOTelExporterSendFailureDelta] = formatOTelColMetricValue(runtimeMetrics.ExporterSendFailureDelta)
			resource.Metadata[model.MetadataOTelExporterSentMetricsAvailable] = strconv.FormatBool(runtimeMetrics.ExporterSentMetricsAvailable)
			resource.Metadata[model.MetadataOTelExporterSentTelemetryDelta] = formatOTelColMetricValue(runtimeMetrics.ExporterSentTelemetryDelta)
			resource.Metadata[model.MetadataOTelExporterSendFailureRatioEvaluable] = strconv.FormatBool(runtimeMetrics.ExporterSendFailureRatioEvaluable)
			resource.Metadata[model.MetadataOTelExporterSendFailureRatioPercent] = formatOTelColMetricValue(runtimeMetrics.ExporterSendFailureRatioPercent)
			resource.Metadata[model.MetadataOTelReceiverRefusedDelta] = formatOTelColMetricValue(runtimeMetrics.ReceiverRefusedDelta)
			resource.Metadata[model.MetadataOTelReceiverAcceptedMetricsAvailable] = strconv.FormatBool(runtimeMetrics.ReceiverAcceptedMetricsAvailable)
			resource.Metadata[model.MetadataOTelReceiverAcceptedTelemetryDelta] = formatOTelColMetricValue(runtimeMetrics.ReceiverAcceptedTelemetryDelta)
			resource.Metadata[model.MetadataOTelReceiverRefusalRatioEvaluable] = strconv.FormatBool(runtimeMetrics.ReceiverRefusalRatioEvaluable)
			resource.Metadata[model.MetadataOTelReceiverRefusalRatioPercent] = formatOTelColMetricValue(runtimeMetrics.ReceiverRefusalRatioPercent)
			resource.Metadata[model.MetadataOTelScraperErrorDelta] = formatOTelColMetricValue(runtimeMetrics.ScraperErrorDelta)
			resource.Metadata[model.MetadataOTelScraperScrapedMetricsAvailable] = strconv.FormatBool(runtimeMetrics.ScraperScrapedMetricsAvailable)
			resource.Metadata[model.MetadataOTelScraperScrapedMetricPointsDelta] = formatOTelColMetricValue(runtimeMetrics.ScraperScrapedMetricPointsDelta)
			resource.Metadata[model.MetadataOTelScraperErrorRatioEvaluable] = strconv.FormatBool(runtimeMetrics.ScraperErrorRatioEvaluable)
			resource.Metadata[model.MetadataOTelScraperErrorRatioPercent] = formatOTelColMetricValue(runtimeMetrics.ScraperErrorRatioPercent)
			resource.Metadata[model.MetadataOTelTailSamplingDroppedTooEarly] = formatOTelColMetricValue(runtimeMetrics.DroppedTooEarly)
			resource.Metadata[model.MetadataOTelTailSamplingDroppedTooLarge] = formatOTelColMetricValue(runtimeMetrics.DroppedTooLarge)
			resource.Metadata[model.MetadataOTelTailSamplingPolicyEvalErrors] = formatOTelColMetricValue(runtimeMetrics.PolicyEvaluationErrors)
			resource.Metadata[model.MetadataOTelExporterEnqueueFailedLogRecords] = formatOTelColMetricValue(runtimeMetrics.ExporterEnqueueFailedLogRecords)
			resource.Metadata[model.MetadataOTelExporterEnqueueFailedMetricPoints] = formatOTelColMetricValue(runtimeMetrics.ExporterEnqueueFailedMetricPoints)
			resource.Metadata[model.MetadataOTelExporterEnqueueFailedSpans] = formatOTelColMetricValue(runtimeMetrics.ExporterEnqueueFailedSpans)
			resource.Metadata[model.MetadataOTelExporterSendFailedLogRecords] = formatOTelColMetricValue(runtimeMetrics.ExporterSendFailedLogRecords)
			resource.Metadata[model.MetadataOTelExporterSendFailedMetricPoints] = formatOTelColMetricValue(runtimeMetrics.ExporterSendFailedMetricPoints)
			resource.Metadata[model.MetadataOTelExporterSendFailedSpans] = formatOTelColMetricValue(runtimeMetrics.ExporterSendFailedSpans)
			resource.Metadata[model.MetadataOTelReceiverRefusedLogRecords] = formatOTelColMetricValue(runtimeMetrics.ReceiverRefusedLogRecords)
			resource.Metadata[model.MetadataOTelReceiverRefusedMetricPoints] = formatOTelColMetricValue(runtimeMetrics.ReceiverRefusedMetricPoints)
			resource.Metadata[model.MetadataOTelReceiverRefusedSpans] = formatOTelColMetricValue(runtimeMetrics.ReceiverRefusedSpans)
			resource.Metadata[model.MetadataOTelScraperErroredMetricPoints] = formatOTelColMetricValue(runtimeMetrics.ScraperErroredMetricPoints)
			resource.Metadata[model.MetadataOTelExporterQueueObservedCount] = strconv.Itoa(runtimeMetrics.ExporterQueueObservedCount)
			resource.Metadata[model.MetadataOTelExporterQueueSaturatedCount] = strconv.Itoa(runtimeMetrics.ExporterQueueSaturatedCount)
			resource.Metadata[model.MetadataOTelExporterQueueMaxUtilizationPercent] = formatOTelColMetricValue(runtimeMetrics.ExporterQueueMaxUtilizationPercent)
		}
		break
	}
	return snapshot, nil
}

const otelcolRuntimeMetricsBodyLimit = 4 << 20

type otelcolRuntimeMetrics struct {
	Configured                         bool
	Available                          bool
	StatusCode                         int
	RequestErr                         bool
	ParseErr                           bool
	ResponseTooLarge                   bool
	CounterDeltaAvailable              bool
	CounterDeltaIntervalSeconds        float64
	ProcessUptimeMetricsAvailable      bool
	ProcessTelemetryObserved           bool
	ProcessTelemetryMissingCount       int
	RuntimeRestartEvaluable            bool
	RuntimeRestartObserved             bool
	TailSamplingDropDelta              float64
	TailSamplingPolicyEvalErrorDelta   float64
	ExporterEnqueueFailureDelta        float64
	ExporterSendFailureDelta           float64
	ExporterSentMetricsAvailable       bool
	ExporterSentTelemetryDelta         float64
	ExporterSendFailureRatioEvaluable  bool
	ExporterSendFailureRatioPercent    float64
	ReceiverRefusedDelta               float64
	ReceiverAcceptedMetricsAvailable   bool
	ReceiverAcceptedTelemetryDelta     float64
	ReceiverRefusalRatioEvaluable      bool
	ReceiverRefusalRatioPercent        float64
	ScraperErrorDelta                  float64
	ScraperScrapedMetricsAvailable     bool
	ScraperScrapedMetricPointsDelta    float64
	ScraperErrorRatioEvaluable         bool
	ScraperErrorRatioPercent           float64
	DroppedTooEarly                    float64
	DroppedTooLarge                    float64
	PolicyEvaluationErrors             float64
	ExporterEnqueueFailedLogRecords    float64
	ExporterEnqueueFailedMetricPoints  float64
	ExporterEnqueueFailedSpans         float64
	ExporterSendFailedLogRecords       float64
	ExporterSendFailedMetricPoints     float64
	ExporterSendFailedSpans            float64
	ExporterSentLogRecords             float64
	ExporterSentMetricPoints           float64
	ExporterSentSpans                  float64
	ReceiverRefusedLogRecords          float64
	ReceiverRefusedMetricPoints        float64
	ReceiverRefusedSpans               float64
	ReceiverAcceptedLogRecords         float64
	ReceiverAcceptedMetricPoints       float64
	ReceiverAcceptedSpans              float64
	ScraperErroredMetricPoints         float64
	ScraperScrapedMetricPoints         float64
	ProcessUptimeSeconds               float64
	ExporterQueueObservedCount         int
	ExporterQueueSaturatedCount        int
	ExporterQueueMaxUtilizationPercent float64
}

func (c *OpenTelemetryCollectorConnector) runtimeMetrics(ctx context.Context) otelcolRuntimeMetrics {
	if c.metricsURL == "" {
		return otelcolRuntimeMetrics{}
	}
	result := otelcolRuntimeMetrics{Configured: true}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.metricsURL, nil)
	if err != nil {
		result.RequestErr = true
		return result
	}
	response, err := c.healthClient.Do(request)
	if err != nil {
		result.RequestErr = true
		return result
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, otelcolRuntimeMetricsBodyLimit+1))
	if err != nil {
		result.RequestErr = true
		return result
	}
	if len(body) > otelcolRuntimeMetricsBodyLimit {
		result.ResponseTooLarge = true
		return result
	}
	families, err := (&expfmt.TextParser{}).TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		result.ParseErr = true
		return result
	}
	result.Available = true
	result.ProcessUptimeSeconds, result.ProcessUptimeMetricsAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_process_uptime",
		"otelcol_process_uptime_total",
		"otelcol_process_uptime_seconds_total")
	processMetricAvailability := []bool{
		result.ProcessUptimeMetricsAvailable,
		otelcolMetricFamilyAvailable(families,
			"otelcol_process_cpu_seconds",
			"otelcol_process_cpu_seconds_total",
			"otelcol_process_cpu_seconds_seconds_total"),
		otelcolMetricFamilyAvailable(families,
			"otelcol_process_memory_rss",
			"otelcol_process_memory_rss_bytes"),
		otelcolMetricFamilyAvailable(families,
			"otelcol_process_runtime_heap_alloc_bytes"),
		otelcolMetricFamilyAvailable(families,
			"otelcol_process_runtime_total_alloc_bytes",
			"otelcol_process_runtime_total_alloc_bytes_total"),
		otelcolMetricFamilyAvailable(families,
			"otelcol_process_runtime_total_sys_memory_bytes"),
	}
	for _, available := range processMetricAvailability {
		if available {
			result.ProcessTelemetryObserved = true
		} else {
			result.ProcessTelemetryMissingCount++
		}
	}
	result.DroppedTooEarly = otelcolMetricFamilySum(families,
		"otelcol_processor_tail_sampling_sampling_trace_dropped_too_early",
		"otelcol_processor_tail_sampling_sampling_trace_dropped_too_early_total")
	result.DroppedTooLarge = otelcolMetricFamilySum(families,
		"otelcol_processor_tail_sampling_traces_dropped_too_large",
		"otelcol_processor_tail_sampling_traces_dropped_too_large_total")
	result.PolicyEvaluationErrors = otelcolMetricFamilySum(families,
		"otelcol_processor_tail_sampling_sampling_policy_evaluation_error",
		"otelcol_processor_tail_sampling_sampling_policy_evaluation_error_total")
	result.ExporterEnqueueFailedLogRecords = otelcolMetricFamilySum(families,
		"otelcol_exporter_enqueue_failed_log_records",
		"otelcol_exporter_enqueue_failed_log_records_total")
	result.ExporterEnqueueFailedMetricPoints = otelcolMetricFamilySum(families,
		"otelcol_exporter_enqueue_failed_metric_points",
		"otelcol_exporter_enqueue_failed_metric_points_total")
	result.ExporterEnqueueFailedSpans = otelcolMetricFamilySum(families,
		"otelcol_exporter_enqueue_failed_spans",
		"otelcol_exporter_enqueue_failed_spans_total")
	result.ExporterSendFailedLogRecords = otelcolMetricFamilySum(families,
		"otelcol_exporter_send_failed_log_records",
		"otelcol_exporter_send_failed_log_records_total")
	result.ExporterSendFailedMetricPoints = otelcolMetricFamilySum(families,
		"otelcol_exporter_send_failed_metric_points",
		"otelcol_exporter_send_failed_metric_points_total")
	result.ExporterSendFailedSpans = otelcolMetricFamilySum(families,
		"otelcol_exporter_send_failed_spans",
		"otelcol_exporter_send_failed_spans_total")
	var sentLogRecordsAvailable, sentMetricPointsAvailable, sentSpansAvailable bool
	result.ExporterSentLogRecords, sentLogRecordsAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_exporter_sent_log_records",
		"otelcol_exporter_sent_log_records_total")
	result.ExporterSentMetricPoints, sentMetricPointsAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_exporter_sent_metric_points",
		"otelcol_exporter_sent_metric_points_total")
	result.ExporterSentSpans, sentSpansAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_exporter_sent_spans",
		"otelcol_exporter_sent_spans_total")
	result.ExporterSentMetricsAvailable =
		(sentLogRecordsAvailable || sentMetricPointsAvailable || sentSpansAvailable) &&
			(result.ExporterSendFailedLogRecords == 0 || sentLogRecordsAvailable) &&
			(result.ExporterSendFailedMetricPoints == 0 || sentMetricPointsAvailable) &&
			(result.ExporterSendFailedSpans == 0 || sentSpansAvailable)
	result.ReceiverRefusedLogRecords = otelcolMetricFamilySum(families,
		"otelcol_receiver_refused_log_records",
		"otelcol_receiver_refused_log_records_total")
	result.ReceiverRefusedMetricPoints = otelcolMetricFamilySum(families,
		"otelcol_receiver_refused_metric_points",
		"otelcol_receiver_refused_metric_points_total")
	result.ReceiverRefusedSpans = otelcolMetricFamilySum(families,
		"otelcol_receiver_refused_spans",
		"otelcol_receiver_refused_spans_total")
	var acceptedLogRecordsAvailable, acceptedMetricPointsAvailable, acceptedSpansAvailable bool
	result.ReceiverAcceptedLogRecords, acceptedLogRecordsAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_receiver_accepted_log_records",
		"otelcol_receiver_accepted_log_records_total")
	result.ReceiverAcceptedMetricPoints, acceptedMetricPointsAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_receiver_accepted_metric_points",
		"otelcol_receiver_accepted_metric_points_total")
	result.ReceiverAcceptedSpans, acceptedSpansAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_receiver_accepted_spans",
		"otelcol_receiver_accepted_spans_total")
	result.ReceiverAcceptedMetricsAvailable =
		(acceptedLogRecordsAvailable || acceptedMetricPointsAvailable || acceptedSpansAvailable) &&
			(result.ReceiverRefusedLogRecords == 0 || acceptedLogRecordsAvailable) &&
			(result.ReceiverRefusedMetricPoints == 0 || acceptedMetricPointsAvailable) &&
			(result.ReceiverRefusedSpans == 0 || acceptedSpansAvailable)
	result.ScraperErroredMetricPoints = otelcolMetricFamilySum(families,
		"otelcol_scraper_errored_metric_points",
		"otelcol_scraper_errored_metric_points_total")
	result.ScraperScrapedMetricPoints, result.ScraperScrapedMetricsAvailable = otelcolMetricFamilySumWithAvailability(families,
		"otelcol_scraper_scraped_metric_points",
		"otelcol_scraper_scraped_metric_points_total")
	result.ExporterQueueObservedCount,
		result.ExporterQueueSaturatedCount,
		result.ExporterQueueMaxUtilizationPercent = otelcolExporterQueueSummary(families)
	c.applyRuntimeCounterDeltas(&result, time.Now().UTC())
	return result
}

type otelcolRuntimeCounterSnapshot struct {
	TailSamplingDrops            float64
	TailSamplingPolicyErrors     float64
	ExporterEnqueueFailures      float64
	ExporterSendFailures         float64
	ExporterSentTelemetry        float64
	ExporterSentMetricsReady     bool
	ReceiverRefusals             float64
	ReceiverAcceptedTelemetry    float64
	ReceiverAcceptedMetricsReady bool
	ScraperErrors                float64
	ScraperScrapedMetricPoints   float64
	ScraperScrapedMetricsReady   bool
	ProcessUptimeSeconds         float64
	ProcessUptimeMetricsReady    bool
}

func (metrics otelcolRuntimeMetrics) counterSnapshot() otelcolRuntimeCounterSnapshot {
	return otelcolRuntimeCounterSnapshot{
		TailSamplingDrops:            metrics.DroppedTooEarly + metrics.DroppedTooLarge,
		TailSamplingPolicyErrors:     metrics.PolicyEvaluationErrors,
		ExporterEnqueueFailures:      metrics.ExporterEnqueueFailedLogRecords + metrics.ExporterEnqueueFailedMetricPoints + metrics.ExporterEnqueueFailedSpans,
		ExporterSendFailures:         metrics.ExporterSendFailedLogRecords + metrics.ExporterSendFailedMetricPoints + metrics.ExporterSendFailedSpans,
		ExporterSentTelemetry:        metrics.ExporterSentLogRecords + metrics.ExporterSentMetricPoints + metrics.ExporterSentSpans,
		ExporterSentMetricsReady:     metrics.ExporterSentMetricsAvailable,
		ReceiverRefusals:             metrics.ReceiverRefusedLogRecords + metrics.ReceiverRefusedMetricPoints + metrics.ReceiverRefusedSpans,
		ReceiverAcceptedTelemetry:    metrics.ReceiverAcceptedLogRecords + metrics.ReceiverAcceptedMetricPoints + metrics.ReceiverAcceptedSpans,
		ReceiverAcceptedMetricsReady: metrics.ReceiverAcceptedMetricsAvailable,
		ScraperErrors:                metrics.ScraperErroredMetricPoints,
		ScraperScrapedMetricPoints:   metrics.ScraperScrapedMetricPoints,
		ScraperScrapedMetricsReady:   metrics.ScraperScrapedMetricsAvailable,
		ProcessUptimeSeconds:         metrics.ProcessUptimeSeconds,
		ProcessUptimeMetricsReady:    metrics.ProcessUptimeMetricsAvailable,
	}
}

func (c *OpenTelemetryCollectorConnector) applyRuntimeCounterDeltas(metrics *otelcolRuntimeMetrics, observedAt time.Time) {
	current := metrics.counterSnapshot()
	c.runtimeMetricsMu.Lock()
	defer c.runtimeMetricsMu.Unlock()

	if c.runtimeCounterBaselineSet && observedAt.After(c.runtimeCounterBaselineAt) {
		metrics.CounterDeltaAvailable = true
		metrics.CounterDeltaIntervalSeconds = math.Round(
			observedAt.Sub(c.runtimeCounterBaselineAt).Seconds()*1000,
		) / 1000
		if current.ProcessUptimeMetricsReady && c.runtimeCounterBaseline.ProcessUptimeMetricsReady {
			metrics.RuntimeRestartEvaluable = true
			metrics.RuntimeRestartObserved = current.ProcessUptimeSeconds < c.runtimeCounterBaseline.ProcessUptimeSeconds
		}
		metrics.TailSamplingDropDelta = otelcolCounterDelta(current.TailSamplingDrops, c.runtimeCounterBaseline.TailSamplingDrops)
		metrics.TailSamplingPolicyEvalErrorDelta = otelcolCounterDelta(current.TailSamplingPolicyErrors, c.runtimeCounterBaseline.TailSamplingPolicyErrors)
		metrics.ExporterEnqueueFailureDelta = otelcolCounterDelta(current.ExporterEnqueueFailures, c.runtimeCounterBaseline.ExporterEnqueueFailures)
		metrics.ExporterSendFailureDelta = otelcolCounterDelta(current.ExporterSendFailures, c.runtimeCounterBaseline.ExporterSendFailures)
		if current.ExporterSentMetricsReady && c.runtimeCounterBaseline.ExporterSentMetricsReady {
			metrics.ExporterSentTelemetryDelta = otelcolCounterDelta(current.ExporterSentTelemetry, c.runtimeCounterBaseline.ExporterSentTelemetry)
			metrics.ExporterSendFailureRatioEvaluable = true
			metrics.ExporterSendFailureRatioPercent = otelcolFailureRatioPercent(
				metrics.ExporterSendFailureDelta,
				metrics.ExporterSentTelemetryDelta,
			)
		}
		metrics.ReceiverRefusedDelta = otelcolCounterDelta(current.ReceiverRefusals, c.runtimeCounterBaseline.ReceiverRefusals)
		if current.ReceiverAcceptedMetricsReady && c.runtimeCounterBaseline.ReceiverAcceptedMetricsReady {
			metrics.ReceiverAcceptedTelemetryDelta = otelcolCounterDelta(current.ReceiverAcceptedTelemetry, c.runtimeCounterBaseline.ReceiverAcceptedTelemetry)
			metrics.ReceiverRefusalRatioEvaluable = true
			metrics.ReceiverRefusalRatioPercent = otelcolFailureRatioPercent(
				metrics.ReceiverRefusedDelta,
				metrics.ReceiverAcceptedTelemetryDelta,
			)
		}
		metrics.ScraperErrorDelta = otelcolCounterDelta(current.ScraperErrors, c.runtimeCounterBaseline.ScraperErrors)
		if current.ScraperScrapedMetricsReady && c.runtimeCounterBaseline.ScraperScrapedMetricsReady {
			metrics.ScraperScrapedMetricPointsDelta = otelcolCounterDelta(current.ScraperScrapedMetricPoints, c.runtimeCounterBaseline.ScraperScrapedMetricPoints)
			metrics.ScraperErrorRatioEvaluable = true
			metrics.ScraperErrorRatioPercent = otelcolFailureRatioPercent(
				metrics.ScraperErrorDelta,
				metrics.ScraperScrapedMetricPointsDelta,
			)
		}
	}
	c.runtimeCounterBaseline = current
	c.runtimeCounterBaselineAt = observedAt
	c.runtimeCounterBaselineSet = true
}

func otelcolCounterDelta(current float64, previous float64) float64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func otelcolFailureRatioPercent(failed float64, succeeded float64) float64 {
	attempted := failed + succeeded
	if attempted <= 0 {
		return 0
	}
	return math.Round(failed/attempted*100*1000) / 1000
}

func otelcolMetricFamilySum(families map[string]*dto.MetricFamily, names ...string) float64 {
	total, _ := otelcolMetricFamilySumWithAvailability(families, names...)
	return total
}

func otelcolMetricFamilyAvailable(families map[string]*dto.MetricFamily, names ...string) bool {
	for _, name := range names {
		family, ok := families[name]
		if !ok {
			continue
		}
		for _, metric := range family.GetMetric() {
			if _, valid := otelcolMetricValue(family.GetType(), metric); valid {
				return true
			}
		}
	}
	return false
}

func otelcolMetricFamilySumWithAvailability(families map[string]*dto.MetricFamily, names ...string) (float64, bool) {
	for _, name := range names {
		family, ok := families[name]
		if !ok {
			continue
		}
		total := 0.0
		for _, metric := range family.GetMetric() {
			if value, ok := otelcolMetricValue(family.GetType(), metric); ok {
				total += value
			}
		}
		return total, true
	}
	return 0, false
}

func otelcolMetricValue(metricType dto.MetricType, metric *dto.Metric) (float64, bool) {
	value := 0.0
	switch metricType {
	case dto.MetricType_COUNTER:
		value = metric.GetCounter().GetValue()
	case dto.MetricType_GAUGE:
		value = metric.GetGauge().GetValue()
	case dto.MetricType_UNTYPED:
		value = metric.GetUntyped().GetValue()
	default:
		return 0, false
	}
	return value, value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func otelcolExporterQueueSummary(families map[string]*dto.MetricFamily) (int, int, float64) {
	sizes := otelcolMetricFamilyValuesByLabelSet(families, "otelcol_exporter_queue_size")
	capacities := otelcolMetricFamilyValuesByLabelSet(families, "otelcol_exporter_queue_capacity")
	observed := 0
	saturated := 0
	maxUtilization := 0.0
	for labelSet, capacity := range capacities {
		size, ok := sizes[labelSet]
		if !ok || capacity <= 0 {
			continue
		}
		observed++
		utilization := size / capacity * 100
		if utilization > maxUtilization {
			maxUtilization = utilization
		}
		if size >= capacity {
			saturated++
		}
	}
	return observed, saturated, maxUtilization
}

func otelcolMetricFamilyValuesByLabelSet(families map[string]*dto.MetricFamily, names ...string) map[string]float64 {
	values := map[string]float64{}
	for _, name := range names {
		family, ok := families[name]
		if !ok {
			continue
		}
		for _, metric := range family.GetMetric() {
			value, valid := otelcolMetricValue(family.GetType(), metric)
			if !valid {
				continue
			}
			labels := make([]string, 0, len(metric.GetLabel()))
			for _, label := range metric.GetLabel() {
				labelName := label.GetName()
				labelValue := label.GetValue()
				labels = append(labels,
					strconv.Itoa(len(labelName))+":"+labelName+
						strconv.Itoa(len(labelValue))+":"+labelValue)
			}
			sort.Strings(labels)
			values[strings.Join(labels, "|")] = value
		}
		return values
	}
	return values
}

func formatOTelColMetricValue(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func otelcolRuntimeMetricsDiagnostic(metrics otelcolRuntimeMetrics) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "OpenTelemetry Collector runtime metrics discovery completed"
	if !metrics.Available {
		status = model.ExecutionStatusWarning
		message = "OpenTelemetry Collector runtime metrics endpoint is unavailable; configuration discovery continued"
	}
	metadata := map[string]string{
		"configured": strconv.FormatBool(metrics.Configured),
		"available":  strconv.FormatBool(metrics.Available),
	}
	if metrics.StatusCode != 0 {
		metadata["status_code"] = strconv.Itoa(metrics.StatusCode)
	}
	if metrics.RequestErr {
		metadata["request_error"] = "true"
	}
	if metrics.ParseErr {
		metadata["parse_error"] = "true"
	}
	if metrics.ResponseTooLarge {
		metadata["response_too_large"] = "true"
	}
	return model.Diagnostic{
		ID:       "otelcol_runtime_metrics",
		Name:     "OpenTelemetry Collector runtime metrics",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

type otelcolHealth struct {
	Configured bool
	Available  bool
	Healthy    bool
	StatusCode int
	RequestErr bool
}

func (c *OpenTelemetryCollectorConnector) health(ctx context.Context) otelcolHealth {
	if c.healthURL == "" {
		return otelcolHealth{}
	}
	result := otelcolHealth{Configured: true}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.healthURL, nil)
	if err != nil {
		result.RequestErr = true
		return result
	}
	response, err := c.healthClient.Do(request)
	if err != nil {
		result.RequestErr = true
		return result
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	switch {
	case response.StatusCode == http.StatusServiceUnavailable:
		result.Available = true
		result.Healthy = false
	case response.StatusCode >= 200 && response.StatusCode < 300:
		result.Available = true
		result.Healthy = true
	}
	return result
}

func otelcolHealthDiagnostic(health otelcolHealth) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "OpenTelemetry Collector health discovery completed"
	if health.Available && !health.Healthy {
		status = model.ExecutionStatusWarning
		message = "OpenTelemetry Collector health endpoint explicitly reports the runtime as unhealthy"
	} else if !health.Available {
		status = model.ExecutionStatusWarning
		message = "OpenTelemetry Collector health endpoint is unavailable; configuration discovery continued"
	}
	metadata := map[string]string{
		"configured": strconv.FormatBool(health.Configured),
		"available":  strconv.FormatBool(health.Available),
	}
	if health.Available {
		metadata["healthy"] = strconv.FormatBool(health.Healthy)
	}
	if health.StatusCode != 0 {
		metadata["status_code"] = strconv.Itoa(health.StatusCode)
	}
	if health.RequestErr {
		metadata["request_error"] = "true"
	}
	return model.Diagnostic{
		ID:       "otelcol_health",
		Name:     "OpenTelemetry Collector runtime health",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

type otelcolPipeline struct {
	Name       string
	Signal     string
	Receivers  []string
	Processors []string
	Exporters  []string
}

type otelcolExtension struct {
	Name                      string
	Declared                  bool
	Enabled                   bool
	EndpointConfigured        bool
	EndpointExposureEvaluable bool
	EndpointPublic            bool
}

type otelcolConfigTopology struct {
	Receivers           []string
	ReceiverSafety      map[string]otelcolReceiverSafety
	Processors          []string
	ProcessorSafety     map[string]otelcolProcessorSafety
	BatchSafety         map[string]otelcolBatchSafety
	TailSafety          map[string]otelcolTailSamplingSafety
	ProbabilisticSafety map[string]otelcolProbabilisticSamplingSafety
	Exporters           []string
	ExporterSafety      map[string]otelcolExporterSafety
	Connectors          []string
	Extensions          []otelcolExtension
	Pipelines           []otelcolPipeline
}

type otelcolReceiverSafety struct {
	ProtocolCount              int
	EndpointConfiguredCount    int
	EndpointEvaluableCount     int
	PublicEndpointCount        int
	PublicUnauthenticatedCount int
	PublicPlaintextCount       int
}

type otelcolOptionalBool struct {
	Value     bool
	Evaluable bool
}

type otelcolExporterSafety struct {
	SendingQueueEnabled   otelcolOptionalBool
	RetryOnFailureEnabled otelcolOptionalBool
	TLSInsecure           otelcolOptionalBool
	TLSInsecureSkipVerify otelcolOptionalBool
}

type otelcolProcessorSafety struct {
	LimitConfigured         bool
	LimitEvaluable          bool
	ConfigurationIssueCount int
}

type otelcolOptionalInt struct {
	Value      int64
	Configured bool
	Evaluable  bool
}

type otelcolOptionalUint64 struct {
	Value      uint64
	Configured bool
	Evaluable  bool
	Invalid    bool
}

type otelcolOptionalDuration struct {
	Value      time.Duration
	Configured bool
	Evaluable  bool
	Invalid    bool
}

type otelcolFeatureGateState struct {
	Evaluable bool
	Enabled   bool
}

type otelcolBatchSafety struct {
	ConfigurationIssueCount int
	PassThroughEvaluable    bool
	PassThrough             bool
}

type otelcolTailSamplingSafety struct {
	PolicyCount                 int
	PoliciesEvaluable           bool
	ConfigurationIssueCount     int
	FullCaptureEvaluable        bool
	FullCapture                 bool
	DropPendingEvaluable        bool
	DropPendingOnShutdown       bool
	TraceCapacityEvaluable      bool
	ZeroTraceCapacity           bool
	DecisionCacheEvaluable      bool
	UndersizedCacheCount        int
	TailStorageConfigured       bool
	TailStorageGateEvaluable    bool
	TailStorageGateEnabled      bool
	TailStorageReference        string
	TailStorageRefEvaluable     bool
	TailStorageExtensionReady   bool
	MaxTraceSizeConfigured      bool
	MaxTraceSizeEvaluable       bool
	MaxTraceSizeUnbounded       bool
	BlockOverflowConfigured     bool
	BlockOverflowEvaluable      bool
	BlockOverflowEnabled        bool
	RecordPolicyGateEvaluable   bool
	RecordPolicyGateEnabled     bool
	DetailedMetricsEnabledCount int
}

type otelcolProbabilisticSamplingSafety struct {
	PercentageEvaluable        bool
	FullCapture                bool
	DropAll                    bool
	ConfigurationIssueCount    int
	OptionIssueCount           int
	FailClosedEvaluable        bool
	FailClosed                 bool
	AttributeSourceEvaluable   bool
	AttributeSourceRecord      bool
	FromAttributeEvaluable     bool
	FromAttributeConfigured    bool
	ModeEvaluable              bool
	RecordSourceModeCompatible bool
}

type otelcolConfigDocument struct {
	Receivers  map[string]yaml.Node `yaml:"receivers"`
	Processors map[string]yaml.Node `yaml:"processors"`
	Exporters  map[string]yaml.Node `yaml:"exporters"`
	Connectors map[string]yaml.Node `yaml:"connectors"`
	Extensions map[string]yaml.Node `yaml:"extensions"`
	Service    struct {
		Extensions []string `yaml:"extensions"`
		Pipelines  map[string]struct {
			Receivers  []string `yaml:"receivers"`
			Processors []string `yaml:"processors"`
			Exporters  []string `yaml:"exporters"`
		} `yaml:"pipelines"`
	} `yaml:"service"`
}

func otelcolSnapshotFromConfig(content string, instance string, tailStorageGateState, recordPolicyGateState otelcolFeatureGateState, detailedMetricsEnabledCount int, now time.Time) (Snapshot, error) {
	topology, err := parseOTelColConfigTopology(content, tailStorageGateState, recordPolicyGateState, detailedMetricsEnabledCount)
	if err != nil {
		return Snapshot{}, err
	}
	resourcesByID := map[string]model.Resource{}
	relationshipsByID := map[string]model.Relationship{}

	addComponent := func(kind string, resourceType model.ResourceType, name string) model.Resource {
		resource := otelcolResource(resourceType, name, instance, kind+":"+name, now)
		resource.Metadata[model.MetadataComponentKind] = kind
		resource.Metadata[model.MetadataComponentType] = componentType(name)
		resourcesByID[resource.ID] = resource
		return resource
	}
	for _, receiver := range topology.Receivers {
		addComponent("receiver", model.ResourceTypeReceiver, receiver)
	}
	for _, processor := range topology.Processors {
		addComponent("processor", model.ResourceTypeProcessor, processor)
	}
	for _, exporter := range topology.Exporters {
		addComponent("exporter", model.ResourceTypeExporter, exporter)
	}
	receiverNames := stringSet(topology.Receivers)
	exporterNames := stringSet(topology.Exporters)
	connectorNames := stringSet(topology.Connectors)
	connectorReceiverUsage := make(map[string]int, len(topology.Connectors))
	connectorExporterUsage := make(map[string]int, len(topology.Connectors))
	for _, pipeline := range topology.Pipelines {
		for _, receiver := range pipeline.Receivers {
			if connectorNames[receiver] && !receiverNames[receiver] {
				connectorReceiverUsage[receiver]++
			}
		}
		for _, exporter := range pipeline.Exporters {
			if connectorNames[exporter] && !exporterNames[exporter] {
				connectorExporterUsage[exporter]++
			}
		}
	}
	for _, connector := range topology.Connectors {
		resource := addComponent("connector", model.ResourceTypeTelemetryConnector, connector)
		resource.Metadata[model.MetadataOTelConnectorReceiverUsage] = strconv.Itoa(connectorReceiverUsage[connector])
		resource.Metadata[model.MetadataOTelConnectorExporterUsage] = strconv.Itoa(connectorExporterUsage[connector])
		resourcesByID[resource.ID] = resource
	}
	for _, extension := range topology.Extensions {
		resource := addComponent("extension", model.ResourceTypeExtension, extension.Name)
		resource.Metadata[model.MetadataOTelExtensionDeclared] = strconv.FormatBool(extension.Declared)
		resource.Metadata[model.MetadataOTelExtensionEnabled] = strconv.FormatBool(extension.Enabled)
		resource.Metadata[model.MetadataOTelEndpointConfigured] = strconv.FormatBool(extension.EndpointConfigured)
		resource.Metadata[model.MetadataOTelEndpointExposureEvaluable] = strconv.FormatBool(extension.EndpointExposureEvaluable)
		resource.Metadata[model.MetadataOTelEndpointPublic] = strconv.FormatBool(extension.EndpointPublic)
		resourcesByID[resource.ID] = resource
	}

	for _, pipeline := range topology.Pipelines {
		pipelineResource := otelcolResource(model.ResourceTypePipeline, pipeline.Name, instance, "pipeline:"+pipeline.Name, now)
		pipelineResource.Metadata[model.MetadataComponentKind] = "pipeline"
		pipelineResource.Metadata[model.MetadataPipelineSignal] = pipeline.Signal
		pipelineResource.Metadata[model.MetadataPipelineReceivers] = strings.Join(pipeline.Receivers, ",")
		pipelineResource.Metadata[model.MetadataPipelineProcessors] = strings.Join(pipeline.Processors, ",")
		pipelineResource.Metadata[model.MetadataPipelineExporters] = strings.Join(pipeline.Exporters, ",")
		resourcesByID[pipelineResource.ID] = pipelineResource

		for _, receiver := range pipeline.Receivers {
			kind := "receiver"
			resourceType := model.ResourceTypeReceiver
			if connectorNames[receiver] && !receiverNames[receiver] {
				kind = "connector"
				resourceType = model.ResourceTypeTelemetryConnector
			}
			component := addComponent(kind, resourceType, receiver)
			if resourceType == model.ResourceTypeTelemetryConnector {
				component.Metadata[model.MetadataOTelConnectorReceiverUsage] = strconv.Itoa(connectorReceiverUsage[receiver])
				component.Metadata[model.MetadataOTelConnectorExporterUsage] = strconv.Itoa(connectorExporterUsage[receiver])
				resourcesByID[component.ID] = component
			}
			relationship := otelcolRelationship(pipelineResource.ID, component.ID, model.RelationshipUses, now)
			relationshipsByID[relationship.ID] = relationship
		}
		for _, processor := range pipeline.Processors {
			component := addComponent("processor", model.ResourceTypeProcessor, processor)
			relationship := otelcolRelationship(pipelineResource.ID, component.ID, model.RelationshipUses, now)
			relationshipsByID[relationship.ID] = relationship
		}
		for _, exporter := range pipeline.Exporters {
			kind := "exporter"
			resourceType := model.ResourceTypeExporter
			if connectorNames[exporter] && !exporterNames[exporter] {
				kind = "connector"
				resourceType = model.ResourceTypeTelemetryConnector
			}
			component := addComponent(kind, resourceType, exporter)
			if resourceType == model.ResourceTypeTelemetryConnector {
				component.Metadata[model.MetadataOTelConnectorReceiverUsage] = strconv.Itoa(connectorReceiverUsage[exporter])
				component.Metadata[model.MetadataOTelConnectorExporterUsage] = strconv.Itoa(connectorExporterUsage[exporter])
				resourcesByID[component.ID] = component
			}
			relationship := otelcolRelationship(pipelineResource.ID, component.ID, model.RelationshipUses, now)
			relationshipsByID[relationship.ID] = relationship
		}
	}
	for name, safety := range topology.ExporterSafety {
		resourceID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeExporter), "exporter:"+name)
		resource, exists := resourcesByID[resourceID]
		if !exists {
			continue
		}
		setOTelColOptionalBoolMetadata(resource.Metadata, model.MetadataOTelExporterSendingQueueEnabled, safety.SendingQueueEnabled)
		setOTelColOptionalBoolMetadata(resource.Metadata, model.MetadataOTelExporterRetryOnFailureEnabled, safety.RetryOnFailureEnabled)
		setOTelColOptionalBoolMetadata(resource.Metadata, model.MetadataOTelExporterTLSInsecure, safety.TLSInsecure)
		setOTelColOptionalBoolMetadata(resource.Metadata, model.MetadataOTelExporterTLSInsecureSkipVerify, safety.TLSInsecureSkipVerify)
		resourcesByID[resourceID] = resource
	}
	for name, safety := range topology.ReceiverSafety {
		resourceID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeReceiver), "receiver:"+name)
		resource, exists := resourcesByID[resourceID]
		if !exists {
			continue
		}
		resource.Metadata[model.MetadataOTelReceiverNetworkSafety] = "true"
		resource.Metadata[model.MetadataOTelReceiverProtocolCount] = strconv.Itoa(safety.ProtocolCount)
		resource.Metadata[model.MetadataOTelReceiverEndpointConfiguredCount] = strconv.Itoa(safety.EndpointConfiguredCount)
		resource.Metadata[model.MetadataOTelReceiverEndpointEvaluableCount] = strconv.Itoa(safety.EndpointEvaluableCount)
		resource.Metadata[model.MetadataOTelReceiverPublicEndpointCount] = strconv.Itoa(safety.PublicEndpointCount)
		resource.Metadata[model.MetadataOTelReceiverPublicUnauthenticatedCnt] = strconv.Itoa(safety.PublicUnauthenticatedCount)
		resource.Metadata[model.MetadataOTelReceiverPublicPlaintextCount] = strconv.Itoa(safety.PublicPlaintextCount)
		resourcesByID[resourceID] = resource
	}
	for name, safety := range topology.ProcessorSafety {
		resourceID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeProcessor), "processor:"+name)
		resource, exists := resourcesByID[resourceID]
		if !exists {
			continue
		}
		resource.Metadata[model.MetadataOTelMemoryLimiterConfig] = "true"
		resource.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] = strconv.FormatBool(safety.LimitConfigured)
		resource.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] = strconv.FormatBool(safety.LimitEvaluable)
		resource.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount] = strconv.Itoa(safety.ConfigurationIssueCount)
		resourcesByID[resourceID] = resource
	}
	for name, safety := range topology.BatchSafety {
		resourceID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeProcessor), "processor:"+name)
		resource, exists := resourcesByID[resourceID]
		if !exists {
			continue
		}
		resource.Metadata[model.MetadataOTelBatchConfig] = "true"
		resource.Metadata[model.MetadataOTelBatchConfigIssueCount] = strconv.Itoa(safety.ConfigurationIssueCount)
		resource.Metadata[model.MetadataOTelBatchPassThroughEvaluable] = strconv.FormatBool(safety.PassThroughEvaluable)
		resource.Metadata[model.MetadataOTelBatchPassThrough] = strconv.FormatBool(safety.PassThrough)
		resourcesByID[resourceID] = resource
	}
	for name, safety := range topology.TailSafety {
		resourceID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeProcessor), "processor:"+name)
		resource, exists := resourcesByID[resourceID]
		if !exists {
			continue
		}
		resource.Metadata[model.MetadataOTelTailSamplingConfig] = "true"
		resource.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] = strconv.FormatBool(safety.PoliciesEvaluable)
		if safety.PoliciesEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingPolicyCount] = strconv.Itoa(safety.PolicyCount)
		}
		resource.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] = strconv.Itoa(safety.ConfigurationIssueCount)
		resource.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] = strconv.FormatBool(safety.FullCaptureEvaluable)
		if safety.FullCaptureEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingFullCapture] = strconv.FormatBool(safety.FullCapture)
		}
		resource.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] = strconv.FormatBool(safety.DropPendingEvaluable)
		if safety.DropPendingEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] = strconv.FormatBool(safety.DropPendingOnShutdown)
		}
		resource.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] = strconv.FormatBool(safety.TraceCapacityEvaluable)
		if safety.TraceCapacityEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] = strconv.FormatBool(safety.ZeroTraceCapacity)
		}
		resource.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] = strconv.FormatBool(safety.DecisionCacheEvaluable)
		if safety.DecisionCacheEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] = strconv.Itoa(safety.UndersizedCacheCount)
		}
		resource.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = strconv.FormatBool(safety.TailStorageConfigured)
		resource.Metadata[model.MetadataOTelTailSamplingTailStorageGateEvaluable] = strconv.FormatBool(safety.TailStorageGateEvaluable)
		if safety.TailStorageGateEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingTailStorageGateEnabled] = strconv.FormatBool(safety.TailStorageGateEnabled)
		}
		resource.Metadata[model.MetadataOTelTailSamplingTailStorageRefEvaluable] = strconv.FormatBool(safety.TailStorageRefEvaluable)
		if safety.TailStorageRefEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingTailStorageExtensionReady] = strconv.FormatBool(safety.TailStorageExtensionReady)
		}
		resource.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] = strconv.FormatBool(safety.MaxTraceSizeConfigured)
		resource.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] = strconv.FormatBool(safety.MaxTraceSizeEvaluable)
		if safety.MaxTraceSizeEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded] = strconv.FormatBool(safety.MaxTraceSizeUnbounded)
		}
		resource.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] = strconv.FormatBool(safety.BlockOverflowConfigured)
		resource.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] = strconv.FormatBool(safety.BlockOverflowEvaluable)
		if safety.BlockOverflowEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled] = strconv.FormatBool(safety.BlockOverflowEnabled)
		}
		resource.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEvaluable] = strconv.FormatBool(safety.RecordPolicyGateEvaluable)
		if safety.RecordPolicyGateEvaluable {
			resource.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEnabled] = strconv.FormatBool(safety.RecordPolicyGateEnabled)
		}
		resource.Metadata[model.MetadataOTelTailSamplingDetailedMetricsEnabledCnt] = strconv.Itoa(safety.DetailedMetricsEnabledCount)
		resourcesByID[resourceID] = resource
	}
	probabilisticUsedByLogs := make(map[string]bool, len(topology.ProbabilisticSafety))
	for _, pipeline := range topology.Pipelines {
		if pipeline.Signal != "logs" {
			continue
		}
		for _, processor := range pipeline.Processors {
			if _, exists := topology.ProbabilisticSafety[processor]; exists {
				probabilisticUsedByLogs[processor] = true
			}
		}
	}
	for name, safety := range topology.ProbabilisticSafety {
		resourceID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeProcessor), "processor:"+name)
		resource, exists := resourcesByID[resourceID]
		if !exists {
			continue
		}
		resource.Metadata[model.MetadataOTelProbabilisticSamplerConfig] = "true"
		resource.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] = strconv.FormatBool(safety.PercentageEvaluable)
		if safety.PercentageEvaluable {
			resource.Metadata[model.MetadataOTelProbabilisticFullCapture] = strconv.FormatBool(safety.FullCapture)
			resource.Metadata[model.MetadataOTelProbabilisticDropAll] = strconv.FormatBool(safety.DropAll)
		}
		resource.Metadata[model.MetadataOTelProbabilisticConfigIssueCount] = strconv.Itoa(safety.ConfigurationIssueCount)
		resource.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] = strconv.Itoa(safety.OptionIssueCount)
		resource.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] = strconv.FormatBool(safety.FailClosedEvaluable)
		if safety.FailClosedEvaluable {
			resource.Metadata[model.MetadataOTelProbabilisticFailClosed] = strconv.FormatBool(safety.FailClosed)
		}
		resource.Metadata[model.MetadataOTelProbabilisticUsedByLogs] = strconv.FormatBool(probabilisticUsedByLogs[name])
		resource.Metadata[model.MetadataOTelProbabilisticAttributeSourceEvaluable] = strconv.FormatBool(safety.AttributeSourceEvaluable)
		if safety.AttributeSourceEvaluable {
			resource.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] = strconv.FormatBool(safety.AttributeSourceRecord)
		}
		resource.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] = strconv.FormatBool(safety.FromAttributeEvaluable)
		if safety.FromAttributeEvaluable {
			resource.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] = strconv.FormatBool(safety.FromAttributeConfigured)
		}
		resource.Metadata[model.MetadataOTelProbabilisticModeEvaluable] = strconv.FormatBool(safety.ModeEvaluable)
		if safety.ModeEvaluable && safety.AttributeSourceEvaluable {
			resource.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible] = strconv.FormatBool(safety.RecordSourceModeCompatible)
		}
		resourcesByID[resourceID] = resource
	}

	collectorResource := otelcolResource(model.ResourceTypeInstance, "OpenTelemetry Collector", instance, "collector", now)
	collectorResource.Metadata[model.MetadataOTelCollectorConfigInstance] = "true"
	collectorResource.Metadata[model.MetadataOTelPipelineCount] = strconv.Itoa(len(topology.Pipelines))
	collectorResource.Metadata[model.MetadataOTelHealthCheckEnabled] = strconv.FormatBool(otelcolHealthCheckEnabled(topology.Extensions))
	resourcesByID[collectorResource.ID] = collectorResource
	for _, extension := range topology.Extensions {
		if !extension.Enabled {
			continue
		}
		extensionID := model.StableID("resource", otelcolSystem, instance, string(model.ResourceTypeExtension), "extension:"+extension.Name)
		relationship := otelcolRelationship(collectorResource.ID, extensionID, model.RelationshipUses, now)
		relationshipsByID[relationship.ID] = relationship
	}

	snapshot := Snapshot{
		Resources:     make([]model.Resource, 0, len(resourcesByID)),
		Relationships: make([]model.Relationship, 0, len(relationshipsByID)),
	}
	for _, resource := range resourcesByID {
		snapshot.Resources = append(snapshot.Resources, resource)
	}
	for _, relationship := range relationshipsByID {
		snapshot.Relationships = append(snapshot.Relationships, relationship)
	}
	sort.Slice(snapshot.Resources, func(i, j int) bool {
		return snapshot.Resources[i].ID < snapshot.Resources[j].ID
	})
	sort.Slice(snapshot.Relationships, func(i, j int) bool {
		return snapshot.Relationships[i].ID < snapshot.Relationships[j].ID
	})
	return snapshot, nil
}

func parseOTelColConfigTopology(content string, tailStorageGateState, recordPolicyGateState otelcolFeatureGateState, detailedMetricsEnabledCount int) (otelcolConfigTopology, error) {
	var document otelcolConfigDocument
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		return otelcolConfigTopology{}, fmt.Errorf("parse otelcol config: %w", err)
	}

	topology := otelcolConfigTopology{
		Receivers:           sortedOTelColMapKeys(document.Receivers),
		ReceiverSafety:      make(map[string]otelcolReceiverSafety),
		Processors:          sortedOTelColMapKeys(document.Processors),
		ProcessorSafety:     make(map[string]otelcolProcessorSafety),
		BatchSafety:         make(map[string]otelcolBatchSafety),
		TailSafety:          make(map[string]otelcolTailSamplingSafety),
		ProbabilisticSafety: make(map[string]otelcolProbabilisticSamplingSafety),
		Exporters:           sortedOTelColMapKeys(document.Exporters),
		ExporterSafety:      make(map[string]otelcolExporterSafety, len(document.Exporters)),
		Connectors:          sortedOTelColMapKeys(document.Connectors),
	}
	for name, configNode := range document.Receivers {
		name = strings.TrimSpace(name)
		if name == "" || componentType(name) != "otlp" {
			continue
		}
		topology.ReceiverSafety[name] = otelcolOTLPReceiverSafety(configNode)
	}
	for name, configNode := range document.Exporters {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		topology.ExporterSafety[name] = otelcolExporterSafety{
			SendingQueueEnabled:   yamlBoolPath(configNode, "sending_queue", "enabled"),
			RetryOnFailureEnabled: yamlBoolPath(configNode, "retry_on_failure", "enabled"),
			TLSInsecure:           yamlBoolPath(configNode, "tls", "insecure"),
			TLSInsecureSkipVerify: yamlBoolPath(configNode, "tls", "insecure_skip_verify"),
		}
	}
	for name, configNode := range document.Processors {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		switch componentType(name) {
		case "memory_limiter":
			topology.ProcessorSafety[name] = otelcolMemoryLimiterSafety(configNode)
		case "batch":
			topology.BatchSafety[name] = otelcolBatchSafetySummary(configNode)
		case "tail_sampling":
			topology.TailSafety[name] = otelcolTailSamplingSafetySummary(configNode, tailStorageGateState, recordPolicyGateState, detailedMetricsEnabledCount)
		case "probabilistic_sampler":
			topology.ProbabilisticSafety[name] = otelcolProbabilisticSamplingSafetySummary(configNode)
		}
	}
	for name, pipelineConfig := range document.Service.Pipelines {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		topology.Pipelines = append(topology.Pipelines, otelcolPipeline{
			Name:       name,
			Signal:     pipelineSignal(name),
			Receivers:  appendUniqueStrings(nil, pipelineConfig.Receivers...),
			Processors: appendUniqueStrings(nil, pipelineConfig.Processors...),
			Exporters:  appendUniqueStrings(nil, pipelineConfig.Exporters...),
		})
	}

	extensions := make(map[string]otelcolExtension, len(document.Extensions)+len(document.Service.Extensions))
	for name, configNode := range document.Extensions {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		endpoint, endpointConfigured := yamlScalarField(configNode, "endpoint")
		evaluable, public := otelcolEndpointExposure(endpoint, endpointConfigured)
		extensions[name] = otelcolExtension{
			Name:                      name,
			Declared:                  true,
			EndpointConfigured:        endpointConfigured,
			EndpointExposureEvaluable: evaluable,
			EndpointPublic:            public,
		}
	}
	for _, name := range document.Service.Extensions {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		extension := extensions[name]
		extension.Name = name
		extension.Enabled = true
		extensions[name] = extension
	}
	for name, safety := range topology.TailSafety {
		if !safety.TailStorageRefEvaluable {
			continue
		}
		extension, exists := extensions[safety.TailStorageReference]
		safety.TailStorageExtensionReady = exists && extension.Declared && extension.Enabled
		topology.TailSafety[name] = safety
	}
	for _, extension := range extensions {
		topology.Extensions = append(topology.Extensions, extension)
	}

	sort.Slice(topology.Pipelines, func(i, j int) bool {
		return topology.Pipelines[i].Name < topology.Pipelines[j].Name
	})
	sort.Slice(topology.Extensions, func(i, j int) bool {
		return topology.Extensions[i].Name < topology.Extensions[j].Name
	})
	return topology, nil
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func sortedOTelColMapKeys(values map[string]yaml.Node) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		name = strings.TrimSpace(name)
		if name != "" {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func yamlScalarField(node yaml.Node, field string) (string, bool) {
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = *node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return "", false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if key.Value != field || value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
			continue
		}
		return strings.TrimSpace(value.Value), true
	}
	return "", false
}

func yamlBoolPath(node yaml.Node, path ...string) otelcolOptionalBool {
	for _, field := range path {
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			node = *node.Content[0]
		}
		if node.Kind != yaml.MappingNode {
			return otelcolOptionalBool{}
		}
		found := false
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Value != field {
				continue
			}
			node = *node.Content[index+1]
			found = true
			break
		}
		if !found {
			return otelcolOptionalBool{}
		}
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return otelcolOptionalBool{}
	}
	value, err := strconv.ParseBool(strings.TrimSpace(node.Value))
	if err != nil {
		return otelcolOptionalBool{}
	}
	return otelcolOptionalBool{Value: value, Evaluable: true}
}

func yamlIntField(node yaml.Node, field string) otelcolOptionalInt {
	child, configured := yamlMappingChild(node, field)
	if !configured || child.Kind != yaml.ScalarNode || child.Tag == "!!null" {
		return otelcolOptionalInt{}
	}
	result := otelcolOptionalInt{Configured: true}
	if child.Tag != "!!int" {
		return result
	}
	var value int64
	if err := child.Decode(&value); err != nil {
		return result
	}
	result.Value = value
	result.Evaluable = true
	return result
}

func yamlDurationField(node yaml.Node, field string) otelcolOptionalDuration {
	child, configured := yamlMappingChild(node, field)
	if !configured || child.Kind != yaml.ScalarNode || child.Tag == "!!null" {
		return otelcolOptionalDuration{}
	}
	result := otelcolOptionalDuration{Configured: true}
	value := strings.TrimSpace(child.Value)
	if strings.Contains(value, "${") {
		return result
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		result.Invalid = true
		return result
	}
	result.Value = duration
	result.Evaluable = true
	return result
}

func otelcolBatchSafetySummary(node yaml.Node) otelcolBatchSafety {
	sendBatchSize := yamlIntField(node, "send_batch_size")
	if !sendBatchSize.Configured {
		sendBatchSize = otelcolOptionalInt{Value: 8192, Evaluable: true}
	}
	sendBatchMaxSize := yamlIntField(node, "send_batch_max_size")
	if !sendBatchMaxSize.Configured {
		sendBatchMaxSize = otelcolOptionalInt{Evaluable: true}
	}
	timeout := yamlDurationField(node, "timeout")
	if !timeout.Configured {
		timeout = otelcolOptionalDuration{Value: 200 * time.Millisecond, Evaluable: true}
	}

	safety := otelcolBatchSafety{
		PassThroughEvaluable: timeout.Evaluable && sendBatchMaxSize.Evaluable,
	}
	if sendBatchSize.Evaluable && sendBatchSize.Value < 0 {
		safety.ConfigurationIssueCount++
	}
	if sendBatchMaxSize.Evaluable {
		if sendBatchMaxSize.Value < 0 {
			safety.ConfigurationIssueCount++
		} else if sendBatchMaxSize.Value > 0 &&
			sendBatchSize.Evaluable &&
			sendBatchMaxSize.Value < sendBatchSize.Value {
			safety.ConfigurationIssueCount++
		}
	}
	if timeout.Invalid || (timeout.Evaluable && timeout.Value < 0) {
		safety.ConfigurationIssueCount++
	}
	if safety.PassThroughEvaluable {
		safety.PassThrough = timeout.Value == 0 && sendBatchMaxSize.Value == 0
	}
	return safety
}

func otelcolTailSamplingSafetySummary(node yaml.Node, tailStorageGateState, recordPolicyGateState otelcolFeatureGateState, detailedMetricsEnabledCount int) otelcolTailSamplingSafety {
	safety := otelcolTailSamplingSafety{
		PoliciesEvaluable:           true,
		FullCaptureEvaluable:        true,
		DropPendingEvaluable:        true,
		TraceCapacityEvaluable:      true,
		DecisionCacheEvaluable:      true,
		TailStorageGateEvaluable:    tailStorageGateState.Evaluable,
		TailStorageGateEnabled:      tailStorageGateState.Enabled,
		RecordPolicyGateEvaluable:   recordPolicyGateState.Evaluable,
		RecordPolicyGateEnabled:     recordPolicyGateState.Enabled,
		DetailedMetricsEnabledCount: detailedMetricsEnabledCount,
	}
	if tailStorage, configured := yamlMappingChild(node, "tail_storage"); configured && tailStorage.Tag != "!!null" {
		safety.TailStorageConfigured = true
		if tailStorage.Kind != yaml.ScalarNode {
			safety.ConfigurationIssueCount++
		} else {
			reference := strings.TrimSpace(tailStorage.Value)
			switch {
			case reference == "":
				safety.ConfigurationIssueCount++
			case strings.Contains(reference, "${"):
				// Runtime substitutions cannot be resolved from the static topology.
			default:
				safety.TailStorageReference = reference
				safety.TailStorageRefEvaluable = true
			}
		}
	}
	if policies, configured := yamlMappingChild(node, "policies"); configured && policies.Tag != "!!null" {
		switch policies.Kind {
		case yaml.SequenceNode:
			safety.PolicyCount = len(policies.Content)
			hasAlwaysSample := false
			hasDrop := false
			policyNames := make(map[string]struct{}, len(policies.Content))
			for _, policy := range policies.Content {
				if policy.Kind != yaml.MappingNode {
					safety.ConfigurationIssueCount++
					safety.FullCaptureEvaluable = false
					continue
				}
				policyName, configured := yamlMappingChild(*policy, "name")
				switch {
				case !configured || policyName.Tag == "!!null" || policyName.Kind != yaml.ScalarNode:
					safety.ConfigurationIssueCount++
				case strings.Contains(policyName.Value, "${"):
				case policyName.Value == "":
					safety.ConfigurationIssueCount++
				default:
					if _, exists := policyNames[policyName.Value]; exists {
						safety.ConfigurationIssueCount++
					} else {
						policyNames[policyName.Value] = struct{}{}
					}
				}
				policyType, configured := yamlMappingChild(*policy, "type")
				if !configured || policyType.Tag == "!!null" || policyType.Kind != yaml.ScalarNode {
					safety.FullCaptureEvaluable = false
					continue
				}
				value := strings.TrimSpace(policyType.Value)
				if strings.Contains(value, "${") {
					safety.FullCaptureEvaluable = false
					continue
				}
				switch value {
				case "always_sample":
					hasAlwaysSample = true
				case "drop":
					hasDrop = true
				}
			}
			if safety.FullCaptureEvaluable {
				safety.FullCapture = hasAlwaysSample && !hasDrop
			}
		case yaml.ScalarNode:
			safety.FullCaptureEvaluable = false
			if strings.Contains(strings.TrimSpace(policies.Value), "${") {
				safety.PoliciesEvaluable = false
			} else {
				safety.PoliciesEvaluable = false
				safety.ConfigurationIssueCount++
			}
		default:
			safety.PoliciesEvaluable = false
			safety.FullCaptureEvaluable = false
			safety.ConfigurationIssueCount++
		}
	}

	if strategy, configured := yamlMappingChild(node, "sampling_strategy"); configured && strategy.Tag != "!!null" {
		if strategy.Kind != yaml.ScalarNode {
			safety.ConfigurationIssueCount++
		} else {
			value := strings.TrimSpace(strategy.Value)
			if !strings.Contains(value, "${") && value != "trace-complete" && value != "span-ingest" {
				safety.ConfigurationIssueCount++
			}
		}
	}
	safety.ConfigurationIssueCount += otelcolTailSamplingSpanIngestStatefulIssueCount(node)
	if configured := yamlMappingChildBool(node, "drop_pending_traces_on_shutdown", &safety.DropPendingOnShutdown); configured < 0 {
		safety.DropPendingEvaluable = false
	} else if configured == 0 {
		safety.DropPendingEvaluable = false
		safety.ConfigurationIssueCount++
	}
	numTraces := yamlUint64Field(node, "num_traces")
	if !numTraces.Configured {
		numTraces = otelcolOptionalUint64{Value: 50000, Evaluable: true}
	}
	safety.TraceCapacityEvaluable = numTraces.Evaluable
	if numTraces.Evaluable {
		safety.ZeroTraceCapacity = numTraces.Value == 0
	}
	if numTraces.Invalid {
		safety.ConfigurationIssueCount++
	}
	if decisionCache, configured := yamlMappingChild(node, "decision_cache"); configured && decisionCache.Tag != "!!null" {
		if decisionCache.Kind != yaml.MappingNode {
			if decisionCache.Kind == yaml.ScalarNode && strings.Contains(strings.TrimSpace(decisionCache.Value), "${") {
				safety.DecisionCacheEvaluable = false
			} else {
				safety.DecisionCacheEvaluable = false
				safety.ConfigurationIssueCount++
			}
		} else {
			for _, field := range []string{"sampled_cache_size", "non_sampled_cache_size"} {
				cacheSize := yamlNonNegativeIntField(decisionCache, field)
				if cacheSize.Invalid {
					safety.ConfigurationIssueCount++
				}
				if cacheSize.Configured && !cacheSize.Evaluable {
					safety.DecisionCacheEvaluable = false
					continue
				}
				if cacheSize.Evaluable && cacheSize.Value > 0 {
					if !numTraces.Evaluable {
						safety.DecisionCacheEvaluable = false
					} else if cacheSize.Value <= numTraces.Value {
						safety.UndersizedCacheCount++
					}
				}
			}
		}
	}
	if !safety.DecisionCacheEvaluable {
		safety.UndersizedCacheCount = 0
	}
	maxTraceSize := yamlUint64Field(node, "maximum_trace_size_bytes")
	safety.MaxTraceSizeConfigured = maxTraceSize.Configured
	safety.MaxTraceSizeEvaluable = maxTraceSize.Configured && maxTraceSize.Evaluable
	if safety.MaxTraceSizeEvaluable {
		safety.MaxTraceSizeUnbounded = maxTraceSize.Value == 0
	}
	switch yamlMappingChildBool(node, "block_on_overflow", &safety.BlockOverflowEnabled) {
	case 1:
		safety.BlockOverflowConfigured = true
		safety.BlockOverflowEvaluable = true
	case -1, 0:
		safety.BlockOverflowConfigured = true
	}
	safety.ConfigurationIssueCount += otelcolTailSamplingCoreOptionIssueCount(node)
	return safety
}

func parseOTelColFeatureGateState(spec, target string, defaultEnabled bool) (otelcolFeatureGateState, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return otelcolFeatureGateState{}, nil
	}
	state := otelcolFeatureGateState{Evaluable: true, Enabled: defaultEnabled}
	if spec == "defaults" {
		return state, nil
	}
	spec = strings.TrimPrefix(spec, "--feature-gates=")
	if strings.TrimSpace(spec) == "" {
		return otelcolFeatureGateState{}, fmt.Errorf("otelcol feature gates must be %q or a comma-separated +gate,-gate list", "defaults")
	}
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if len(item) < 2 || (item[0] != '+' && item[0] != '-') {
			return otelcolFeatureGateState{}, fmt.Errorf("invalid otelcol feature gate override %q", item)
		}
		name := strings.TrimSpace(item[1:])
		if name == "" || strings.ContainsAny(name, " \t\r\n") {
			return otelcolFeatureGateState{}, fmt.Errorf("invalid otelcol feature gate override %q", item)
		}
		if name == target {
			state.Enabled = item[0] == '+'
		}
	}
	return state, nil
}

func otelcolTailSamplingCoreOptionIssueCount(node yaml.Node) int {
	issues := 0
	for _, field := range []string{"decision_wait", "decision_wait_after_root_received"} {
		value := yamlDurationField(node, field)
		if value.Invalid || (value.Evaluable && value.Value < 0) {
			issues++
		}
	}
	for _, field := range []string{"block_on_overflow", "sample_on_first_match"} {
		var value bool
		if yamlMappingChildBool(node, field, &value) == 0 {
			issues++
		}
	}
	for _, field := range []string{"expected_new_traces_per_sec", "maximum_trace_size_bytes"} {
		if yamlUint64Field(node, field).Invalid {
			issues++
		}
	}
	return issues
}

func yamlUint64Field(node yaml.Node, field string) otelcolOptionalUint64 {
	child, configured := yamlMappingChild(node, field)
	if !configured {
		return otelcolOptionalUint64{}
	}
	result := otelcolOptionalUint64{Configured: true}
	if child.Tag == "!!null" {
		result.Invalid = true
		return result
	}
	if child.Kind == yaml.ScalarNode && strings.Contains(strings.TrimSpace(child.Value), "${") {
		return result
	}
	if child.Kind != yaml.ScalarNode || child.Tag != "!!int" {
		result.Invalid = true
		return result
	}
	if err := child.Decode(&result.Value); err != nil {
		result.Invalid = true
		return result
	}
	result.Evaluable = true
	return result
}

func yamlNonNegativeIntField(node yaml.Node, field string) otelcolOptionalUint64 {
	result := yamlUint64Field(node, field)
	if result.Evaluable && result.Value > uint64(^uint(0)>>1) {
		result.Evaluable = false
		result.Invalid = true
	}
	return result
}

// yamlMappingChildBool returns 1 for a static bool, -1 for a dynamic value,
// 2 when omitted (the caller keeps the Collector default), and 0 when invalid.
func yamlMappingChildBool(node yaml.Node, field string, target *bool) int {
	child, configured := yamlMappingChild(node, field)
	if !configured {
		return 2
	}
	if child.Kind == yaml.ScalarNode && strings.Contains(strings.TrimSpace(child.Value), "${") {
		return -1
	}
	if child.Kind != yaml.ScalarNode || child.Tag != "!!bool" {
		return 0
	}
	value, err := strconv.ParseBool(strings.TrimSpace(child.Value))
	if err != nil {
		return 0
	}
	*target = value
	return 1
}

func otelcolTailSamplingSpanIngestStatefulIssueCount(node yaml.Node) int {
	strategy, configured := yamlMappingChild(node, "sampling_strategy")
	if !configured || strategy.Tag == "!!null" || strategy.Kind != yaml.ScalarNode ||
		strings.Contains(strings.TrimSpace(strategy.Value), "${") ||
		strings.TrimSpace(strategy.Value) != "span-ingest" {
		return 0
	}
	policies, configured := yamlMappingChild(node, "policies")
	if !configured || policies.Kind != yaml.SequenceNode {
		return 0
	}
	issues := 0
	for _, policy := range policies.Content {
		if policy.Kind != yaml.MappingNode {
			continue
		}
		if evaluable, stateful := otelcolTailSamplingPolicyStateful(*policy); evaluable && stateful {
			issues++
		}
	}
	return issues
}

func otelcolTailSamplingPolicyStateful(policy yaml.Node) (bool, bool) {
	policyType, configured := yamlMappingChild(policy, "type")
	if !configured || policyType.Tag == "!!null" || policyType.Kind != yaml.ScalarNode {
		return false, false
	}
	value := strings.TrimSpace(policyType.Value)
	if strings.Contains(value, "${") {
		return false, false
	}
	switch value {
	case "rate_limiting", "bytes_limiting":
		return true, true
	case "latency":
		return otelcolTailSamplingPositiveNestedInt(policy, "latency", "upper_threshold_ms")
	case "span_count":
		return otelcolTailSamplingPositiveNestedInt(policy, "span_count", "max_spans")
	case "and":
		return otelcolTailSamplingNestedPoliciesStateful(policy, "and", "and_sub_policy")
	case "drop":
		return otelcolTailSamplingNestedPoliciesStateful(policy, "drop", "drop_sub_policy")
	case "composite":
		return otelcolTailSamplingNestedPoliciesStateful(policy, "composite", "composite_sub_policy")
	case "not":
		config, configured := yamlMappingChild(policy, "not")
		if !configured || config.Tag == "!!null" || config.Kind != yaml.MappingNode {
			return false, false
		}
		subPolicy, configured := yamlMappingChild(config, "not_sub_policy")
		if !configured || subPolicy.Tag == "!!null" || subPolicy.Kind != yaml.MappingNode {
			return false, false
		}
		return otelcolTailSamplingPolicyStateful(subPolicy)
	case "always_sample", "numeric_attribute", "probabilistic", "status_code",
		"string_attribute", "trace_state", "boolean_attribute", "ottl_condition", "trace_flags":
		return true, false
	default:
		return false, false
	}
}

func otelcolTailSamplingPositiveNestedInt(policy yaml.Node, configName, fieldName string) (bool, bool) {
	config, configured := yamlMappingChild(policy, configName)
	if !configured || config.Tag == "!!null" {
		return true, false
	}
	if config.Kind != yaml.MappingNode {
		return false, false
	}
	field, configured := yamlMappingChild(config, fieldName)
	if !configured || field.Tag == "!!null" {
		return true, false
	}
	if field.Kind != yaml.ScalarNode || strings.Contains(strings.TrimSpace(field.Value), "${") {
		return false, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(field.Value), 0, 64)
	if err != nil {
		return false, false
	}
	return true, value > 0
}

func otelcolTailSamplingNestedPoliciesStateful(policy yaml.Node, configName, listName string) (bool, bool) {
	config, configured := yamlMappingChild(policy, configName)
	if !configured || config.Tag == "!!null" || config.Kind != yaml.MappingNode {
		return false, false
	}
	subPolicies, configured := yamlMappingChild(config, listName)
	if !configured || subPolicies.Tag == "!!null" || subPolicies.Kind != yaml.SequenceNode {
		return false, false
	}
	allEvaluable := true
	for _, subPolicy := range subPolicies.Content {
		if subPolicy.Kind != yaml.MappingNode {
			allEvaluable = false
			continue
		}
		evaluable, stateful := otelcolTailSamplingPolicyStateful(*subPolicy)
		if evaluable && stateful {
			return true, true
		}
		if !evaluable {
			allEvaluable = false
		}
	}
	return allEvaluable, false
}

func otelcolProbabilisticSamplingSafetySummary(node yaml.Node) otelcolProbabilisticSamplingSafety {
	safety := otelcolProbabilisticSamplingOptionSafetySummary(node)
	percentage, configured := yamlMappingChild(node, "sampling_percentage")
	if !configured || percentage.Tag == "!!null" {
		safety.PercentageEvaluable = true
		safety.DropAll = true
		return safety
	}
	if percentage.Kind != yaml.ScalarNode {
		safety.ConfigurationIssueCount++
		return safety
	}
	value := strings.TrimSpace(percentage.Value)
	if strings.Contains(value, "${") {
		return safety
	}
	switch strings.ToLower(value) {
	case ".nan", ".inf", "+.inf", "-.inf":
		safety.ConfigurationIssueCount++
		return safety
	}
	number, err := strconv.ParseFloat(value, 32)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 ||
		(number > 0 && number < otelcolMinimumProbabilisticSamplingPercentage) {
		safety.ConfigurationIssueCount++
		return safety
	}
	safety.PercentageEvaluable = true
	safety.FullCapture = number >= 100
	safety.DropAll = number == 0
	return safety
}

func otelcolProbabilisticSamplingOptionSafetySummary(node yaml.Node) otelcolProbabilisticSamplingSafety {
	safety := otelcolProbabilisticSamplingSafety{
		FailClosedEvaluable:        true,
		FailClosed:                 true,
		AttributeSourceEvaluable:   true,
		FromAttributeEvaluable:     true,
		ModeEvaluable:              true,
		RecordSourceModeCompatible: true,
	}

	mode := ""
	if modeNode, configured := yamlMappingChild(node, "mode"); configured && modeNode.Tag != "!!null" {
		switch {
		case modeNode.Kind != yaml.ScalarNode:
			safety.OptionIssueCount++
			safety.ModeEvaluable = false
		case strings.Contains(strings.TrimSpace(modeNode.Value), "${"):
			safety.ModeEvaluable = false
		default:
			mode = strings.TrimSpace(modeNode.Value)
			switch mode {
			case "", "hash_seed", "equalizing", "proportional":
			default:
				safety.OptionIssueCount++
				safety.ModeEvaluable = false
			}
		}
	}
	if source, configured := yamlMappingChild(node, "attribute_source"); configured && source.Tag != "!!null" {
		switch {
		case source.Kind != yaml.ScalarNode:
			safety.OptionIssueCount++
			safety.AttributeSourceEvaluable = false
		case strings.Contains(strings.TrimSpace(source.Value), "${"):
			safety.AttributeSourceEvaluable = false
		default:
			switch strings.TrimSpace(source.Value) {
			case "", "traceID":
			case "record":
				safety.AttributeSourceRecord = true
			default:
				safety.OptionIssueCount++
				safety.AttributeSourceEvaluable = false
			}
		}
	}
	if safety.ModeEvaluable && safety.AttributeSourceEvaluable && safety.AttributeSourceRecord {
		safety.RecordSourceModeCompatible = mode == "" || mode == "hash_seed"
	}

	if fromAttribute, configured := yamlMappingChild(node, "from_attribute"); configured && fromAttribute.Tag != "!!null" {
		switch {
		case fromAttribute.Kind != yaml.ScalarNode:
			safety.OptionIssueCount++
			safety.FromAttributeEvaluable = false
		case strings.Contains(strings.TrimSpace(fromAttribute.Value), "${"):
			safety.FromAttributeEvaluable = false
		default:
			safety.FromAttributeConfigured = strings.TrimSpace(fromAttribute.Value) != ""
		}
	}

	if precision, configured := yamlMappingChild(node, "sampling_precision"); configured && precision.Tag != "!!null" {
		if precision.Kind != yaml.ScalarNode {
			safety.OptionIssueCount++
		} else {
			value := strings.TrimSpace(precision.Value)
			if !strings.Contains(value, "${") {
				number, err := strconv.Atoi(value)
				if err != nil || number < 1 || number > 14 {
					safety.OptionIssueCount++
				}
			}
		}
	}

	if hashSeed, configured := yamlMappingChild(node, "hash_seed"); configured && hashSeed.Tag != "!!null" {
		if hashSeed.Kind != yaml.ScalarNode {
			safety.OptionIssueCount++
		} else {
			value := strings.TrimSpace(hashSeed.Value)
			if !strings.Contains(value, "${") {
				if _, err := strconv.ParseUint(value, 0, 32); err != nil {
					safety.OptionIssueCount++
				}
			}
		}
	}

	if failClosed, configured := yamlMappingChild(node, "fail_closed"); configured && failClosed.Tag != "!!null" {
		switch {
		case failClosed.Kind != yaml.ScalarNode:
			safety.OptionIssueCount++
			safety.FailClosedEvaluable = false
		case strings.Contains(strings.TrimSpace(failClosed.Value), "${"):
			safety.FailClosedEvaluable = false
		case failClosed.Tag != "!!bool":
			safety.OptionIssueCount++
			safety.FailClosedEvaluable = false
		default:
			value, err := strconv.ParseBool(strings.TrimSpace(failClosed.Value))
			if err != nil {
				safety.OptionIssueCount++
				safety.FailClosedEvaluable = false
			} else {
				safety.FailClosed = value
			}
		}
	}
	return safety
}

func otelcolStaticEnumIssueCount(node yaml.Node, field string, allowed map[string]struct{}) int {
	valueNode, configured := yamlMappingChild(node, field)
	if !configured || valueNode.Tag == "!!null" {
		return 0
	}
	if valueNode.Kind != yaml.ScalarNode {
		return 1
	}
	value := strings.TrimSpace(valueNode.Value)
	if strings.Contains(value, "${") {
		return 0
	}
	if _, ok := allowed[value]; !ok {
		return 1
	}
	return 0
}

func otelcolMemoryLimiterSafety(node yaml.Node) otelcolProcessorSafety {
	limitMiB := yamlIntField(node, "limit_mib")
	limitPercentage := yamlIntField(node, "limit_percentage")
	spikeMiB := yamlIntField(node, "spike_limit_mib")
	spikePercentage := yamlIntField(node, "spike_limit_percentage")

	safety := otelcolProcessorSafety{
		LimitConfigured: limitMiB.Configured || limitPercentage.Configured,
	}
	switch {
	case limitMiB.Configured:
		safety.LimitEvaluable = limitMiB.Evaluable
		if !limitMiB.Evaluable {
			return safety
		}
		if limitMiB.Value <= 0 {
			safety.ConfigurationIssueCount++
		}
		if spikeMiB.Configured && spikeMiB.Evaluable &&
			(spikeMiB.Value < 0 || spikeMiB.Value >= limitMiB.Value) {
			safety.ConfigurationIssueCount++
		}
	case limitPercentage.Configured:
		safety.LimitEvaluable = limitPercentage.Evaluable
		if !limitPercentage.Evaluable {
			return safety
		}
		if limitPercentage.Value <= 0 || limitPercentage.Value > 100 {
			safety.ConfigurationIssueCount++
		}
		if spikePercentage.Configured && spikePercentage.Evaluable &&
			(spikePercentage.Value < 0 || spikePercentage.Value >= limitPercentage.Value) {
			safety.ConfigurationIssueCount++
		}
	default:
		safety.LimitEvaluable = true
	}
	return safety
}

func otelcolOTLPReceiverSafety(node yaml.Node) otelcolReceiverSafety {
	protocols, exists := yamlMappingChild(node, "protocols")
	if !exists || protocols.Kind != yaml.MappingNode {
		return otelcolReceiverSafety{}
	}
	safety := otelcolReceiverSafety{}
	for index := 0; index+1 < len(protocols.Content); index += 2 {
		protocolName := strings.ToLower(strings.TrimSpace(protocols.Content[index].Value))
		if protocolName != "grpc" && protocolName != "http" {
			continue
		}
		safety.ProtocolCount++
		protocol := *protocols.Content[index+1]
		endpoint, configured := yamlScalarField(protocol, "endpoint")
		if !configured {
			continue
		}
		safety.EndpointConfiguredCount++
		evaluable, public := otelcolEndpointExposure(endpoint, true)
		if !evaluable {
			continue
		}
		safety.EndpointEvaluableCount++
		if !public {
			continue
		}
		safety.PublicEndpointCount++
		authenticator, authConfigured := yamlScalarPath(protocol, "auth", "authenticator")
		if !authConfigured || strings.TrimSpace(authenticator) == "" {
			safety.PublicUnauthenticatedCount++
		}
		certFile, certConfigured := yamlScalarPath(protocol, "tls", "cert_file")
		keyFile, keyConfigured := yamlScalarPath(protocol, "tls", "key_file")
		if !certConfigured || !keyConfigured || strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
			safety.PublicPlaintextCount++
		}
	}
	return safety
}

func yamlMappingChild(node yaml.Node, field string) (yaml.Node, bool) {
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = *node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return yaml.Node{}, false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == field {
			return *node.Content[index+1], true
		}
	}
	return yaml.Node{}, false
}

func yamlScalarPath(node yaml.Node, path ...string) (string, bool) {
	for index, field := range path {
		child, exists := yamlMappingChild(node, field)
		if !exists {
			return "", false
		}
		if index == len(path)-1 {
			if child.Kind != yaml.ScalarNode || child.Tag == "!!null" {
				return "", false
			}
			return strings.TrimSpace(child.Value), true
		}
		node = child
	}
	return "", false
}

func setOTelColOptionalBoolMetadata(metadata map[string]string, key string, value otelcolOptionalBool) {
	if value.Evaluable {
		metadata[key] = strconv.FormatBool(value.Value)
	}
}

func otelcolEndpointExposure(endpoint string, configured bool) (bool, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if !configured || endpoint == "" || strings.Contains(endpoint, "${") {
		return false, false
	}
	hostPort := endpoint
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Scheme != "" {
		hostPort = parsed.Host
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false, false
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "0.0.0.0" {
		return true, true
	}
	if address := net.ParseIP(host); address != nil {
		return true, address.IsUnspecified()
	}
	return true, false
}

func otelcolHealthCheckEnabled(extensions []otelcolExtension) bool {
	for _, extension := range extensions {
		if !extension.Enabled {
			continue
		}
		switch componentType(extension.Name) {
		case "health_check", "healthcheckv2":
			return true
		}
	}
	return false
}

func appendUniqueStrings(items []string, values ...string) []string {
	seen := make(map[string]bool, len(items)+len(values))
	for _, item := range items {
		seen[item] = true
	}
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		items = append(items, value)
	}
	return items
}

func pipelineSignal(name string) string {
	signal := name
	if index := strings.Index(signal, "/"); index >= 0 {
		signal = signal[:index]
	}
	return strings.TrimSpace(signal)
}

func componentType(name string) string {
	name = strings.TrimSpace(name)
	if index := strings.Index(name, "/"); index >= 0 {
		return name[:index]
	}
	return name
}

func otelcolResource(resourceType model.ResourceType, name string, instance string, externalID string, now time.Time) model.Resource {
	return model.Resource{
		ID:   model.StableID("resource", otelcolSystem, instance, string(resourceType), externalID),
		Type: resourceType,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     otelcolSystem,
			Instance:   instance,
			ExternalID: externalID,
		},
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func otelcolRelationship(fromID string, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID("relationship", otelcolSystem, fromID, toID, string(relationshipType)),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}
