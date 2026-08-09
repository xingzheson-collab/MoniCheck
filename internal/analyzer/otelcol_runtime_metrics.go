package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelTailSamplingRuntimeDropsAnalyzerID = "builtin.otelcol_tail_sampling_runtime_drops"
	OTelTailSamplingPolicyErrorsAnalyzerID = "builtin.otelcol_tail_sampling_policy_evaluation_errors"
)

type OTelTailSamplingRuntimeAnalyzer struct {
	id   string
	name string
}

func NewOTelTailSamplingRuntimeDropsAnalyzer() *OTelTailSamplingRuntimeAnalyzer {
	return &OTelTailSamplingRuntimeAnalyzer{
		id:   OTelTailSamplingRuntimeDropsAnalyzerID,
		name: "OpenTelemetry Collector Tail Sampling Runtime Drops",
	}
}

func NewOTelTailSamplingPolicyErrorsAnalyzer() *OTelTailSamplingRuntimeAnalyzer {
	return &OTelTailSamplingRuntimeAnalyzer{
		id:   OTelTailSamplingPolicyErrorsAnalyzerID,
		name: "OpenTelemetry Collector Tail Sampling Policy Evaluation Errors",
	}
}

func (a *OTelTailSamplingRuntimeAnalyzer) ID() string      { return a.id }
func (a *OTelTailSamplingRuntimeAnalyzer) Name() string    { return a.name }
func (a *OTelTailSamplingRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *OTelTailSamplingRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelTailSamplingRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "otelcol" ||
			resource.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "true" {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *OTelTailSamplingRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case OTelTailSamplingRuntimeDropsAnalyzerID:
		tooEarly := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelTailSamplingDroppedTooEarly])
		tooLarge := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelTailSamplingDroppedTooLarge])
		counterEvidence := otelColRuntimeCounterEvidence(resource.Metadata, model.MetadataOTelTailSamplingDropDelta)
		if !counterEvidence.shouldReport(tooEarly + tooLarge) {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingRuntimeDrops"
		if counterEvidence.DeltaAvailable {
			evidence = fmt.Sprintf(
				"OpenTelemetry Collector tail-sampling drop counters increased by %s during the latest %s-second successful-scrape interval; cumulative totals are %s trace(s) dropped before the configured wait time and %s oversized trace(s)",
				formatOTelColRuntimeEvidenceValue(counterEvidence.Delta),
				formatOTelColRuntimeEvidenceValue(counterEvidence.IntervalSeconds),
				formatOTelColRuntimeEvidenceValue(tooEarly),
				formatOTelColRuntimeEvidenceValue(tooLarge),
			)
		} else {
			evidence = fmt.Sprintf("OpenTelemetry Collector tail sampling has observed %s trace(s) dropped before the configured wait time and %s oversized trace(s) dropped since runtime counters were reset", formatOTelColRuntimeEvidenceValue(tooEarly), formatOTelColRuntimeEvidenceValue(tooLarge))
		}
		recommendation = "检查 sampling_trace_dropped_too_early 和 traces_dropped_too_large 的增长速率；按峰值新 trace 速率、decision_wait 与最大正常 trace 大小调整 num_traces、block_on_overflow 和 maximum_trace_size_bytes，并验证 Collector 内存与接收背压。"
		metadata["dropped_too_early"] = formatOTelColRuntimeEvidenceValue(tooEarly)
		metadata["dropped_too_large"] = formatOTelColRuntimeEvidenceValue(tooLarge)
		addOTelColRuntimeCounterEvidence(metadata, counterEvidence)
	case OTelTailSamplingPolicyErrorsAnalyzerID:
		errors := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelTailSamplingPolicyEvalErrors])
		counterEvidence := otelColRuntimeCounterEvidence(resource.Metadata, model.MetadataOTelTailSamplingPolicyEvalErrorDelta)
		if !counterEvidence.shouldReport(errors) {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingPolicyEvaluationErrors"
		if counterEvidence.DeltaAvailable {
			evidence = fmt.Sprintf(
				"OpenTelemetry Collector tail-sampling policy evaluation errors increased by %s during the latest %s-second successful-scrape interval; the cumulative total is %s",
				formatOTelColRuntimeEvidenceValue(counterEvidence.Delta),
				formatOTelColRuntimeEvidenceValue(counterEvidence.IntervalSeconds),
				formatOTelColRuntimeEvidenceValue(errors),
			)
		} else {
			evidence = fmt.Sprintf("OpenTelemetry Collector tail sampling has observed %s policy evaluation error(s) since runtime counters were reset", formatOTelColRuntimeEvidenceValue(errors))
		}
		recommendation = "检查 Collector 日志和 sampling_policy_evaluation_error 的增长来源，修复对应 policy 的类型、属性、正则或 OTTL 表达式；变更后确认错误计数不再增长并验证关键 trace 的保留结果。"
		metadata["policy_evaluation_errors"] = formatOTelColRuntimeEvidenceValue(errors)
		addOTelColRuntimeCounterEvidence(metadata, counterEvidence)
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityCritical,
		Category:       model.FindingCategoryReliability,
		Status:         model.FindingStatusOpen,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func positiveOTelColRuntimeMetric(value string) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func formatOTelColRuntimeEvidenceValue(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

type otelColCounterEvidence struct {
	DeltaAvailable  bool
	Delta           float64
	IntervalSeconds float64
}

func otelColRuntimeCounterEvidence(metadata map[string]string, deltaKey string) otelColCounterEvidence {
	if metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] != "true" {
		return otelColCounterEvidence{}
	}
	return otelColCounterEvidence{
		DeltaAvailable: true,
		Delta:          positiveOTelColRuntimeMetric(metadata[deltaKey]),
		IntervalSeconds: positiveOTelColRuntimeMetric(
			metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds],
		),
	}
}

func (evidence otelColCounterEvidence) shouldReport(cumulativeTotal float64) bool {
	if evidence.DeltaAvailable {
		return evidence.Delta > 0
	}
	return cumulativeTotal > 0
}

func addOTelColRuntimeCounterEvidence(metadata map[string]string, evidence otelColCounterEvidence) {
	if !evidence.DeltaAvailable {
		metadata["counter_evidence"] = "cumulative"
		return
	}
	metadata["counter_evidence"] = "delta"
	metadata["counter_delta"] = formatOTelColRuntimeEvidenceValue(evidence.Delta)
	metadata["counter_interval_seconds"] = formatOTelColRuntimeEvidenceValue(evidence.IntervalSeconds)
}
