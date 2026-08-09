package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const RiskyMetricLabelAnalyzerID = "builtin.risky_metric_label"

var defaultRiskyMetricLabelNames = []string{
	"user_id",
	"userid",
	"uid",
	"request_id",
	"requestid",
	"req_id",
	"trace_id",
	"traceid",
	"span_id",
	"spanid",
	"session_id",
	"sessionid",
	"pod_uid",
	"container_id",
	"client_ip",
	"remote_addr",
	"path",
	"url",
}

type RiskyMetricLabelAnalyzer struct{}

func NewRiskyMetricLabelAnalyzer() *RiskyMetricLabelAnalyzer {
	return &RiskyMetricLabelAnalyzer{}
}

func (a *RiskyMetricLabelAnalyzer) ID() string {
	return RiskyMetricLabelAnalyzerID
}

func (a *RiskyMetricLabelAnalyzer) Name() string {
	return "Risky Metric Label"
}

func (a *RiskyMetricLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *RiskyMetricLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *RiskyMetricLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}

	riskyNames := riskyMetricLabelNameSet(analysis.Config)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		riskyLabels := metricRiskyLabels(metric, riskyNames)
		if len(riskyLabels) == 0 {
			continue
		}
		joinedLabels := strings.Join(riskyLabels, ",")
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), metric.ID, joinedLabels),
			Type:     "RiskyMetricLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: metric.ID, Type: metric.Type, Name: metric.Name},
			Evidence: []string{
				fmt.Sprintf("metric %q exposes labels commonly associated with high cardinality: %s", metric.Name, strings.Join(riskyLabels, ", ")),
			},
			Recommendation: "避免将 user/request/trace/session/path 等无界或高变化维度作为 Prometheus labels；优先写入日志或 trace，并将指标标签限制为稳定、可枚举的业务维度。",
			Metadata: map[string]string{
				"analyzer_id":  a.ID(),
				"risky_labels": joinedLabels,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func riskyMetricLabelNameSet(config map[string]any) map[string]bool {
	values := stringSliceConfig(config, "risky_metric_label_names", defaultRiskyMetricLabelNames)
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if normalized := normalizeMetricLabelName(value); normalized != "" {
			result[normalized] = true
		}
	}
	return result
}

func metricRiskyLabels(metric model.Resource, riskyNames map[string]bool) []string {
	labels := make(map[string]string)
	for _, label := range strings.Split(metric.Metadata[model.MetadataMetricLabelKeys], ",") {
		label = strings.TrimSpace(label)
		if label != "" {
			labels[normalizeMetricLabelName(label)] = label
		}
	}
	for label := range metric.Labels {
		label = strings.TrimSpace(label)
		if label != "" {
			labels[normalizeMetricLabelName(label)] = label
		}
	}

	result := make([]string, 0)
	for normalized, label := range labels {
		if riskyNames[normalized] {
			result = append(result, label)
		}
	}
	sort.Strings(result)
	return result
}

func normalizeMetricLabelName(value string) string {
	return strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(strings.ToLower(strings.TrimSpace(value)))
}
