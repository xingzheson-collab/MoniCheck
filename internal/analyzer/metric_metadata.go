package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MetricMetadataAnalyzerID = "builtin.metric_metadata"

type MetricMetadataAnalyzer struct{}

func NewMetricMetadataAnalyzer() *MetricMetadataAnalyzer {
	return &MetricMetadataAnalyzer{}
}

func (a *MetricMetadataAnalyzer) ID() string {
	return MetricMetadataAnalyzerID
}

func (a *MetricMetadataAnalyzer) Name() string {
	return "Metric Metadata"
}

func (a *MetricMetadataAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MetricMetadataAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *MetricMetadataAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		for _, issue := range metricMetadataIssues(metric) {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), issue.findingType, metric.ID),
				Type:     issue.findingType,
				Severity: issue.severity,
				Resource: model.ResourceRef{
					ID:   metric.ID,
					Type: metric.Type,
					Name: metric.Name,
				},
				Evidence:       []string{issue.evidence},
				Recommendation: issue.recommendation,
				Metadata: map[string]string{
					"analyzer_id": a.ID(),
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

type metricMetadataIssue struct {
	findingType    string
	severity       model.Severity
	evidence       string
	recommendation string
}

func metricMetadataIssues(metric model.Resource) []metricMetadataIssue {
	issues := make([]metricMetadataIssue, 0, 3)
	if strings.TrimSpace(metric.Metadata[model.MetadataMetricType]) == "" {
		issues = append(issues, metricMetadataIssue{
			findingType:    "MissingMetricType",
			severity:       model.SeverityWarning,
			evidence:       fmt.Sprintf("metric %q has no metadata type", metric.Name),
			recommendation: "为指标补充 Prometheus TYPE 元数据，便于区分 counter、gauge、histogram 等语义。",
		})
	}
	if strings.TrimSpace(metric.Metadata[model.MetadataMetricHelp]) == "" {
		issues = append(issues, metricMetadataIssue{
			findingType:    "MissingMetricHelp",
			severity:       model.SeverityWarning,
			evidence:       fmt.Sprintf("metric %q has no metadata help", metric.Name),
			recommendation: "为指标补充 Prometheus HELP 元数据，说明指标含义、单位和使用场景。",
		})
	}
	if strings.TrimSpace(metric.Metadata[model.MetadataMetricUnit]) == "" {
		issues = append(issues, metricMetadataIssue{
			findingType:    "MissingMetricUnit",
			severity:       model.SeverityInfo,
			evidence:       fmt.Sprintf("metric %q has no metadata unit", metric.Name),
			recommendation: "Declare the metric unit in metadata or its name when one exists, for example seconds, bytes, or total, so queries and dashboards cannot misinterpret the value.",
		})
	}
	return issues
}
