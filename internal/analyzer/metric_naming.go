package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MetricNamingAnalyzerID = "builtin.metric_naming"

var metricNamePattern = regexp.MustCompile(`^[a-z_:][a-z0-9_:]*$`)

type MetricNamingAnalyzer struct{}

func NewMetricNamingAnalyzer() *MetricNamingAnalyzer {
	return &MetricNamingAnalyzer{}
}

func (a *MetricNamingAnalyzer) ID() string {
	return MetricNamingAnalyzerID
}

func (a *MetricNamingAnalyzer) Name() string {
	return "Metric Naming Convention"
}

func (a *MetricNamingAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MetricNamingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *MetricNamingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if metric.Status != model.ResourceStatusActive {
			continue
		}
		if metricNamePattern.MatchString(metric.Name) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), metric.ID),
			Type:     "MetricNamingViolation",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   metric.ID,
				Type: metric.Type,
				Name: metric.Name,
			},
			Evidence: []string{
				fmt.Sprintf("metric %q does not follow lowercase Prometheus naming convention", metric.Name),
			},
			Recommendation: "将指标命名调整为小写 snake_case，并只使用字母、数字、下划线和必要的冒号。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
