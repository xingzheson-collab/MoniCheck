package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InconsistentMetricMetadataAnalyzerID = "builtin.inconsistent_metric_metadata"

type InconsistentMetricMetadataAnalyzer struct{}

func NewInconsistentMetricMetadataAnalyzer() *InconsistentMetricMetadataAnalyzer {
	return &InconsistentMetricMetadataAnalyzer{}
}

func (a *InconsistentMetricMetadataAnalyzer) ID() string {
	return InconsistentMetricMetadataAnalyzerID
}

func (a *InconsistentMetricMetadataAnalyzer) Name() string {
	return "Inconsistent Metric Metadata"
}

func (a *InconsistentMetricMetadataAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InconsistentMetricMetadataAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *InconsistentMetricMetadataAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		typeVariants := metricMetadataVariantValues(metric.Metadata[model.MetadataMetricTypeVariants])
		helpVariants := metricMetadataVariantValues(metric.Metadata[model.MetadataMetricHelpVariants])
		unitVariants := metricMetadataVariantValues(metric.Metadata[model.MetadataMetricUnitVariants])
		if len(typeVariants) <= 1 && len(helpVariants) <= 1 && len(unitVariants) <= 1 {
			continue
		}

		severity := model.SeverityWarning
		if len(typeVariants) > 1 {
			severity = model.SeverityCritical
		}
		evidence := metricMetadataVariantEvidence(typeVariants, helpVariants, unitVariants)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), metric.ID),
			Type:     "InconsistentMetricMetadata",
			Severity: severity,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{
				ID:   metric.ID,
				Type: metric.Type,
				Name: metric.Name,
			},
			Evidence:       evidence,
			Recommendation: "统一各 exporter/target 对同名指标暴露的 TYPE、HELP 和 UNIT；同名指标元数据冲突会造成查询语义不一致、文档误导，并可能破坏下游类型假设。",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"type_variants": metric.Metadata[model.MetadataMetricTypeVariants],
				"help_variants": metric.Metadata[model.MetadataMetricHelpVariants],
				"unit_variants": metric.Metadata[model.MetadataMetricUnitVariants],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func metricMetadataVariantValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func metricMetadataVariantEvidence(typeVariants []string, helpVariants []string, unitVariants []string) []string {
	evidence := make([]string, 0, 3)
	if len(typeVariants) > 1 {
		evidence = append(evidence, fmt.Sprintf("metric TYPE differs across targets: %q", typeVariants))
	}
	if len(helpVariants) > 1 {
		evidence = append(evidence, fmt.Sprintf("metric HELP differs across targets: %q", helpVariants))
	}
	if len(unitVariants) > 1 {
		evidence = append(evidence, fmt.Sprintf("metric UNIT differs across targets: %q", unitVariants))
	}
	return evidence
}
