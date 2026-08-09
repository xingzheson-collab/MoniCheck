package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PrometheusShortStorageRetentionAnalyzerID = "builtin.prometheus_short_storage_retention"

const defaultPrometheusMinimumStorageRetention = 7 * 24 * time.Hour

type PrometheusShortStorageRetentionAnalyzer struct{}

func NewPrometheusShortStorageRetentionAnalyzer() *PrometheusShortStorageRetentionAnalyzer {
	return &PrometheusShortStorageRetentionAnalyzer{}
}

func (a *PrometheusShortStorageRetentionAnalyzer) ID() string {
	return PrometheusShortStorageRetentionAnalyzerID
}

func (a *PrometheusShortStorageRetentionAnalyzer) Name() string {
	return "Prometheus Short Storage Retention"
}

func (a *PrometheusShortStorageRetentionAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PrometheusShortStorageRetentionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusShortStorageRetentionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}

	minimum := durationConfig(analysis.Config, "prometheus_minimum_storage_retention", defaultPrometheusMinimumStorageRetention)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_prometheus_short_retentions", nil))
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusRuntimeAvailable] != "true" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[model.MetadataPrometheusRetentionSeconds]), 10, 64)
		if err != nil || seconds <= 0 {
			continue
		}
		if seconds >= int64(minimum/time.Second) || prometheusRetentionAllowed(resource, allowed) {
			continue
		}
		retention := time.Duration(seconds) * time.Second
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "PrometheusShortStorageRetention",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{
				fmt.Sprintf("Prometheus storage retention is %s, below the configured minimum %s", retention, minimum),
			},
			Recommendation: "延长 Prometheus 本地保留期，或确认长期存储和查询链路已覆盖容量、故障恢复与历史排障需求；调整后重新同步验证。",
			Metadata: map[string]string{
				"analyzer_id":       a.ID(),
				"retention":         retention.String(),
				"minimum_retention": minimum.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func prometheusRetentionAllowed(resource model.Resource, allowed map[string]bool) bool {
	if allowedResource(resource, allowed) {
		return true
	}
	instance := strings.ToLower(strings.TrimSpace(resource.Source.Instance))
	return instance != "" && allowed[instance]
}
