package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusLongStorageRetentionAnalyzerID               = "builtin.prometheus_long_storage_retention"
	PrometheusExemplarStorageEnabledAnalyzerID             = "builtin.prometheus_exemplar_storage_enabled"
	PrometheusDeprecatedExtraScrapeMetricsAnalyzerID       = "builtin.prometheus_deprecated_extra_scrape_metrics"
	prometheusDefaultStorageRetentionSeconds         int64 = 15 * 24 * 60 * 60
)

type PrometheusStorageCostAnalyzer struct {
	id   string
	name string
}

func NewPrometheusLongStorageRetentionAnalyzer() *PrometheusStorageCostAnalyzer {
	return &PrometheusStorageCostAnalyzer{id: PrometheusLongStorageRetentionAnalyzerID, name: "Prometheus Long Storage Retention"}
}

func NewPrometheusExemplarStorageEnabledAnalyzer() *PrometheusStorageCostAnalyzer {
	return &PrometheusStorageCostAnalyzer{id: PrometheusExemplarStorageEnabledAnalyzerID, name: "Prometheus Exemplar Storage Enabled"}
}

func NewPrometheusDeprecatedExtraScrapeMetricsAnalyzer() *PrometheusStorageCostAnalyzer {
	return &PrometheusStorageCostAnalyzer{id: PrometheusDeprecatedExtraScrapeMetricsAnalyzerID, name: "Prometheus Deprecated Extra Scrape Metrics"}
}

func (a *PrometheusStorageCostAnalyzer) ID() string      { return a.id }
func (a *PrometheusStorageCostAnalyzer) Name() string    { return a.name }
func (a *PrometheusStorageCostAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusStorageCostAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusStorageCostAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" || resource.Status != model.ResourceStatusActive {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusStorageCostAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryCost
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusLongStorageRetentionAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusRuntimeAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAgentMode] == "true" {
			return model.Finding{}, false
		}
		seconds, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusRetentionSeconds)
		if !ok || seconds <= prometheusDefaultStorageRetentionSeconds {
			return model.Finding{}, false
		}
		retention := time.Duration(seconds) * time.Second
		evidence = fmt.Sprintf("Prometheus local storage retention is %s, above the official default of 15 days", retention)
		recommendation = "将本地保留期恢复到官方 15d 默认值或经过查询、故障恢复与磁盘预算验证的窗口；长期历史优先写入可扩展的远端存储，并持续监控磁盘水位和 compaction。"
		findingType = "PrometheusLongStorageRetention"
		metadata[model.MetadataPrometheusRetentionSeconds] = strconv.FormatInt(seconds, 10)
	case PrometheusExemplarStorageEnabledAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAgentMode] == "true" ||
			resource.Metadata[model.MetadataPrometheusExemplarStorageEnabled] != "true" {
			return model.Finding{}, false
		}
		evidence = "Prometheus exemplar storage feature is explicitly enabled; exemplars consume memory and are appended to the WAL"
		recommendation = "仅在 trace correlation 有明确使用方时保留 exemplar-storage，按 exemplar 数量、内存、WAL 与远端写入成本设定容量边界；无消费链路时关闭该实验特性。"
		findingType = "PrometheusExemplarStorageEnabled"
		metadata[model.MetadataPrometheusExemplarStorageEnabled] = "true"
	case PrometheusDeprecatedExtraScrapeMetricsAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusExtraScrapeMetricsEnabled] != "true" {
			return model.Finding{}, false
		}
		evidence = "Prometheus deprecated extra-scrape-metrics feature flag is explicitly enabled"
		recommendation = "从已废弃的 extra-scrape-metrics feature flag 迁移到 extra_scrape_metrics 配置项；仅在这些额外采集指标有明确治理用途时启用，否则关闭以避免额外 series 与存储成本。"
		findingType = "PrometheusDeprecatedExtraScrapeMetrics"
		category = model.FindingCategoryLifecycle
		metadata[model.MetadataPrometheusExtraScrapeMetricsEnabled] = "true"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       category,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
