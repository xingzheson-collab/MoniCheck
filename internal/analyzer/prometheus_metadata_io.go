package analyzer

import (
	"context"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusMetadataWALRecordsAnalyzerID     = "builtin.prometheus_metadata_wal_records_enabled"
	PrometheusTypeUnitLabelsAnalyzerID         = "builtin.prometheus_type_and_unit_labels_enabled"
	PrometheusExperimentalUncachedIOAnalyzerID = "builtin.prometheus_experimental_uncached_io"
)

type PrometheusMetadataIOAnalyzer struct {
	id   string
	name string
}

func NewPrometheusMetadataWALRecordsAnalyzer() *PrometheusMetadataIOAnalyzer {
	return &PrometheusMetadataIOAnalyzer{id: PrometheusMetadataWALRecordsAnalyzerID, name: "Prometheus Metadata WAL Records Enabled"}
}

func NewPrometheusTypeUnitLabelsAnalyzer() *PrometheusMetadataIOAnalyzer {
	return &PrometheusMetadataIOAnalyzer{id: PrometheusTypeUnitLabelsAnalyzerID, name: "Prometheus Type And Unit Labels Enabled"}
}

func NewPrometheusExperimentalUncachedIOAnalyzer() *PrometheusMetadataIOAnalyzer {
	return &PrometheusMetadataIOAnalyzer{id: PrometheusExperimentalUncachedIOAnalyzerID, name: "Prometheus Experimental Uncached IO"}
}

func (a *PrometheusMetadataIOAnalyzer) ID() string      { return a.id }
func (a *PrometheusMetadataIOAnalyzer) Name() string    { return a.name }
func (a *PrometheusMetadataIOAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusMetadataIOAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusMetadataIOAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" {
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

func (a *PrometheusMetadataIOAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryCost
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusMetadataWALRecordsAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusMetadataWALRecordsEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusMetadataWALRecordsEnabled"
		evidence = "Prometheus metadata WAL records are explicitly enabled and maintain metadata changes in memory and WAL on a per-series basis"
		recommendation = "仅在 remote_write 2.0 元数据确有消费方时启用 metadata-wal-records；量化 head memory、WAL 增量、checkpoint/replay 时间和远端写入收益，无消费链路时关闭。"
		metadata[model.MetadataPrometheusMetadataWALRecordsEnabled] = "true"
	case PrometheusTypeUnitLabelsAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusTypeAndUnitLabelsEnabled"
		evidence = "Prometheus experimental type-and-unit-labels is explicitly enabled and injects reserved type and unit labels into ingested samples"
		recommendation = "先在隔离环境量化新增保留标签对 series schema、索引内存、WAL/remote_write 字节和下游查询的影响；确认规则、Dashboard、federation 与长期存储兼容后再用于生产。"
		metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] = "true"
	case PrometheusExperimentalUncachedIOAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusAgentMode] == "true" ||
			resource.Metadata[model.MetadataPrometheusUncachedIOEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusExperimentalUncachedIO"
		category = model.FindingCategoryReliability
		evidence = "Prometheus experimental uncached I/O is explicitly enabled and writes chunks through Linux direct I/O instead of the page cache"
		recommendation = "生产 TSDB 关闭 use-uncached-io，或先在同类磁盘与真实 ingestion/query 负载下验证 direct I/O 对延迟、吞吐、内存、compaction 和故障恢复的影响，并保留可回滚配置。"
		metadata[model.MetadataPrometheusUncachedIOEnabled] = "true"
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
