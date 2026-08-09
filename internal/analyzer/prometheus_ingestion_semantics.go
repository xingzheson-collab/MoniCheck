package analyzer

import (
	"context"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusExperimentalSTStorageAnalyzerID = "builtin.prometheus_experimental_st_storage"
	PrometheusSTSynthesisAnalyzerID           = "builtin.prometheus_st_synthesis_enabled"
	PrometheusOTLPNativeDeltaAnalyzerID       = "builtin.prometheus_otlp_native_delta_ingestion"
)

type PrometheusIngestionSemanticsAnalyzer struct {
	id   string
	name string
}

func NewPrometheusExperimentalSTStorageAnalyzer() *PrometheusIngestionSemanticsAnalyzer {
	return &PrometheusIngestionSemanticsAnalyzer{id: PrometheusExperimentalSTStorageAnalyzerID, name: "Prometheus Experimental ST Storage"}
}

func NewPrometheusSTSynthesisAnalyzer() *PrometheusIngestionSemanticsAnalyzer {
	return &PrometheusIngestionSemanticsAnalyzer{id: PrometheusSTSynthesisAnalyzerID, name: "Prometheus ST Synthesis Enabled"}
}

func NewPrometheusOTLPNativeDeltaAnalyzer() *PrometheusIngestionSemanticsAnalyzer {
	return &PrometheusIngestionSemanticsAnalyzer{id: PrometheusOTLPNativeDeltaAnalyzerID, name: "Prometheus OTLP Native Delta Ingestion"}
}

func (a *PrometheusIngestionSemanticsAnalyzer) ID() string      { return a.id }
func (a *PrometheusIngestionSemanticsAnalyzer) Name() string    { return a.name }
func (a *PrometheusIngestionSemanticsAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusIngestionSemanticsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusIngestionSemanticsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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

func (a *PrometheusIngestionSemanticsAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusExperimentalSTStorageAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusSTStorageEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusExperimentalSTStorage"
		severity = model.SeverityCritical
		category = model.FindingCategoryLifecycle
		evidence = "Prometheus experimental start-timestamp storage is enabled; its SamplesV2 WAL records require Prometheus 3.11 or later for replay"
		recommendation = "生产环境关闭 st-storage；仅在隔离环境验证 WAL 回放、升级/回滚、备份恢复和 remote_write 兼容性。Server 若需持久化 ST 到 blocks 还必须评估同样高度实验性的 XOR2 及下游兼容风险。"
		metadata[model.MetadataPrometheusSTStorageEnabled] = "true"
		if xor2, ok := resource.Metadata[model.MetadataPrometheusXOR2EncodingEnabled]; ok {
			metadata[model.MetadataPrometheusXOR2EncodingEnabled] = xor2
		}
	case PrometheusSTSynthesisAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusSTSynthesisEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusSTSynthesisEnabled"
		evidence = "Prometheus experimental start-timestamp synthesis is enabled; it drops the first sample, changes raw cumulative values, and rejects unordered samples without start timestamps"
		recommendation = "在隔离数据集验证 counter reset、首样本丢弃、原值变化和乱序写入行为；确认所有规则、Dashboard 与 remote_write 消费方兼容前，不要在生产采集链路启用 st-synthesis。"
		metadata[model.MetadataPrometheusSTSynthesisEnabled] = "true"
	case PrometheusOTLPNativeDeltaAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusOTLPReceiver] != "true" ||
			resource.Metadata[model.MetadataPrometheusOTLPNativeDeltaEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusOTLPNativeDeltaIngestion"
		evidence = "Prometheus early-stage OTLP native delta ingestion is enabled; standard cumulative PromQL functions such as rate and increase produce incorrect results for delta metrics"
		recommendation = "优先在 OpenTelemetry Collector 将 delta 转为 cumulative；若试用 native delta，请隔离标记 delta series，使用经过验证的查询语义，并审计所有规则、Dashboard 与 federation 消费方。"
		metadata[model.MetadataPrometheusOTLPReceiver] = "true"
		metadata[model.MetadataPrometheusOTLPNativeDeltaEnabled] = "true"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       severity,
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
