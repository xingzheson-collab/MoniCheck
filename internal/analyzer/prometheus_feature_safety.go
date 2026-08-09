package analyzer

import (
	"context"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusCreatedTimestampZeroAnalyzerID  = "builtin.prometheus_created_timestamp_zero_ingestion"
	PrometheusOTLPDeltaToCumulativeAnalyzerID = "builtin.prometheus_otlp_delta_to_cumulative"
	PrometheusExperimentalXOR2AnalyzerID      = "builtin.prometheus_experimental_xor2_encoding"
)

type PrometheusFeatureSafetyAnalyzer struct {
	id   string
	name string
}

func NewPrometheusCreatedTimestampZeroAnalyzer() *PrometheusFeatureSafetyAnalyzer {
	return &PrometheusFeatureSafetyAnalyzer{id: PrometheusCreatedTimestampZeroAnalyzerID, name: "Prometheus Created Timestamp Zero Ingestion"}
}

func NewPrometheusOTLPDeltaToCumulativeAnalyzer() *PrometheusFeatureSafetyAnalyzer {
	return &PrometheusFeatureSafetyAnalyzer{id: PrometheusOTLPDeltaToCumulativeAnalyzerID, name: "Prometheus OTLP Delta To Cumulative"}
}

func NewPrometheusExperimentalXOR2Analyzer() *PrometheusFeatureSafetyAnalyzer {
	return &PrometheusFeatureSafetyAnalyzer{id: PrometheusExperimentalXOR2AnalyzerID, name: "Prometheus Experimental XOR2 Encoding"}
}

func (a *PrometheusFeatureSafetyAnalyzer) ID() string      { return a.id }
func (a *PrometheusFeatureSafetyAnalyzer) Name() string    { return a.name }
func (a *PrometheusFeatureSafetyAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusFeatureSafetyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusFeatureSafetyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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

func (a *PrometheusFeatureSafetyAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusCreatedTimestampZeroAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusCreatedTimestampZero] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusCreatedTimestampZeroIngestion"
		category = model.FindingCategoryCost
		evidence = "Prometheus created-timestamp-zero-ingestion is explicitly enabled and may inject additional zero-valued samples"
		recommendation = "量化 start timestamp 零样本带来的 series、WAL、remote_write 与 TSDB 增量；没有明确 rate/increase 语义需求时关闭该 feature，并在迁移新 ST 存储机制前完成兼容性与成本验证。"
		metadata[model.MetadataPrometheusCreatedTimestampZero] = "true"
	case PrometheusOTLPDeltaToCumulativeAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusOTLPReceiver] != "true" ||
			resource.Metadata[model.MetadataPrometheusOTLPDeltaToCumulative] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusOTLPDeltaToCumulative"
		evidence = "Prometheus OTLP delta-to-cumulative conversion is enabled with the OTLP receiver; conversion keeps mutex-guarded per-series state that resets on restart"
		recommendation = "优先在 OpenTelemetry Collector 中完成 temporality 转换和容量控制；如必须在 Prometheus 内转换，压测内存与锁竞争，并让查询和告警容忍重启后 cumulative series 的 counter reset。"
		metadata[model.MetadataPrometheusOTLPReceiver] = "true"
		metadata[model.MetadataPrometheusOTLPDeltaToCumulative] = "true"
	case PrometheusExperimentalXOR2AnalyzerID:
		if resource.Metadata[model.MetadataPrometheusAgentMode] == "true" ||
			resource.Metadata[model.MetadataPrometheusXOR2EncodingEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusExperimentalXOR2Encoding"
		severity = model.SeverityCritical
		category = model.FindingCategoryLifecycle
		evidence = "Prometheus XOR2 encoding is explicitly enabled; the format is highly experimental, may change between versions, and is not readable by older Prometheus versions"
		recommendation = "生产 TSDB 关闭 xor2-encoding；仅在隔离测试环境验证压缩收益、升级/回滚、备份恢复和 Thanos 等下游兼容性，确认可接受清理不兼容 blocks 的数据风险后再评估启用。"
		metadata[model.MetadataPrometheusXOR2EncodingEnabled] = "true"
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
