package analyzer

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusUnboundedRemoteReadConcurrencyAnalyzerID = "builtin.prometheus_unbounded_remote_read_concurrency"
	PrometheusUnboundedRemoteReadSamplesAnalyzerID     = "builtin.prometheus_unbounded_remote_read_samples"
	PrometheusUnboundedSearchAPIAnalyzerID             = "builtin.prometheus_unbounded_search_api"
)

type PrometheusReadRuntimeAnalyzer struct {
	id   string
	name string
}

func NewPrometheusUnboundedRemoteReadConcurrencyAnalyzer() *PrometheusReadRuntimeAnalyzer {
	return &PrometheusReadRuntimeAnalyzer{id: PrometheusUnboundedRemoteReadConcurrencyAnalyzerID, name: "Prometheus Unbounded Remote Read Concurrency"}
}

func NewPrometheusUnboundedRemoteReadSamplesAnalyzer() *PrometheusReadRuntimeAnalyzer {
	return &PrometheusReadRuntimeAnalyzer{id: PrometheusUnboundedRemoteReadSamplesAnalyzerID, name: "Prometheus Unbounded Remote Read Samples"}
}

func NewPrometheusUnboundedSearchAPIAnalyzer() *PrometheusReadRuntimeAnalyzer {
	return &PrometheusReadRuntimeAnalyzer{id: PrometheusUnboundedSearchAPIAnalyzerID, name: "Prometheus Unbounded Search API"}
}

func (a *PrometheusReadRuntimeAnalyzer) ID() string      { return a.id }
func (a *PrometheusReadRuntimeAnalyzer) Name() string    { return a.name }
func (a *PrometheusReadRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusReadRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusReadRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAgentMode] == "true" {
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

func (a *PrometheusReadRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusUnboundedRemoteReadConcurrencyAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusRemoteReadConcurrentLimit)
		if !ok || value != 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusUnboundedRemoteReadConcurrency"
		evidence = "Prometheus remote read concurrency limit is 0, which allows unlimited concurrent remote read calls"
		recommendation = "将 --storage.remote.read-concurrent-limit 设置为经过容量验证的正整数，并结合 CPU、内存、查询队列和 remote read 客户端并发观察资源压力。"
		metadata[model.MetadataPrometheusRemoteReadConcurrentLimit] = "0"
	case PrometheusUnboundedRemoteReadSamplesAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusRemoteReadSampleLimit)
		if !ok || value != 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusUnboundedRemoteReadSamples"
		evidence = "Prometheus remote read sample limit is 0, which removes the per-query sample cap for non-streamed remote read responses"
		recommendation = "将 --storage.remote.read-sample-limit 设置为经过查询负载验证的正数；同时限制客户端时间范围，并单独评估 streamed remote read 的 frame 与资源边界。"
		metadata[model.MetadataPrometheusRemoteReadSampleLimit] = "0"
	case PrometheusUnboundedSearchAPIAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusSearchAPIEnabled] != "true" {
			return model.Finding{}, false
		}
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusSearchMaxLimit)
		if !ok || value != 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusUnboundedSearchAPI"
		evidence = "Prometheus experimental search API is enabled with max limit 0, allowing requests to enumerate the entire index"
		recommendation = "为 --web.search.max-limit 配置经过容量验证的正上限，并通过认证、网络隔离和请求限流保护实验性 Search API。"
		metadata[model.MetadataPrometheusSearchMaxLimit] = "0"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategoryCost,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func prometheusNonNegativeMetadataInt64(resource model.Resource, key string) (int64, bool) {
	raw, exists := resource.Metadata[key]
	if !exists {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}
