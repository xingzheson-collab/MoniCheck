package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusHighQueryConcurrencyAnalyzerID = "builtin.prometheus_high_query_concurrency"
	PrometheusHighQuerySampleLimitAnalyzerID = "builtin.prometheus_high_query_sample_limit"
	PrometheusLongQueryTimeoutAnalyzerID     = "builtin.prometheus_long_query_timeout"
	PrometheusLongQueryLookbackAnalyzerID    = "builtin.prometheus_long_query_lookback"
	PrometheusRuleQuerySaturationAnalyzerID  = "builtin.prometheus_rule_query_saturation_risk"
)

type PrometheusQueryRuntimeAnalyzer struct {
	id   string
	name string
}

func NewPrometheusHighQueryConcurrencyAnalyzer() *PrometheusQueryRuntimeAnalyzer {
	return &PrometheusQueryRuntimeAnalyzer{id: PrometheusHighQueryConcurrencyAnalyzerID, name: "Prometheus High Query Concurrency"}
}

func NewPrometheusHighQuerySampleLimitAnalyzer() *PrometheusQueryRuntimeAnalyzer {
	return &PrometheusQueryRuntimeAnalyzer{id: PrometheusHighQuerySampleLimitAnalyzerID, name: "Prometheus High Query Sample Limit"}
}

func NewPrometheusLongQueryTimeoutAnalyzer() *PrometheusQueryRuntimeAnalyzer {
	return &PrometheusQueryRuntimeAnalyzer{id: PrometheusLongQueryTimeoutAnalyzerID, name: "Prometheus Long Query Timeout"}
}

func NewPrometheusLongQueryLookbackAnalyzer() *PrometheusQueryRuntimeAnalyzer {
	return &PrometheusQueryRuntimeAnalyzer{id: PrometheusLongQueryLookbackAnalyzerID, name: "Prometheus Long Query Lookback"}
}

func NewPrometheusRuleQuerySaturationAnalyzer() *PrometheusQueryRuntimeAnalyzer {
	return &PrometheusQueryRuntimeAnalyzer{id: PrometheusRuleQuerySaturationAnalyzerID, name: "Prometheus Rule Query Saturation Risk"}
}

func (a *PrometheusQueryRuntimeAnalyzer) ID() string      { return a.id }
func (a *PrometheusQueryRuntimeAnalyzer) Name() string    { return a.name }
func (a *PrometheusQueryRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusQueryRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusQueryRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if finding, ok := a.finding(resource, analysis.Config, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusQueryRuntimeAnalyzer) finding(resource model.Resource, config map[string]any, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategoryCost
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusHighQueryConcurrencyAnalyzerID:
		value, ok := prometheusRuntimeMetadataInt64(resource, model.MetadataPrometheusQueryMaxConcurrency)
		threshold := int64(intConfig(config, "kubernetes_query_max_concurrency_threshold", defaultKubernetesQueryMaxConcurrency))
		if !ok || value <= threshold {
			return model.Finding{}, false
		}
		findingType = "PrometheusHighQueryConcurrency"
		evidence = fmt.Sprintf("Prometheus allows %d concurrent queries, above threshold %d", value, threshold)
		recommendation = "将 --query.max-concurrency 调回经压测验证的范围，并结合 CPU、内存、查询队列与 rule evaluation 并发评估实际容量。"
		metadata[model.MetadataPrometheusQueryMaxConcurrency] = strconv.FormatInt(value, 10)
		metadata["threshold"] = strconv.FormatInt(threshold, 10)
	case PrometheusHighQuerySampleLimitAnalyzerID:
		value, ok := prometheusRuntimeMetadataInt64(resource, model.MetadataPrometheusQueryMaxSamples)
		threshold := int64(intConfig(config, "kubernetes_query_max_samples_threshold", defaultKubernetesQueryMaxSamples))
		if !ok || value <= threshold {
			return model.Finding{}, false
		}
		findingType = "PrometheusHighQuerySampleLimit"
		evidence = fmt.Sprintf("Prometheus allows a query to load %d samples, above threshold %d", value, threshold)
		recommendation = "降低 --query.max-samples，优化高扫描量 PromQL，并使用 recording rule 或专用查询层承载确需大范围扫描的查询。"
		metadata[model.MetadataPrometheusQueryMaxSamples] = strconv.FormatInt(value, 10)
		metadata["threshold"] = strconv.FormatInt(threshold, 10)
	case PrometheusLongQueryTimeoutAnalyzerID:
		seconds, ok := prometheusRuntimeMetadataInt64(resource, model.MetadataPrometheusQueryTimeoutSeconds)
		threshold := durationConfig(config, "kubernetes_query_timeout_threshold", defaultKubernetesQueryTimeout)
		if !ok || time.Duration(seconds)*time.Second <= threshold {
			return model.Finding{}, false
		}
		findingType = "PrometheusLongQueryTimeout"
		evidence = fmt.Sprintf("Prometheus query timeout is %s, above threshold %s", time.Duration(seconds)*time.Second, threshold)
		recommendation = "缩短 --query.timeout，并优化或预计算长期运行的 PromQL，避免昂贵查询长时间占用查询槽位和内存。"
		metadata[model.MetadataPrometheusQueryTimeoutSeconds] = strconv.FormatInt(seconds, 10)
		metadata["threshold_seconds"] = strconv.FormatInt(int64(threshold/time.Second), 10)
	case PrometheusLongQueryLookbackAnalyzerID:
		seconds, ok := prometheusRuntimeMetadataInt64(resource, model.MetadataPrometheusQueryLookbackSeconds)
		threshold := durationConfig(config, "kubernetes_query_lookback_threshold", defaultKubernetesQueryLookback)
		if !ok || time.Duration(seconds)*time.Second <= threshold {
			return model.Finding{}, false
		}
		findingType = "PrometheusLongQueryLookback"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Prometheus query lookback is %s, above threshold %s", time.Duration(seconds)*time.Second, threshold)
		recommendation = "将 --query.lookback-delta 保持在采集间隔和可接受陈旧度所需的最小范围，避免查询长时间复用过旧样本。"
		metadata[model.MetadataPrometheusQueryLookbackSeconds] = strconv.FormatInt(seconds, 10)
		metadata["threshold_seconds"] = strconv.FormatInt(int64(threshold/time.Second), 10)
	case PrometheusRuleQuerySaturationAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusConcurrentRuleEval] != "true" {
			return model.Finding{}, false
		}
		headroom, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom]), 10, 64)
		if err != nil || headroom > 0 {
			return model.Finding{}, false
		}
		ruleConcurrency, ruleOK := prometheusRuntimeMetadataInt64(resource, model.MetadataPrometheusRuleMaxConcurrentEvals)
		queryConcurrency, queryOK := prometheusRuntimeMetadataInt64(resource, model.MetadataPrometheusQueryMaxConcurrency)
		if !ruleOK || !queryOK {
			return model.Finding{}, false
		}
		findingType = "PrometheusRuleQuerySaturationRisk"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Prometheus allows %d concurrent rule evaluations against %d total concurrent queries, leaving no guaranteed query headroom", ruleConcurrency, queryConcurrency)
		recommendation = "降低 --rules.max-concurrent-evals（旧版本为 --rules.max-concurrent-rule-evals），或提高经过容量验证的 --query.max-concurrency，为交互查询和 API 查询保留明确余量；同时观察规则评估延迟、查询队列、CPU 和内存。"
		metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] = strconv.FormatInt(ruleConcurrency, 10)
		metadata[model.MetadataPrometheusQueryMaxConcurrency] = strconv.FormatInt(queryConcurrency, 10)
		metadata["query_headroom"] = strconv.FormatInt(headroom, 10)
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

func prometheusRuntimeMetadataInt64(resource model.Resource, key string) (int64, bool) {
	value, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[key]), 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}
