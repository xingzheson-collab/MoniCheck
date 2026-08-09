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
	KubernetesInvalidPrometheusQueryAnalyzerID   = "builtin.kubernetes_invalid_prometheus_query"
	KubernetesHighQueryConcurrencyAnalyzerID     = "builtin.kubernetes_high_query_concurrency"
	KubernetesHighQuerySampleLimitAnalyzerID     = "builtin.kubernetes_high_query_sample_limit"
	KubernetesLongQueryTimeoutAnalyzerID         = "builtin.kubernetes_long_query_timeout"
	KubernetesLongQueryLookbackAnalyzerID        = "builtin.kubernetes_long_query_lookback"
	KubernetesQueryLookbackBelowScrapeAnalyzerID = "builtin.kubernetes_query_lookback_below_scrape_interval"
)

const (
	defaultKubernetesQueryMaxConcurrency = 20
	defaultKubernetesQueryMaxSamples     = 50_000_000
)

const (
	defaultKubernetesQueryTimeout  = 2 * time.Minute
	defaultKubernetesQueryLookback = 5 * time.Minute
)

type KubernetesInvalidPrometheusQueryAnalyzer struct{}
type KubernetesHighQueryConcurrencyAnalyzer struct{}
type KubernetesHighQuerySampleLimitAnalyzer struct{}
type KubernetesLongQueryTimeoutAnalyzer struct{}
type KubernetesLongQueryLookbackAnalyzer struct{}
type KubernetesQueryLookbackBelowScrapeAnalyzer struct{}

func NewKubernetesInvalidPrometheusQueryAnalyzer() *KubernetesInvalidPrometheusQueryAnalyzer {
	return &KubernetesInvalidPrometheusQueryAnalyzer{}
}
func NewKubernetesHighQueryConcurrencyAnalyzer() *KubernetesHighQueryConcurrencyAnalyzer {
	return &KubernetesHighQueryConcurrencyAnalyzer{}
}
func NewKubernetesHighQuerySampleLimitAnalyzer() *KubernetesHighQuerySampleLimitAnalyzer {
	return &KubernetesHighQuerySampleLimitAnalyzer{}
}
func NewKubernetesLongQueryTimeoutAnalyzer() *KubernetesLongQueryTimeoutAnalyzer {
	return &KubernetesLongQueryTimeoutAnalyzer{}
}
func NewKubernetesLongQueryLookbackAnalyzer() *KubernetesLongQueryLookbackAnalyzer {
	return &KubernetesLongQueryLookbackAnalyzer{}
}
func NewKubernetesQueryLookbackBelowScrapeAnalyzer() *KubernetesQueryLookbackBelowScrapeAnalyzer {
	return &KubernetesQueryLookbackBelowScrapeAnalyzer{}
}

func (a *KubernetesInvalidPrometheusQueryAnalyzer) ID() string {
	return KubernetesInvalidPrometheusQueryAnalyzerID
}
func (a *KubernetesInvalidPrometheusQueryAnalyzer) Name() string {
	return "Kubernetes Invalid Prometheus Query Configuration"
}
func (a *KubernetesInvalidPrometheusQueryAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidPrometheusQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesInvalidPrometheusQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusQueryFindings(ctx, analysis, a.ID())
}

func (a *KubernetesHighQueryConcurrencyAnalyzer) ID() string {
	return KubernetesHighQueryConcurrencyAnalyzerID
}
func (a *KubernetesHighQueryConcurrencyAnalyzer) Name() string {
	return "Kubernetes High Prometheus Query Concurrency"
}
func (a *KubernetesHighQueryConcurrencyAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesHighQueryConcurrencyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesHighQueryConcurrencyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusQueryFindings(ctx, analysis, a.ID())
}

func (a *KubernetesHighQuerySampleLimitAnalyzer) ID() string {
	return KubernetesHighQuerySampleLimitAnalyzerID
}
func (a *KubernetesHighQuerySampleLimitAnalyzer) Name() string {
	return "Kubernetes High Prometheus Query Sample Limit"
}
func (a *KubernetesHighQuerySampleLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesHighQuerySampleLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesHighQuerySampleLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusQueryFindings(ctx, analysis, a.ID())
}

func (a *KubernetesLongQueryTimeoutAnalyzer) ID() string { return KubernetesLongQueryTimeoutAnalyzerID }
func (a *KubernetesLongQueryTimeoutAnalyzer) Name() string {
	return "Kubernetes Long Prometheus Query Timeout"
}
func (a *KubernetesLongQueryTimeoutAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesLongQueryTimeoutAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesLongQueryTimeoutAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusQueryFindings(ctx, analysis, a.ID())
}

func (a *KubernetesLongQueryLookbackAnalyzer) ID() string {
	return KubernetesLongQueryLookbackAnalyzerID
}
func (a *KubernetesLongQueryLookbackAnalyzer) Name() string {
	return "Kubernetes Long Prometheus Query Lookback"
}
func (a *KubernetesLongQueryLookbackAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesLongQueryLookbackAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesLongQueryLookbackAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusQueryFindings(ctx, analysis, a.ID())
}

func (a *KubernetesQueryLookbackBelowScrapeAnalyzer) ID() string {
	return KubernetesQueryLookbackBelowScrapeAnalyzerID
}
func (a *KubernetesQueryLookbackBelowScrapeAnalyzer) Name() string {
	return "Kubernetes Prometheus Query Lookback Below Scrape Interval"
}
func (a *KubernetesQueryLookbackBelowScrapeAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesQueryLookbackBelowScrapeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesQueryLookbackBelowScrapeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusQueryFindings(ctx, analysis, a.ID())
}

func kubernetesPrometheusQueryFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Prometheus" {
			continue
		}
		finding, matched := kubernetesPrometheusQueryFinding(analyzerID, resource, analysis.Config, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusQueryFinding(analyzerID string, resource model.Resource, config map[string]any, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategoryCost
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "namespace": resource.Metadata["namespace"]}
	switch analyzerID {
	case KubernetesInvalidPrometheusQueryAnalyzerID:
		count := prometheusQueryMetadataInt64(resource, "prometheus_query_invalid_setting_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidPrometheusQuery"
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		evidence = fmt.Sprintf("Kubernetes Prometheus %q has %d invalid QuerySpec setting(s)", resource.Name, count)
		recommendation = "使用对象形式的 spec.query，配置正整数 maxConcurrency/maxSamples 和有效的正 duration timeout/lookbackDelta，并通过 Operator CRD 校验。"
		metadata["prometheus_query_invalid_setting_count"] = strconv.FormatInt(count, 10)
	case KubernetesHighQueryConcurrencyAnalyzerID:
		value := prometheusQueryMetadataInt64(resource, "prometheus_query_max_concurrency")
		threshold := int64(intConfig(config, "kubernetes_query_max_concurrency_threshold", defaultKubernetesQueryMaxConcurrency))
		if resource.Metadata["prometheus_query_max_concurrency_declared"] != "true" || resource.Metadata["prometheus_query_max_concurrency_valid"] != "true" || value <= threshold {
			return model.Finding{}, false
		}
		findingType = "KubernetesHighQueryConcurrency"
		evidence = fmt.Sprintf("Kubernetes Prometheus %q allows %d concurrent queries, above threshold %d", resource.Name, value, threshold)
		recommendation = "将 query.maxConcurrency 调回经压测验证的范围，并结合 CPU、内存和查询队列指标评估并发容量。"
		metadata["prometheus_query_max_concurrency"] = strconv.FormatInt(value, 10)
		metadata["threshold"] = strconv.FormatInt(threshold, 10)
	case KubernetesHighQuerySampleLimitAnalyzerID:
		value := prometheusQueryMetadataInt64(resource, "prometheus_query_max_samples")
		threshold := int64(intConfig(config, "kubernetes_query_max_samples_threshold", defaultKubernetesQueryMaxSamples))
		if resource.Metadata["prometheus_query_max_samples_declared"] != "true" || resource.Metadata["prometheus_query_max_samples_valid"] != "true" || value <= threshold {
			return model.Finding{}, false
		}
		findingType = "KubernetesHighQuerySampleLimit"
		evidence = fmt.Sprintf("Kubernetes Prometheus %q allows a query to load %d samples, above threshold %d", resource.Name, value, threshold)
		recommendation = "降低 query.maxSamples，优化高扫描量 PromQL，并为确需大范围分析的查询使用 recording rule 或专用查询层。"
		metadata["prometheus_query_max_samples"] = strconv.FormatInt(value, 10)
		metadata["threshold"] = strconv.FormatInt(threshold, 10)
	case KubernetesLongQueryTimeoutAnalyzerID:
		seconds := prometheusQueryMetadataInt64(resource, "prometheus_query_timeout_seconds")
		threshold := durationConfig(config, "kubernetes_query_timeout_threshold", defaultKubernetesQueryTimeout)
		if resource.Metadata["prometheus_query_timeout_declared"] != "true" || resource.Metadata["prometheus_query_timeout_valid"] != "true" || time.Duration(seconds)*time.Second <= threshold {
			return model.Finding{}, false
		}
		findingType = "KubernetesLongQueryTimeout"
		evidence = fmt.Sprintf("Kubernetes Prometheus %q query timeout is %s, above threshold %s", resource.Name, time.Duration(seconds)*time.Second, threshold)
		recommendation = "缩短 query.timeout，并优化或预计算长期运行的 PromQL，避免昂贵查询长时间占用查询槽位和内存。"
		metadata["prometheus_query_timeout_seconds"] = strconv.FormatInt(seconds, 10)
		metadata["threshold_seconds"] = strconv.FormatInt(int64(threshold/time.Second), 10)
	case KubernetesLongQueryLookbackAnalyzerID:
		seconds := prometheusQueryMetadataInt64(resource, "prometheus_query_lookback_seconds")
		threshold := durationConfig(config, "kubernetes_query_lookback_threshold", defaultKubernetesQueryLookback)
		if resource.Metadata["prometheus_query_lookback_declared"] != "true" || resource.Metadata["prometheus_query_lookback_valid"] != "true" || time.Duration(seconds)*time.Second <= threshold {
			return model.Finding{}, false
		}
		findingType = "KubernetesLongQueryLookback"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes Prometheus %q lookbackDelta is %s, above threshold %s", resource.Name, time.Duration(seconds)*time.Second, threshold)
		recommendation = "将 query.lookbackDelta 保持在采集间隔和可接受陈旧度所需的最小范围，避免查询长时间复用过旧样本。"
		metadata["prometheus_query_lookback_seconds"] = strconv.FormatInt(seconds, 10)
		metadata["threshold_seconds"] = strconv.FormatInt(int64(threshold/time.Second), 10)
	case KubernetesQueryLookbackBelowScrapeAnalyzerID:
		if resource.Metadata["prometheus_query_lookback_below_scrape_interval"] != "true" {
			return model.Finding{}, false
		}
		lookback := prometheusQueryMetadataInt64(resource, "prometheus_query_lookback_seconds")
		scrapeInterval := prometheusQueryMetadataInt64(resource, "prometheus_scrape_interval_seconds")
		findingType = "KubernetesQueryLookbackBelowScrapeInterval"
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes Prometheus %q lookbackDelta is %ds, shorter than its %ds global scrape interval", resource.Name, lookback, scrapeInterval)
		recommendation = "将 query.lookbackDelta 调整为不短于 scrapeInterval，并为采集抖动和偶发失败保留合理余量。"
		metadata["prometheus_query_lookback_seconds"] = strconv.FormatInt(lookback, 10)
		metadata["prometheus_scrape_interval_seconds"] = strconv.FormatInt(scrapeInterval, 10)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func prometheusQueryMetadataInt64(resource model.Resource, key string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[key]), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
