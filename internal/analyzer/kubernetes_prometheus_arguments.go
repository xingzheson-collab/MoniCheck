package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesPrometheusFeaturesEnabledAnalyzerID       = "builtin.kubernetes_prometheus_features_enabled"
	KubernetesInvalidPrometheusFeatureSetAnalyzerID     = "builtin.kubernetes_invalid_prometheus_feature_set"
	KubernetesPrometheusAdditionalArgsAnalyzerID        = "builtin.kubernetes_prometheus_additional_arguments"
	KubernetesInvalidPrometheusAdditionalArgsAnalyzerID = "builtin.kubernetes_invalid_prometheus_additional_arguments"
)

type KubernetesPrometheusArgumentsAnalyzer struct {
	id   string
	name string
}

func newKubernetesPrometheusArgumentsAnalyzer(id, name string) *KubernetesPrometheusArgumentsAnalyzer {
	return &KubernetesPrometheusArgumentsAnalyzer{id: id, name: name}
}

func NewKubernetesPrometheusFeaturesEnabledAnalyzer() *KubernetesPrometheusArgumentsAnalyzer {
	return newKubernetesPrometheusArgumentsAnalyzer(KubernetesPrometheusFeaturesEnabledAnalyzerID, "Kubernetes Prometheus Features Enabled")
}
func NewKubernetesInvalidPrometheusFeatureSetAnalyzer() *KubernetesPrometheusArgumentsAnalyzer {
	return newKubernetesPrometheusArgumentsAnalyzer(KubernetesInvalidPrometheusFeatureSetAnalyzerID, "Kubernetes Invalid Prometheus Feature Set")
}
func NewKubernetesPrometheusAdditionalArgsAnalyzer() *KubernetesPrometheusArgumentsAnalyzer {
	return newKubernetesPrometheusArgumentsAnalyzer(KubernetesPrometheusAdditionalArgsAnalyzerID, "Kubernetes Prometheus Additional Arguments")
}
func NewKubernetesInvalidPrometheusAdditionalArgsAnalyzer() *KubernetesPrometheusArgumentsAnalyzer {
	return newKubernetesPrometheusArgumentsAnalyzer(KubernetesInvalidPrometheusAdditionalArgsAnalyzerID, "Kubernetes Invalid Prometheus Additional Arguments")
}
func (a *KubernetesPrometheusArgumentsAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusArgumentsAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusArgumentsAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusArgumentsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusArgumentsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_argument_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusArgumentsFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusArgumentsFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityWarning
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesPrometheusFeaturesEnabledAnalyzerID:
		count := prometheusStorageMetadataInt64(resource, "prometheus_feature_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusFeaturesEnabled"
		evidence = fmt.Sprintf("Kubernetes %s %q enables %d optional feature flag(s) outside the stable default surface", kind, resource.Name, count)
		recommendation = "确认每个 feature flag 的必要性、版本兼容性、升级测试和回退方案；不再需要的实验能力应移除。"
		metadata["prometheus_feature_count"] = fmt.Sprintf("%d", count)
	case KubernetesInvalidPrometheusFeatureSetAnalyzerID:
		invalid := prometheusStorageMetadataInt64(resource, "prometheus_feature_invalid_count")
		duplicates := prometheusStorageMetadataInt64(resource, "prometheus_feature_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidPrometheusFeatureSet"
		evidence = fmt.Sprintf("Kubernetes %s %q has %d invalid and %d duplicate feature entries", kind, resource.Name, invalid, duplicates)
		recommendation = "将 enableFeatures 配置为唯一、非空字符串数组，并确认 Operator 已成功调谐。"
	case KubernetesPrometheusAdditionalArgsAnalyzerID:
		count := prometheusStorageMetadataInt64(resource, "prometheus_additional_arg_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusAdditionalArguments"
		evidence = fmt.Sprintf("Kubernetes %s %q injects %d additional command-line argument(s) outside dedicated Operator fields", kind, resource.Name, count)
		recommendation = "优先迁移到 Operator 专用字段；保留 additionalArgs 时记录用途、版本约束、冲突检查和回退步骤。"
		metadata["prometheus_additional_arg_count"] = fmt.Sprintf("%d", count)
	case KubernetesInvalidPrometheusAdditionalArgsAnalyzerID:
		invalid := prometheusStorageMetadataInt64(resource, "prometheus_additional_arg_invalid_count")
		duplicates := prometheusStorageMetadataInt64(resource, "prometheus_additional_arg_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidPrometheusAdditionalArguments"
		evidence = fmt.Sprintf("Kubernetes %s %q has %d invalid and %d duplicate additional argument entries", kind, resource.Name, invalid, duplicates)
		recommendation = "将 additionalArgs 配置为具有唯一非空 name 的对象数组，删除重复参数，并确认名称不与 Operator 管理参数冲突。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
