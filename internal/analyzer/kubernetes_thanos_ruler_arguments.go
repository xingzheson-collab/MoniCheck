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
	KubernetesThanosRulerFeaturesEnabledAnalyzerID           = "builtin.kubernetes_thanos_ruler_features_enabled"
	KubernetesInvalidThanosRulerFeatureSetAnalyzerID         = "builtin.kubernetes_invalid_thanos_ruler_feature_set"
	KubernetesUnsupportedThanosRulerFeatureVersionAnalyzerID = "builtin.kubernetes_unsupported_thanos_ruler_feature_version"
	KubernetesThanosRulerAdditionalArgsAnalyzerID            = "builtin.kubernetes_thanos_ruler_additional_arguments"
	KubernetesInvalidThanosRulerAdditionalArgsAnalyzerID     = "builtin.kubernetes_invalid_thanos_ruler_additional_arguments"
)

type KubernetesThanosRulerArgumentsAnalyzer struct {
	id   string
	name string
}

func NewKubernetesThanosRulerAdditionalArgsAnalyzer() *KubernetesThanosRulerArgumentsAnalyzer {
	return &KubernetesThanosRulerArgumentsAnalyzer{id: KubernetesThanosRulerAdditionalArgsAnalyzerID, name: "Kubernetes ThanosRuler Additional Arguments"}
}

func NewKubernetesInvalidThanosRulerAdditionalArgsAnalyzer() *KubernetesThanosRulerArgumentsAnalyzer {
	return &KubernetesThanosRulerArgumentsAnalyzer{id: KubernetesInvalidThanosRulerAdditionalArgsAnalyzerID, name: "Kubernetes Invalid ThanosRuler Additional Arguments"}
}

func (a *KubernetesThanosRulerArgumentsAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerArgumentsAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerArgumentsAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerArgumentsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerArgumentsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_argument_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerArgumentsFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerArgumentsFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesThanosRulerFeaturesEnabledAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_feature_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerFeaturesEnabled"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q enables %d optional feature flag(s) outside the maintainers' support guarantee", resource.Name, count)
		recommendation = "确认每个 Thanos feature flag 的必要性、升级兼容性和回退方案；删除不再需要的实验能力。"
		metadata["thanos_ruler_feature_count"] = fmt.Sprintf("%d", count)
	case KubernetesInvalidThanosRulerFeatureSetAnalyzerID:
		invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_feature_invalid_count")
		duplicates := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_feature_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidThanosRulerFeatureSet"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has %d invalid and %d duplicate feature entries", resource.Name, invalid, duplicates)
		recommendation = "将 enableFeatures 配置为唯一、非空字符串数组，并确认 Operator 已成功调谐。"
		metadata["thanos_ruler_feature_invalid_count"] = fmt.Sprintf("%d", invalid)
		metadata["thanos_ruler_feature_duplicate_count"] = fmt.Sprintf("%d", duplicates)
	case KubernetesUnsupportedThanosRulerFeatureVersionAnalyzerID:
		if resource.Metadata["thanos_ruler_feature_version_unsupported"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesUnsupportedThanosRulerFeatureVersion"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares version %q with enableFeatures, which requires Thanos 0.39 or newer", resource.Name, resource.Metadata["thanos_ruler_version"])
		recommendation = "升级 Thanos 到 0.39 或更高版本，或移除不受支持的 enableFeatures 配置。"
	case KubernetesThanosRulerAdditionalArgsAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_additional_arg_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerAdditionalArguments"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q injects %d additional command-line argument(s) outside dedicated Operator fields", resource.Name, count)
		recommendation = "优先迁移到 Operator 专用字段；保留 additionalArgs 时记录用途、Thanos 版本约束、冲突检查和回退步骤。"
		metadata["thanos_ruler_additional_arg_count"] = fmt.Sprintf("%d", count)
	case KubernetesInvalidThanosRulerAdditionalArgsAnalyzerID:
		invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_additional_arg_invalid_count")
		duplicates := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_additional_arg_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidThanosRulerAdditionalArguments"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has %d invalid and %d duplicate additional argument entries", resource.Name, invalid, duplicates)
		recommendation = "将 additionalArgs 配置为唯一、非空 name 的对象数组，删除重复参数，并确认名称不与 Operator 管理的参数冲突。"
		metadata["thanos_ruler_additional_arg_invalid_count"] = fmt.Sprintf("%d", invalid)
		metadata["thanos_ruler_additional_arg_duplicate_count"] = fmt.Sprintf("%d", duplicates)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
func NewKubernetesThanosRulerFeaturesEnabledAnalyzer() *KubernetesThanosRulerArgumentsAnalyzer {
	return &KubernetesThanosRulerArgumentsAnalyzer{id: KubernetesThanosRulerFeaturesEnabledAnalyzerID, name: "Kubernetes ThanosRuler Features Enabled"}
}

func NewKubernetesInvalidThanosRulerFeatureSetAnalyzer() *KubernetesThanosRulerArgumentsAnalyzer {
	return &KubernetesThanosRulerArgumentsAnalyzer{id: KubernetesInvalidThanosRulerFeatureSetAnalyzerID, name: "Kubernetes Invalid ThanosRuler Feature Set"}
}

func NewKubernetesUnsupportedThanosRulerFeatureVersionAnalyzer() *KubernetesThanosRulerArgumentsAnalyzer {
	return &KubernetesThanosRulerArgumentsAnalyzer{id: KubernetesUnsupportedThanosRulerFeatureVersionAnalyzerID, name: "Kubernetes Unsupported ThanosRuler Feature Version"}
}
