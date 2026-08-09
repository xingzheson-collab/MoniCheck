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
	KubernetesAlertmanagerFeaturesEnabledAnalyzerID                  = "builtin.kubernetes_alertmanager_features_enabled"
	KubernetesInvalidAlertmanagerFeatureSetAnalyzerID                = "builtin.kubernetes_invalid_alertmanager_feature_set"
	KubernetesUnsupportedAlertmanagerFeatureVersionAnalyzerID        = "builtin.kubernetes_unsupported_alertmanager_feature_version"
	KubernetesAlertmanagerAdditionalArgsAnalyzerID                   = "builtin.kubernetes_alertmanager_additional_arguments"
	KubernetesInvalidAlertmanagerAdditionalArgsAnalyzerID            = "builtin.kubernetes_invalid_alertmanager_additional_arguments"
	KubernetesUnsupportedAlertmanagerAdditionalArgsVersionAnalyzerID = "builtin.kubernetes_unsupported_alertmanager_additional_arguments_version"
)

type KubernetesAlertmanagerArgumentsAnalyzer struct {
	id   string
	name string
}

func newKubernetesAlertmanagerArgumentsAnalyzer(id, name string) *KubernetesAlertmanagerArgumentsAnalyzer {
	return &KubernetesAlertmanagerArgumentsAnalyzer{id: id, name: name}
}
func NewKubernetesAlertmanagerFeaturesEnabledAnalyzer() *KubernetesAlertmanagerArgumentsAnalyzer {
	return newKubernetesAlertmanagerArgumentsAnalyzer(KubernetesAlertmanagerFeaturesEnabledAnalyzerID, "Kubernetes Alertmanager Features Enabled")
}
func NewKubernetesInvalidAlertmanagerFeatureSetAnalyzer() *KubernetesAlertmanagerArgumentsAnalyzer {
	return newKubernetesAlertmanagerArgumentsAnalyzer(KubernetesInvalidAlertmanagerFeatureSetAnalyzerID, "Kubernetes Invalid Alertmanager Feature Set")
}
func NewKubernetesUnsupportedAlertmanagerFeatureVersionAnalyzer() *KubernetesAlertmanagerArgumentsAnalyzer {
	return newKubernetesAlertmanagerArgumentsAnalyzer(KubernetesUnsupportedAlertmanagerFeatureVersionAnalyzerID, "Kubernetes Unsupported Alertmanager Feature Version")
}
func NewKubernetesAlertmanagerAdditionalArgsAnalyzer() *KubernetesAlertmanagerArgumentsAnalyzer {
	return newKubernetesAlertmanagerArgumentsAnalyzer(KubernetesAlertmanagerAdditionalArgsAnalyzerID, "Kubernetes Alertmanager Additional Arguments")
}
func NewKubernetesInvalidAlertmanagerAdditionalArgsAnalyzer() *KubernetesAlertmanagerArgumentsAnalyzer {
	return newKubernetesAlertmanagerArgumentsAnalyzer(KubernetesInvalidAlertmanagerAdditionalArgsAnalyzerID, "Kubernetes Invalid Alertmanager Additional Arguments")
}
func NewKubernetesUnsupportedAlertmanagerAdditionalArgsVersionAnalyzer() *KubernetesAlertmanagerArgumentsAnalyzer {
	return newKubernetesAlertmanagerArgumentsAnalyzer(KubernetesUnsupportedAlertmanagerAdditionalArgsVersionAnalyzerID, "Kubernetes Unsupported Alertmanager Additional Arguments Version")
}
func (a *KubernetesAlertmanagerArgumentsAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerArgumentsAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerArgumentsAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerArgumentsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerArgumentsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_argument_metadata"] != "true" {
			continue
		}
		finding, matched := kubernetesAlertmanagerArgumentsFinding(a.id, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerArgumentsFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesAlertmanagerFeaturesEnabledAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_feature_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerFeaturesEnabled"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q enables %d optional feature flag(s) outside the maintainers' support guarantee", resource.Name, count)
		recommendation = "确认每个 feature flag 的必要性、升级兼容性和回退方案；不再需要的实验能力应移除。"
		metadata["alertmanager_feature_count"] = fmt.Sprintf("%d", count)
	case KubernetesInvalidAlertmanagerFeatureSetAnalyzerID:
		invalid := alertmanagerStorageMetadataInt64(resource, "alertmanager_feature_invalid_count")
		duplicates := alertmanagerStorageMetadataInt64(resource, "alertmanager_feature_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidAlertmanagerFeatureSet"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has %d invalid and %d duplicate feature entries", resource.Name, invalid, duplicates)
		recommendation = "将 enableFeatures 配置为唯一、非空字符串数组，并确认 Operator 已成功调谐。"
	case KubernetesUnsupportedAlertmanagerFeatureVersionAnalyzerID:
		if resource.Metadata["alertmanager_feature_version_unsupported"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		findingType = "KubernetesUnsupportedAlertmanagerFeatureVersion"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares version %q with enableFeatures, which requires Alertmanager 0.27 or newer", resource.Name, resource.Metadata["alertmanager_version"])
		recommendation = "升级 Alertmanager 到 0.27 或更高版本，或移除不受支持的 enableFeatures 配置。"
	case KubernetesAlertmanagerAdditionalArgsAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_additional_arg_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerAdditionalArguments"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q injects %d additional command-line argument(s) outside dedicated Operator fields", resource.Name, count)
		recommendation = "优先迁移到 Operator 专用字段；保留 additionalArgs 时记录用途、版本约束、冲突检查和回退步骤。"
		metadata["alertmanager_additional_arg_count"] = fmt.Sprintf("%d", count)
	case KubernetesInvalidAlertmanagerAdditionalArgsAnalyzerID:
		invalid := alertmanagerStorageMetadataInt64(resource, "alertmanager_additional_arg_invalid_count")
		duplicates := alertmanagerStorageMetadataInt64(resource, "alertmanager_additional_arg_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidAlertmanagerAdditionalArguments"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has %d invalid and %d duplicate additional argument entries", resource.Name, invalid, duplicates)
		recommendation = "将 additionalArgs 配置为唯一、非空 name 的对象数组，删除重复参数，并确认名称不与 Operator 管理的参数冲突。"
	case KubernetesUnsupportedAlertmanagerAdditionalArgsVersionAnalyzerID:
		if resource.Metadata["alertmanager_additional_args_version_unsupported"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		findingType = "KubernetesUnsupportedAlertmanagerAdditionalArgumentsVersion"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares version %q with additionalArgs, which requires Alertmanager 0.25 or newer", resource.Name, resource.Metadata["alertmanager_version"])
		recommendation = "升级 Alertmanager 到 0.25 或更高版本，或移除不受支持的 additionalArgs 配置。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
