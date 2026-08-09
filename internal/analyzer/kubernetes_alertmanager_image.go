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
	KubernetesInvalidAlertmanagerImageAnalyzerID          = "builtin.kubernetes_invalid_alertmanager_image"
	KubernetesDeprecatedAlertmanagerImageFieldsAnalyzerID = "builtin.kubernetes_deprecated_alertmanager_image_fields"
	KubernetesMutableAlertmanagerImageAnalyzerID          = "builtin.kubernetes_mutable_alertmanager_image"
	KubernetesAlertmanagerImagePullNeverAnalyzerID        = "builtin.kubernetes_alertmanager_image_pull_never"
)

type KubernetesAlertmanagerImageAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerImageAnalyzer() *KubernetesAlertmanagerImageAnalyzer {
	return &KubernetesAlertmanagerImageAnalyzer{id: KubernetesInvalidAlertmanagerImageAnalyzerID, name: "Kubernetes Invalid Alertmanager Image"}
}

func NewKubernetesDeprecatedAlertmanagerImageFieldsAnalyzer() *KubernetesAlertmanagerImageAnalyzer {
	return &KubernetesAlertmanagerImageAnalyzer{id: KubernetesDeprecatedAlertmanagerImageFieldsAnalyzerID, name: "Kubernetes Deprecated Alertmanager Image Fields"}
}

func NewKubernetesMutableAlertmanagerImageAnalyzer() *KubernetesAlertmanagerImageAnalyzer {
	return &KubernetesAlertmanagerImageAnalyzer{id: KubernetesMutableAlertmanagerImageAnalyzerID, name: "Kubernetes Mutable Alertmanager Image"}
}

func NewKubernetesAlertmanagerImagePullNeverAnalyzer() *KubernetesAlertmanagerImageAnalyzer {
	return &KubernetesAlertmanagerImageAnalyzer{id: KubernetesAlertmanagerImagePullNeverAnalyzerID, name: "Kubernetes Alertmanager Image Pull Never"}
}

func (a *KubernetesAlertmanagerImageAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerImageAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerImageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerImageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerImageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_image_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerImageFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerImageFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_image_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerImageAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerImage"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid image setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法 OCI 镜像引用、Always/IfNotPresent/Never 拉取策略，并为每个 imagePullSecret 配置唯一非空名称。"
		metadata["alertmanager_image_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesDeprecatedAlertmanagerImageFieldsAnalyzerID:
		legacyCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_legacy_image_field_count")
		if invalidCount > 0 || legacyCount == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesDeprecatedAlertmanagerImageFields"
		shadowedCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_shadowed_legacy_image_field_count")
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d deprecated image field(s), of which %d are shadowed by spec.image", resource.Name, legacyCount, shadowedCount)
		recommendation = "将 baseImage/tag/sha 合并为唯一 spec.image 引用，并使用 digest pin 后删除旧字段。"
		metadata["alertmanager_legacy_image_field_count"] = fmt.Sprintf("%d", legacyCount)
		metadata["alertmanager_shadowed_legacy_image_field_count"] = fmt.Sprintf("%d", shadowedCount)
	case KubernetesMutableAlertmanagerImageAnalyzerID:
		if invalidCount > 0 || resource.Metadata["alertmanager_image_declared"] != "true" || resource.Metadata["alertmanager_image_valid"] != "true" || resource.Metadata["alertmanager_image_digest_pinned"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesMutableAlertmanagerImage"
		latest := resource.Metadata["alertmanager_image_latest_tag"] == "true"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q uses an explicit mutable image reference (latest-or-untagged=%t)", resource.Name, latest)
		recommendation = "将 spec.image 固定到经过验证的 sha256 digest，由受控发布流程显式更新 digest，避免标签漂移导致副本版本不一致。"
		metadata["alertmanager_image_latest_tag"] = fmt.Sprintf("%t", latest)
	case KubernetesAlertmanagerImagePullNeverAnalyzerID:
		if invalidCount > 0 || resource.Metadata["alertmanager_image_pull_policy_valid"] != "true" || resource.Metadata["alertmanager_image_pull_policy"] != "Never" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerImagePullNever"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q uses imagePullPolicy Never, requiring every eligible node to have all images preloaded", resource.Name)
		recommendation = "使用 digest-pinned image 配合 IfNotPresent，或验证所有节点和扩容节点均有可靠的预拉取与镜像垃圾回收豁免流程。"
		metadata["alertmanager_image_pull_policy"] = "Never"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
