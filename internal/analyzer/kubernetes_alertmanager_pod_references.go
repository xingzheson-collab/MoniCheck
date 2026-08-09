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
	KubernetesInvalidAlertmanagerPodReferencesAnalyzerID     = "builtin.kubernetes_invalid_alertmanager_pod_references"
	KubernetesAlertmanagerAdditionalSecretMountsAnalyzerID   = "builtin.kubernetes_alertmanager_additional_secret_mounts"
	KubernetesAlertmanagerGeneratedVolumeCollisionAnalyzerID = "builtin.kubernetes_alertmanager_generated_volume_collision"
)

type KubernetesAlertmanagerPodReferencesAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerPodReferencesAnalyzer() *KubernetesAlertmanagerPodReferencesAnalyzer {
	return &KubernetesAlertmanagerPodReferencesAnalyzer{id: KubernetesInvalidAlertmanagerPodReferencesAnalyzerID, name: "Kubernetes Invalid Alertmanager Pod References"}
}

func NewKubernetesAlertmanagerAdditionalSecretMountsAnalyzer() *KubernetesAlertmanagerPodReferencesAnalyzer {
	return &KubernetesAlertmanagerPodReferencesAnalyzer{id: KubernetesAlertmanagerAdditionalSecretMountsAnalyzerID, name: "Kubernetes Alertmanager Additional Secret Mounts"}
}

func NewKubernetesAlertmanagerGeneratedVolumeCollisionAnalyzer() *KubernetesAlertmanagerPodReferencesAnalyzer {
	return &KubernetesAlertmanagerPodReferencesAnalyzer{id: KubernetesAlertmanagerGeneratedVolumeCollisionAnalyzerID, name: "Kubernetes Alertmanager Generated Volume Collision"}
}

func (a *KubernetesAlertmanagerPodReferencesAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerPodReferencesAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerPodReferencesAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerPodReferencesAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerPodReferencesAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_pod_reference_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerPodReferenceFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerPodReferenceFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_pod_reference_invalid_setting_count")
	serviceAccountInvalid := resource.Metadata["alertmanager_service_account_name_declared"] == "true" && resource.Metadata["alertmanager_service_account_name_valid"] != "true"
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerPodReferencesAnalyzerID:
		if invalidCount == 0 && !serviceAccountInvalid {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerPodReferences"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has %d invalid or duplicate Secret/ConfigMap reference setting(s) and invalid serviceAccountName=%t", resource.Name, invalidCount, serviceAccountInvalid)
		recommendation = "使用唯一、非空且符合 DNS-1123 的 Secret、ConfigMap 和 ServiceAccount 名称，并确认引用对象位于 Alertmanager 命名空间。"
		metadata["alertmanager_pod_reference_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
		metadata["alertmanager_service_account_name_invalid"] = fmt.Sprintf("%t", serviceAccountInvalid)
	case KubernetesAlertmanagerAdditionalSecretMountsAnalyzerID:
		secretCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_secret_count")
		if invalidCount > 0 || serviceAccountInvalid || secretCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerAdditionalSecretMounts"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q mounts %d additional Secret object(s), exposing every key in each referenced Secret to the Alertmanager container filesystem", resource.Name, secretCount)
		recommendation = "仅挂载 Alertmanager 实际需要的专用 Secret，避免复用包含无关凭据的聚合 Secret，并限制 Secret 读取 RBAC、轮换和 Pod 访问权限。"
		metadata["alertmanager_secret_count"] = fmt.Sprintf("%d", secretCount)
	case KubernetesAlertmanagerGeneratedVolumeCollisionAnalyzerID:
		collisionCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_generated_volume_collision_count")
		if invalidCount > 0 || collisionCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesAlertmanagerGeneratedVolumeCollision"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d additional volume name(s) colliding with Operator-generated Secret or ConfigMap volumes", resource.Name, collisionCount)
		recommendation = "重命名冲突的 spec.volumes 条目，避免使用 Operator 保留的 secret-<name> 和 configmap-<name> 生成卷名。"
		metadata["alertmanager_generated_volume_collision_count"] = fmt.Sprintf("%d", collisionCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
