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
	KubernetesInvalidAlertmanagerPVCRetentionAnalyzerID = "builtin.kubernetes_invalid_alertmanager_pvc_retention"
	KubernetesAlertmanagerPVCDeleteWithStatefulSetID    = "builtin.kubernetes_alertmanager_pvc_delete_with_statefulset"
	KubernetesAlertmanagerPVCDeleteOnScaleDownID        = "builtin.kubernetes_alertmanager_pvc_delete_on_scale_down"
)

type KubernetesAlertmanagerPVCRetentionAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerPVCRetentionAnalyzer() *KubernetesAlertmanagerPVCRetentionAnalyzer {
	return &KubernetesAlertmanagerPVCRetentionAnalyzer{id: KubernetesInvalidAlertmanagerPVCRetentionAnalyzerID, name: "Kubernetes Invalid Alertmanager PVC Retention"}
}

func NewKubernetesAlertmanagerPVCDeleteWithStatefulSetAnalyzer() *KubernetesAlertmanagerPVCRetentionAnalyzer {
	return &KubernetesAlertmanagerPVCRetentionAnalyzer{id: KubernetesAlertmanagerPVCDeleteWithStatefulSetID, name: "Kubernetes Alertmanager PVC Delete With StatefulSet"}
}

func NewKubernetesAlertmanagerPVCDeleteOnScaleDownAnalyzer() *KubernetesAlertmanagerPVCRetentionAnalyzer {
	return &KubernetesAlertmanagerPVCRetentionAnalyzer{id: KubernetesAlertmanagerPVCDeleteOnScaleDownID, name: "Kubernetes Alertmanager PVC Delete On Scale Down"}
}

func (a *KubernetesAlertmanagerPVCRetentionAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerPVCRetentionAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerPVCRetentionAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerPVCRetentionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerPVCRetentionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_pvc_retention_policy_declared"] == "" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerPVCRetentionFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerPVCRetentionFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_pvc_retention_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryLifecycle
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerPVCRetentionAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerPVCRetention"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid PVC retention setting(s)", resource.Name, invalidCount)
		recommendation = "将 persistentVolumeClaimRetentionPolicy 配置为对象，并仅使用 Retain 或 Delete 的 whenDeleted/whenScaled 值。"
		metadata["alertmanager_pvc_retention_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesAlertmanagerPVCDeleteWithStatefulSetID:
		if invalidCount > 0 || resource.Metadata["alertmanager_storage_mode"] != "pvc" || resource.Metadata["alertmanager_pvc_when_deleted"] != "Delete" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerPVCDeleteWithStatefulSet"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q deletes every volumeClaimTemplate PVC after its StatefulSet Pods are deleted", resource.Name)
		recommendation = "生产 Alertmanager 使用 whenDeleted=Retain；若确需自动删除，先验证 silence/notification 状态备份、恢复与删除保护流程。"
		metadata["alertmanager_pvc_when_deleted"] = "Delete"
	case KubernetesAlertmanagerPVCDeleteOnScaleDownID:
		if invalidCount > 0 || resource.Metadata["alertmanager_storage_mode"] != "pvc" || resource.Metadata["alertmanager_pvc_when_scaled"] != "Delete" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerPVCDeleteOnScaleDown"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q deletes PVCs associated with replicas removed during scale-down", resource.Name)
		recommendation = "使用 whenScaled=Retain，或在缩容前确认剩余副本已同步状态并接受被缩容成员的本地数据永久删除。"
		metadata["alertmanager_pvc_when_scaled"] = "Delete"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
