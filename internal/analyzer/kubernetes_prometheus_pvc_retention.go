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
	KubernetesInvalidPrometheusPVCRetentionAnalyzerID = "builtin.kubernetes_invalid_prometheus_pvc_retention"
	KubernetesPrometheusPVCDeleteWithStatefulSetID    = "builtin.kubernetes_prometheus_pvc_delete_with_statefulset"
	KubernetesPrometheusPVCDeleteOnScaleDownID        = "builtin.kubernetes_prometheus_pvc_delete_on_scale_down"
)

type KubernetesPrometheusPVCRetentionAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusPVCRetentionAnalyzer() *KubernetesPrometheusPVCRetentionAnalyzer {
	return &KubernetesPrometheusPVCRetentionAnalyzer{id: KubernetesInvalidPrometheusPVCRetentionAnalyzerID, name: "Kubernetes Invalid Prometheus PVC Retention"}
}

func NewKubernetesPrometheusPVCDeleteWithStatefulSetAnalyzer() *KubernetesPrometheusPVCRetentionAnalyzer {
	return &KubernetesPrometheusPVCRetentionAnalyzer{id: KubernetesPrometheusPVCDeleteWithStatefulSetID, name: "Kubernetes Prometheus PVC Delete With StatefulSet"}
}

func NewKubernetesPrometheusPVCDeleteOnScaleDownAnalyzer() *KubernetesPrometheusPVCRetentionAnalyzer {
	return &KubernetesPrometheusPVCRetentionAnalyzer{id: KubernetesPrometheusPVCDeleteOnScaleDownID, name: "Kubernetes Prometheus PVC Delete On Scale Down"}
}

func (a *KubernetesPrometheusPVCRetentionAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusPVCRetentionAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusPVCRetentionAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusPVCRetentionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusPVCRetentionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_pvc_retention_policy_declared"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusPVCRetentionFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusPVCRetentionFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_pvc_retention_invalid_setting_count")
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityWarning
	category := model.FindingCategoryLifecycle
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusPVCRetentionAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusPVCRetention"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid or inapplicable PVC retention setting(s)", kind, resource.Name, invalidCount)
		recommendation = "仅在 StatefulSet 模式将 persistentVolumeClaimRetentionPolicy 配置为对象，并只使用 Retain 或 Delete 的 whenDeleted/whenScaled 值。"
		metadata["prometheus_pvc_retention_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
		metadata["prometheus_pvc_retention_applicable"] = resource.Metadata["prometheus_pvc_retention_applicable"]
	case KubernetesPrometheusPVCDeleteWithStatefulSetID:
		if invalidCount > 0 || resource.Metadata["prometheus_pvc_retention_applicable"] != "true" || resource.Metadata["prometheus_storage_mode"] != "pvc" || resource.Metadata["prometheus_pvc_when_deleted"] != "Delete" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusPVCDeleteWithStatefulSet"
		evidence = fmt.Sprintf("Kubernetes %s %q deletes every volumeClaimTemplate PVC after its StatefulSet Pods are deleted", kind, resource.Name)
		recommendation = "生产工作负载使用 whenDeleted=Retain；若确需自动删除，先验证 TSDB/WAL 数据保留、远端写入恢复和删除保护流程。"
		metadata["prometheus_pvc_when_deleted"] = "Delete"
	case KubernetesPrometheusPVCDeleteOnScaleDownID:
		if invalidCount > 0 || resource.Metadata["prometheus_pvc_retention_applicable"] != "true" || resource.Metadata["prometheus_storage_mode"] != "pvc" || resource.Metadata["prometheus_pvc_when_scaled"] != "Delete" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusPVCDeleteOnScaleDown"
		evidence = fmt.Sprintf("Kubernetes %s %q deletes PVCs associated with replicas removed during scale-down", kind, resource.Name)
		recommendation = "使用 whenScaled=Retain，或在缩容前确认数据已持久化到远端并接受被缩容副本的本地 TSDB/WAL 永久删除。"
		metadata["prometheus_pvc_when_scaled"] = "Delete"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
