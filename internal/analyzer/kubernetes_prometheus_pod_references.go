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
	KubernetesInvalidPrometheusPodReferencesAnalyzerID     = "builtin.kubernetes_invalid_prometheus_pod_references"
	KubernetesPrometheusAdditionalSecretMountsAnalyzerID   = "builtin.kubernetes_prometheus_additional_secret_mounts"
	KubernetesPrometheusGeneratedVolumeCollisionAnalyzerID = "builtin.kubernetes_prometheus_generated_volume_collision"
)

type KubernetesPrometheusPodReferencesAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusPodReferencesAnalyzer() *KubernetesPrometheusPodReferencesAnalyzer {
	return &KubernetesPrometheusPodReferencesAnalyzer{id: KubernetesInvalidPrometheusPodReferencesAnalyzerID, name: "Kubernetes Invalid Prometheus Pod References"}
}

func NewKubernetesPrometheusAdditionalSecretMountsAnalyzer() *KubernetesPrometheusPodReferencesAnalyzer {
	return &KubernetesPrometheusPodReferencesAnalyzer{id: KubernetesPrometheusAdditionalSecretMountsAnalyzerID, name: "Kubernetes Prometheus Additional Secret Mounts"}
}

func NewKubernetesPrometheusGeneratedVolumeCollisionAnalyzer() *KubernetesPrometheusPodReferencesAnalyzer {
	return &KubernetesPrometheusPodReferencesAnalyzer{id: KubernetesPrometheusGeneratedVolumeCollisionAnalyzerID, name: "Kubernetes Prometheus Generated Volume Collision"}
}

func (a *KubernetesPrometheusPodReferencesAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusPodReferencesAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusPodReferencesAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusPodReferencesAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusPodReferencesAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_pod_reference_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusPodReferenceFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusPodReferenceFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_pod_reference_invalid_setting_count")
	serviceAccountInvalid := resource.Metadata["prometheus_service_account_name_declared"] == "true" && resource.Metadata["prometheus_service_account_name_valid"] != "true"
	kind := resource.Metadata["kubernetes_kind"]
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusPodReferencesAnalyzerID:
		if invalidCount == 0 && !serviceAccountInvalid {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusPodReferences"
		evidence = fmt.Sprintf("Kubernetes %s %q has %d invalid or duplicate Secret/ConfigMap reference setting(s) and invalid serviceAccountName=%t", kind, resource.Name, invalidCount, serviceAccountInvalid)
		recommendation = "使用唯一、非空且符合 DNS-1123 的 Secret、ConfigMap 和 ServiceAccount 名称，并确认引用对象位于工作负载命名空间。"
		metadata["prometheus_pod_reference_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
		metadata["prometheus_service_account_name_invalid"] = fmt.Sprintf("%t", serviceAccountInvalid)
	case KubernetesPrometheusAdditionalSecretMountsAnalyzerID:
		secretCount := prometheusStorageMetadataInt64(resource, "prometheus_secret_count")
		if invalidCount > 0 || serviceAccountInvalid || secretCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusAdditionalSecretMounts"
		evidence = fmt.Sprintf("Kubernetes %s %q mounts %d additional Secret object(s), exposing every key in each referenced Secret to the Prometheus container filesystem", kind, resource.Name, secretCount)
		recommendation = "仅挂载工作负载实际需要的专用 Secret，避免复用包含无关凭据的聚合 Secret，并限制 Secret 读取 RBAC、轮换和 Pod 访问权限。"
		metadata["prometheus_secret_count"] = fmt.Sprintf("%d", secretCount)
	case KubernetesPrometheusGeneratedVolumeCollisionAnalyzerID:
		collisionCount := prometheusStorageMetadataInt64(resource, "prometheus_generated_volume_collision_count")
		if invalidCount > 0 || collisionCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesPrometheusGeneratedVolumeCollision"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d additional volume name(s) colliding with Operator-generated Secret or ConfigMap volumes", kind, resource.Name, collisionCount)
		recommendation = "重命名冲突的 spec.volumes 条目，避免使用 Operator 保留的 secret-<name> 和 configmap-<name> 生成卷名。"
		metadata["prometheus_generated_volume_collision_count"] = fmt.Sprintf("%d", collisionCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
