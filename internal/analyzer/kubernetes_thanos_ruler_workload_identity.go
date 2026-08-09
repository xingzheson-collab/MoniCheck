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
	KubernetesInvalidThanosRulerWorkloadIdentityAnalyzerID = "builtin.kubernetes_invalid_thanos_ruler_workload_identity"
	KubernetesSharedThanosRulerGoverningServiceAnalyzerID  = "builtin.kubernetes_shared_thanos_ruler_governing_service"
)

type KubernetesThanosRulerWorkloadIdentityAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerWorkloadIdentityAnalyzer() *KubernetesThanosRulerWorkloadIdentityAnalyzer {
	return &KubernetesThanosRulerWorkloadIdentityAnalyzer{id: KubernetesInvalidThanosRulerWorkloadIdentityAnalyzerID, name: "Kubernetes Invalid ThanosRuler Workload Identity"}
}

func NewKubernetesSharedThanosRulerGoverningServiceAnalyzer() *KubernetesThanosRulerWorkloadIdentityAnalyzer {
	return &KubernetesThanosRulerWorkloadIdentityAnalyzer{id: KubernetesSharedThanosRulerGoverningServiceAnalyzerID, name: "Kubernetes Shared ThanosRuler Governing Service"}
}

func (a *KubernetesThanosRulerWorkloadIdentityAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerWorkloadIdentityAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerWorkloadIdentityAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerWorkloadIdentityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerWorkloadIdentityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_workload_identity_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerWorkloadIdentityFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerWorkloadIdentityFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	serviceInvalid := resource.Metadata["thanos_ruler_service_name_declared"] == "true" && resource.Metadata["thanos_ruler_service_name_valid"] != "true"
	serviceAccountInvalid := resource.Metadata["thanos_ruler_service_account_name_declared"] == "true" && resource.Metadata["thanos_ruler_service_account_name_valid"] != "true"
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerWorkloadIdentityAnalyzerID:
		if !serviceInvalid && !serviceAccountInvalid {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerWorkloadIdentity"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has invalid workload identity settings: serviceName invalid=%t, serviceAccountName invalid=%t", resource.Name, serviceInvalid, serviceAccountInvalid)
		recommendation = "使用非空且符合 DNS-1123 的 serviceName 和 serviceAccountName，并确认 governing Service 在 ThanosRuler 之前创建。"
		metadata["thanos_ruler_service_name_invalid"] = fmt.Sprintf("%t", serviceInvalid)
		metadata["thanos_ruler_service_account_name_invalid"] = fmt.Sprintf("%t", serviceAccountInvalid)
	case KubernetesSharedThanosRulerGoverningServiceAnalyzerID:
		sharedCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_shared_service_count")
		if serviceInvalid || sharedCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesSharedThanosRulerGoverningService"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q shares its governing Service identity with %d other ThanosRuler resource(s) in the namespace", resource.Name, sharedCount)
		recommendation = "为同命名空间的每个 ThanosRuler 配置不同 serviceName，并确保对应 headless Service 在 CR 之前创建且 selector 匹配 Pod。"
		metadata["thanos_ruler_shared_service_count"] = fmt.Sprintf("%d", sharedCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
