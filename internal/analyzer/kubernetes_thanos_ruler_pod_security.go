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
	KubernetesInvalidThanosRulerPodSecurityAnalyzerID   = "builtin.kubernetes_invalid_thanos_ruler_pod_security"
	KubernetesPrivilegedThanosRulerWorkloadAnalyzerID   = "builtin.kubernetes_privileged_thanos_ruler_workload"
	KubernetesWeakThanosRulerSecurityControlsAnalyzerID = "builtin.kubernetes_weak_thanos_ruler_security_controls"
)

type KubernetesThanosRulerPodSecurityAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerPodSecurityAnalyzer() *KubernetesThanosRulerPodSecurityAnalyzer {
	return &KubernetesThanosRulerPodSecurityAnalyzer{id: KubernetesInvalidThanosRulerPodSecurityAnalyzerID, name: "Kubernetes Invalid ThanosRuler Pod Security"}
}

func NewKubernetesPrivilegedThanosRulerWorkloadAnalyzer() *KubernetesThanosRulerPodSecurityAnalyzer {
	return &KubernetesThanosRulerPodSecurityAnalyzer{id: KubernetesPrivilegedThanosRulerWorkloadAnalyzerID, name: "Kubernetes Privileged ThanosRuler Workload"}
}

func NewKubernetesWeakThanosRulerSecurityControlsAnalyzer() *KubernetesThanosRulerPodSecurityAnalyzer {
	return &KubernetesThanosRulerPodSecurityAnalyzer{id: KubernetesWeakThanosRulerSecurityControlsAnalyzerID, name: "Kubernetes Weak ThanosRuler Security Controls"}
}

func (a *KubernetesThanosRulerPodSecurityAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerPodSecurityAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerPodSecurityAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerPodSecurityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerPodSecurityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_pod_security_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerPodSecurityFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerPodSecurityFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_security_context_invalid_count")
	rootCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_root_user_context_count")
	privilegedCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_privileged_container_count")
	hostProcessCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_host_process_context_count")
	switch analyzerID {
	case KubernetesInvalidThanosRulerPodSecurityAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerPodSecurity"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d malformed Pod/container security context setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法 Kubernetes PodSecurityContext/SecurityContext 类型，并通过 admission dry-run 和 Operator Reconciled 状态验证生成 Pod。"
		metadata["thanos_ruler_security_context_invalid_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesPrivilegedThanosRulerWorkloadAnalyzerID:
		if invalidCount > 0 || rootCount+privilegedCount+hostProcessCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrivilegedThanosRulerWorkload"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares root UID contexts=%d, privileged containers=%d, HostProcess contexts=%d", resource.Name, rootCount, privilegedCount, hostProcessCount)
		recommendation = "以非 root UID 运行，禁用 privileged/HostProcess，并使用最小权限的 volume、network 和 kernel 安全配置。"
		metadata["thanos_ruler_root_user_context_count"] = fmt.Sprintf("%d", rootCount)
		metadata["thanos_ruler_privileged_container_count"] = fmt.Sprintf("%d", privilegedCount)
		metadata["thanos_ruler_host_process_context_count"] = fmt.Sprintf("%d", hostProcessCount)
	case KubernetesWeakThanosRulerSecurityControlsAnalyzerID:
		nonRootDisabled := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_non_root_disabled_context_count")
		escalation := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_privilege_escalation_context_count")
		unconfined := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_unconfined_seccomp_context_count")
		capabilities := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_capability_addition_context_count")
		writableRoot := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_writable_root_filesystem_context_count")
		if invalidCount > 0 || nonRootDisabled+escalation+unconfined+capabilities+writableRoot == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesWeakThanosRulerSecurityControls"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q weakens security controls: non-root disabled=%d, privilege escalation=%d, unconfined seccomp=%d, capability additions=%d, writable root filesystems=%d", resource.Name, nonRootDisabled, escalation, unconfined, capabilities, writableRoot)
		recommendation = "设置 runAsNonRoot=true、allowPrivilegeEscalation=false、RuntimeDefault/Localhost seccomp 和 readOnlyRootFilesystem=true，并删除不必要 capabilities。"
		metadata["thanos_ruler_weak_security_control_count"] = fmt.Sprintf("%d", nonRootDisabled+escalation+unconfined+capabilities+writableRoot)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
