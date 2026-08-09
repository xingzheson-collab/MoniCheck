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
	KubernetesInvalidPrometheusPodSecurityAnalyzerID   = "builtin.kubernetes_invalid_prometheus_pod_security"
	KubernetesPrivilegedPrometheusWorkloadAnalyzerID   = "builtin.kubernetes_privileged_prometheus_workload"
	KubernetesWeakPrometheusSecurityControlsAnalyzerID = "builtin.kubernetes_weak_prometheus_security_controls"
)

type KubernetesPrometheusPodSecurityAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusPodSecurityAnalyzer() *KubernetesPrometheusPodSecurityAnalyzer {
	return &KubernetesPrometheusPodSecurityAnalyzer{id: KubernetesInvalidPrometheusPodSecurityAnalyzerID, name: "Kubernetes Invalid Prometheus Pod Security"}
}

func NewKubernetesPrivilegedPrometheusWorkloadAnalyzer() *KubernetesPrometheusPodSecurityAnalyzer {
	return &KubernetesPrometheusPodSecurityAnalyzer{id: KubernetesPrivilegedPrometheusWorkloadAnalyzerID, name: "Kubernetes Privileged Prometheus Workload"}
}

func NewKubernetesWeakPrometheusSecurityControlsAnalyzer() *KubernetesPrometheusPodSecurityAnalyzer {
	return &KubernetesPrometheusPodSecurityAnalyzer{id: KubernetesWeakPrometheusSecurityControlsAnalyzerID, name: "Kubernetes Weak Prometheus Security Controls"}
}

func (a *KubernetesPrometheusPodSecurityAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusPodSecurityAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusPodSecurityAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusPodSecurityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusPodSecurityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_pod_security_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusPodSecurityFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusPodSecurityFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	kind := resource.Metadata["kubernetes_kind"]
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	invalidCount := alertmanagerStorageMetadataInt64(resource, "prometheus_security_context_invalid_count")
	rootCount := alertmanagerStorageMetadataInt64(resource, "prometheus_root_user_context_count")
	privilegedCount := alertmanagerStorageMetadataInt64(resource, "prometheus_privileged_container_count")
	hostProcessCount := alertmanagerStorageMetadataInt64(resource, "prometheus_host_process_context_count")
	switch analyzerID {
	case KubernetesInvalidPrometheusPodSecurityAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusPodSecurity"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d malformed Pod/container security context setting(s)", kind, resource.Name, invalidCount)
		recommendation = "使用合法 Kubernetes PodSecurityContext/SecurityContext 类型，并通过 admission dry-run 和 Operator Reconciled 状态验证生成 Pod。"
		metadata["prometheus_security_context_invalid_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesPrivilegedPrometheusWorkloadAnalyzerID:
		if invalidCount > 0 || rootCount+privilegedCount+hostProcessCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrivilegedPrometheusWorkload"
		evidence = fmt.Sprintf("Kubernetes %s %q declares root UID contexts=%d, privileged containers=%d, HostProcess contexts=%d", kind, resource.Name, rootCount, privilegedCount, hostProcessCount)
		recommendation = "以非 root UID 运行，禁用 privileged/HostProcess，并使用最小权限的 volume、network 和 kernel 安全配置。"
		metadata["prometheus_root_user_context_count"] = fmt.Sprintf("%d", rootCount)
		metadata["prometheus_privileged_container_count"] = fmt.Sprintf("%d", privilegedCount)
		metadata["prometheus_host_process_context_count"] = fmt.Sprintf("%d", hostProcessCount)
	case KubernetesWeakPrometheusSecurityControlsAnalyzerID:
		nonRootDisabled := alertmanagerStorageMetadataInt64(resource, "prometheus_non_root_disabled_context_count")
		escalation := alertmanagerStorageMetadataInt64(resource, "prometheus_privilege_escalation_context_count")
		unconfined := alertmanagerStorageMetadataInt64(resource, "prometheus_unconfined_seccomp_context_count")
		capabilities := alertmanagerStorageMetadataInt64(resource, "prometheus_capability_addition_context_count")
		writableRoot := alertmanagerStorageMetadataInt64(resource, "prometheus_writable_root_filesystem_context_count")
		if invalidCount > 0 || nonRootDisabled+escalation+unconfined+capabilities+writableRoot == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesWeakPrometheusSecurityControls"
		evidence = fmt.Sprintf("Kubernetes %s %q weakens security controls: non-root disabled=%d, privilege escalation=%d, unconfined seccomp=%d, capability additions=%d, writable root filesystems=%d", kind, resource.Name, nonRootDisabled, escalation, unconfined, capabilities, writableRoot)
		recommendation = "设置 runAsNonRoot=true、allowPrivilegeEscalation=false、RuntimeDefault/Localhost seccomp 和 readOnlyRootFilesystem=true，并删除不必要 capabilities。"
		metadata["prometheus_weak_security_control_count"] = fmt.Sprintf("%d", nonRootDisabled+escalation+unconfined+capabilities+writableRoot)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
