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
	KubernetesPrometheusHostNetworkAnalyzerID           = "builtin.kubernetes_prometheus_host_network"
	KubernetesPrometheusAutomountTokenAnalyzerID        = "builtin.kubernetes_prometheus_automount_service_account_token"
	KubernetesInvalidPrometheusAutomountTokenAnalyzerID = "builtin.kubernetes_invalid_prometheus_automount_service_account_token"
)

type KubernetesPrometheusSecurityAnalyzer struct {
	id   string
	name string
}

func NewKubernetesPrometheusHostNetworkAnalyzer() *KubernetesPrometheusSecurityAnalyzer {
	return &KubernetesPrometheusSecurityAnalyzer{id: KubernetesPrometheusHostNetworkAnalyzerID, name: "Kubernetes Prometheus Host Network"}
}

func NewKubernetesPrometheusAutomountTokenAnalyzer() *KubernetesPrometheusSecurityAnalyzer {
	return &KubernetesPrometheusSecurityAnalyzer{id: KubernetesPrometheusAutomountTokenAnalyzerID, name: "Kubernetes Prometheus Automount Service Account Token"}
}

func NewKubernetesInvalidPrometheusAutomountTokenAnalyzer() *KubernetesPrometheusSecurityAnalyzer {
	return &KubernetesPrometheusSecurityAnalyzer{id: KubernetesInvalidPrometheusAutomountTokenAnalyzerID, name: "Kubernetes Invalid Prometheus Automount Service Account Token"}
}

func (a *KubernetesPrometheusSecurityAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusSecurityAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusSecurityAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusSecurityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusSecurityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") {
			continue
		}
		if finding, matched := kubernetesPrometheusSecurityFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusSecurityFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesPrometheusHostNetworkAnalyzerID:
		if resource.Metadata["prometheus_host_network_valid"] != "true" || resource.Metadata["prometheus_host_network_enabled"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusHostNetwork"
		evidence = fmt.Sprintf("Kubernetes %s %q uses the node network namespace", kind, resource.Name)
		recommendation = "关闭 hostNetwork，使用 ClusterIP/Ingress 和 NetworkPolicy 暴露所需端口；确需主机网络时限制节点、端口和入站来源。"
	case KubernetesPrometheusAutomountTokenAnalyzerID:
		if resource.Metadata["prometheus_automount_token_declared"] != "true" || resource.Metadata["prometheus_automount_token_valid"] != "true" || resource.Metadata["prometheus_automount_token_enabled"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusAutomountServiceAccountToken"
		evidence = fmt.Sprintf("Kubernetes %s %q explicitly mounts a ServiceAccount API token", kind, resource.Name)
		recommendation = "若工作负载不需要直接访问 Kubernetes API，设置 automountServiceAccountToken=false，并最小化 ServiceAccount RBAC 权限。"
	case KubernetesInvalidPrometheusAutomountTokenAnalyzerID:
		if resource.Metadata["prometheus_automount_token_declared"] != "true" || resource.Metadata["prometheus_automount_token_valid"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusAutomountServiceAccountToken"
		evidence = fmt.Sprintf("Kubernetes %s %q declares a non-boolean automountServiceAccountToken value", kind, resource.Name)
		recommendation = "将 automountServiceAccountToken 配置为 true 或 false，并通过 CRD/admission 校验确认 Operator 可以调谐。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
