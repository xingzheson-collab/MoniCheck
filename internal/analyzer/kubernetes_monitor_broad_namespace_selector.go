package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesMonitorBroadNamespaceSelectorAnalyzerID = "builtin.kubernetes_monitor_broad_namespace_selector"

type KubernetesMonitorBroadNamespaceSelectorAnalyzer struct{}

func NewKubernetesMonitorBroadNamespaceSelectorAnalyzer() *KubernetesMonitorBroadNamespaceSelectorAnalyzer {
	return &KubernetesMonitorBroadNamespaceSelectorAnalyzer{}
}

func (a *KubernetesMonitorBroadNamespaceSelectorAnalyzer) ID() string {
	return KubernetesMonitorBroadNamespaceSelectorAnalyzerID
}

func (a *KubernetesMonitorBroadNamespaceSelectorAnalyzer) Name() string {
	return "Kubernetes Monitor Broad Namespace Selector"
}

func (a *KubernetesMonitorBroadNamespaceSelectorAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorBroadNamespaceSelectorAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorBroadNamespaceSelectorAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		if !isKubernetesBroadNamespaceMonitorTarget(target, kind) || strings.TrimSpace(target.Metadata["namespace_selector"]) != "*" {
			continue
		}
		selectedCount := kubernetesBroadNamespaceMetadataInt(target.Metadata, "prometheus_selected_count")
		effectiveCount := kubernetesBroadNamespaceMetadataInt(target.Metadata, "prometheus_namespace_selector_effective_count")
		if selectedCount == 0 || effectiveCount == 0 {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorBroadNamespaceSelector",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q uses namespaceSelector.any=true for %d of %d selecting Prometheus workload(s)", kind, target.Name, namespace, effectiveCount, selectedCount),
			},
			Recommendation: "确认该 Monitor 是否确实需要跨所有 namespace 采集；优先使用 namespaceSelector.matchNames 限定 namespace，或在所有选中它的 Prometheus/Agent 设置 ignoreNamespaceSelectors=true，降低误采集和跨租户影响面。",
			Metadata: map[string]string{
				"analyzer_id":              a.ID(),
				"kubernetes_kind":          kind,
				"namespace":                namespace,
				"namespace_selector":       "*",
				"selected_workload_count":  strconv.Itoa(selectedCount),
				"effective_workload_count": strconv.Itoa(effectiveCount),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Metadata["namespace"] != findings[j].Metadata["namespace"] {
			return findings[i].Metadata["namespace"] < findings[j].Metadata["namespace"]
		}
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func isKubernetesBroadNamespaceMonitorTarget(resource model.Resource, kind string) bool {
	if resource.Source.System != "kubernetes" || resource.Type != model.ResourceTypeTarget || resource.Status != model.ResourceStatusActive {
		return false
	}
	return kind == "ServiceMonitor" || kind == "PodMonitor" || kind == "Probe"
}

func kubernetesBroadNamespaceMetadataInt(metadata map[string]string, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(metadata[key]))
	if err != nil || value < 0 {
		return 0
	}
	return value
}
