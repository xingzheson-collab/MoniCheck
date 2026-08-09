package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesMonitorWithoutSelectorAnalyzerID = "builtin.kubernetes_monitor_without_selector"

type KubernetesMonitorWithoutSelectorAnalyzer struct{}

func NewKubernetesMonitorWithoutSelectorAnalyzer() *KubernetesMonitorWithoutSelectorAnalyzer {
	return &KubernetesMonitorWithoutSelectorAnalyzer{}
}

func (a *KubernetesMonitorWithoutSelectorAnalyzer) ID() string {
	return KubernetesMonitorWithoutSelectorAnalyzerID
}

func (a *KubernetesMonitorWithoutSelectorAnalyzer) Name() string {
	return "Kubernetes Monitor Without Selector"
}

func (a *KubernetesMonitorWithoutSelectorAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorWithoutSelectorAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorWithoutSelectorAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesMonitorTarget(target) || strings.TrimSpace(target.Metadata["selector"]) != "" {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorWithoutSelector",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has no selector metadata", kind, target.Name, namespace),
			},
			Recommendation: "为该 ServiceMonitor/PodMonitor 补充 selector.matchLabels 或 selector 标签约束，确保 Prometheus Operator 只选择预期服务或 Pod。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"kubernetes_kind": kind,
				"namespace":       namespace,
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

func isKubernetesMonitorTarget(resource model.Resource) bool {
	if resource.Source.System != "kubernetes" || resource.Type != model.ResourceTypeTarget || resource.Status != model.ResourceStatusActive {
		return false
	}
	kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
	return kind == "ServiceMonitor" || kind == "PodMonitor"
}

func kubernetesResourceNamespace(resource model.Resource) string {
	namespace := strings.TrimSpace(resource.Metadata["namespace"])
	if namespace == "" {
		return "default"
	}
	return namespace
}
