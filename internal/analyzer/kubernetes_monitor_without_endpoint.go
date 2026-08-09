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

const KubernetesMonitorWithoutEndpointAnalyzerID = "builtin.kubernetes_monitor_without_endpoint"

type KubernetesMonitorWithoutEndpointAnalyzer struct{}

func NewKubernetesMonitorWithoutEndpointAnalyzer() *KubernetesMonitorWithoutEndpointAnalyzer {
	return &KubernetesMonitorWithoutEndpointAnalyzer{}
}

func (a *KubernetesMonitorWithoutEndpointAnalyzer) ID() string {
	return KubernetesMonitorWithoutEndpointAnalyzerID
}

func (a *KubernetesMonitorWithoutEndpointAnalyzer) Name() string {
	return "Kubernetes Monitor Without Endpoint"
}

func (a *KubernetesMonitorWithoutEndpointAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorWithoutEndpointAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorWithoutEndpointAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesMonitorTarget(target) {
			continue
		}
		if strings.TrimSpace(target.Metadata["endpoint_count"]) != "" && strings.TrimSpace(target.Metadata["endpoint_count"]) != "0" {
			continue
		}

		namespace := kubernetesResourceNamespace(target)
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorWithoutEndpoint",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has no scrape endpoints", kind, target.Name, namespace),
			},
			Recommendation: "为该 ServiceMonitor/PodMonitor 补充 endpoints 或 podMetricsEndpoints，否则即使 selector 匹配服务，也不会产生有效 Prometheus scrape 配置。",
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
