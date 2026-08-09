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

const KubernetesMonitorWithoutEndpointPortAnalyzerID = "builtin.kubernetes_monitor_without_endpoint_port"

type KubernetesMonitorWithoutEndpointPortAnalyzer struct{}

func NewKubernetesMonitorWithoutEndpointPortAnalyzer() *KubernetesMonitorWithoutEndpointPortAnalyzer {
	return &KubernetesMonitorWithoutEndpointPortAnalyzer{}
}

func (a *KubernetesMonitorWithoutEndpointPortAnalyzer) ID() string {
	return KubernetesMonitorWithoutEndpointPortAnalyzerID
}

func (a *KubernetesMonitorWithoutEndpointPortAnalyzer) Name() string {
	return "Kubernetes Monitor Without Endpoint Port"
}

func (a *KubernetesMonitorWithoutEndpointPortAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorWithoutEndpointPortAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorWithoutEndpointPortAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if strings.TrimSpace(target.Metadata["endpoint_count"]) == "" || strings.TrimSpace(target.Metadata["endpoint_count"]) == "0" {
			continue
		}
		if strings.TrimSpace(target.Metadata["endpoint_ports"]) != "" {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorWithoutEndpointPort",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has endpoint entries without port or targetPort metadata", kind, target.Name, namespace),
			},
			Recommendation: "为每个 ServiceMonitor/PodMonitor endpoint 补充 port 或 targetPort，确保 Prometheus Operator 可以解析要采集的服务端口。",
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
