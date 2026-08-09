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

const KubernetesServiceWithoutMonitorAnalyzerID = "builtin.kubernetes_service_without_monitor"

type KubernetesServiceWithoutMonitorAnalyzer struct{}

func NewKubernetesServiceWithoutMonitorAnalyzer() *KubernetesServiceWithoutMonitorAnalyzer {
	return &KubernetesServiceWithoutMonitorAnalyzer{}
}

func (a *KubernetesServiceWithoutMonitorAnalyzer) ID() string {
	return KubernetesServiceWithoutMonitorAnalyzerID
}

func (a *KubernetesServiceWithoutMonitorAnalyzer) Name() string {
	return "Kubernetes Service Without Monitor"
}

func (a *KubernetesServiceWithoutMonitorAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesServiceWithoutMonitorAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService}
}

func (a *KubernetesServiceWithoutMonitorAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Source.System != "kubernetes" || service.Status != model.ResourceStatusActive {
			continue
		}
		monitors := kubernetesMonitorsForService(service.ID, analysis)
		if len(monitors) > 0 {
			continue
		}

		namespace := strings.TrimSpace(service.Metadata["namespace"])
		if namespace == "" {
			namespace = "default"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "KubernetesServiceWithoutMonitor",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{
				ID:   service.ID,
				Type: service.Type,
				Name: service.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes Service %q in namespace %q is not referenced by any ServiceMonitor or PodMonitor", service.Name, namespace),
			},
			Recommendation: "为该 Kubernetes Service 补充 ServiceMonitor/PodMonitor，或确认它不需要被 Prometheus 采集；否则服务指标可能不会进入监控治理和告警链路。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"namespace":   namespace,
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

func kubernetesMonitorsForService(serviceID string, analysis Context) []model.Resource {
	monitors := make([]model.Resource, 0)
	seen := make(map[string]bool)
	for _, relationship := range analysis.Graph.Incoming(serviceID) {
		if relationship.Type != model.RelationshipReferences || seen[relationship.FromID] {
			continue
		}
		monitor, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || monitor.Source.System != "kubernetes" || monitor.Type != model.ResourceTypeTarget || monitor.Status != model.ResourceStatusActive {
			continue
		}
		kind := strings.TrimSpace(monitor.Metadata["kubernetes_kind"])
		if kind != "ServiceMonitor" && kind != "PodMonitor" {
			continue
		}
		seen[monitor.ID] = true
		monitors = append(monitors, monitor)
	}
	return monitors
}
