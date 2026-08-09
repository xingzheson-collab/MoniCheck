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

const KubernetesMonitorWithoutMatchedServiceAnalyzerID = "builtin.kubernetes_monitor_without_matched_service"

type KubernetesMonitorWithoutMatchedServiceAnalyzer struct{}

func NewKubernetesMonitorWithoutMatchedServiceAnalyzer() *KubernetesMonitorWithoutMatchedServiceAnalyzer {
	return &KubernetesMonitorWithoutMatchedServiceAnalyzer{}
}

func (a *KubernetesMonitorWithoutMatchedServiceAnalyzer) ID() string {
	return KubernetesMonitorWithoutMatchedServiceAnalyzerID
}

func (a *KubernetesMonitorWithoutMatchedServiceAnalyzer) Name() string {
	return "Kubernetes Monitor Without Matched Service"
}

func (a *KubernetesMonitorWithoutMatchedServiceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorWithoutMatchedServiceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorWithoutMatchedServiceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesServiceMonitorTarget(target) || strings.TrimSpace(target.Metadata["selector"]) == "" {
			continue
		}
		if len(kubernetesServicesForMonitor(target.ID, analysis)) > 0 {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorWithoutMatchedService",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has selector %q but does not reference any Service", kind, target.Name, namespace, target.Metadata["selector"]),
			},
			Recommendation: "检查该 ServiceMonitor/PodMonitor 的 selector、namespaceSelector 和目标 Service 标签是否一致；无匹配服务时 Prometheus Operator 不会为它生成有效 scrape 目标。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"kubernetes_kind": kind,
				"namespace":       namespace,
				"selector":        target.Metadata["selector"],
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

func kubernetesServicesForMonitor(monitorID string, analysis Context) []model.Resource {
	services := make([]model.Resource, 0)
	seen := make(map[string]bool)
	for _, relationship := range analysis.Graph.Outgoing(monitorID) {
		if relationship.Type != model.RelationshipReferences || seen[relationship.ToID] {
			continue
		}
		service, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok || service.Source.System != "kubernetes" || service.Type != model.ResourceTypeService || service.Status != model.ResourceStatusActive {
			continue
		}
		seen[service.ID] = true
		services = append(services, service)
	}
	return services
}

func isKubernetesServiceMonitorTarget(resource model.Resource) bool {
	return isKubernetesMonitorTarget(resource) && strings.TrimSpace(resource.Metadata["kubernetes_kind"]) == "ServiceMonitor"
}
