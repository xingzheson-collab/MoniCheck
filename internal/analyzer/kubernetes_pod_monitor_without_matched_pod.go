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

const KubernetesPodMonitorWithoutMatchedPodAnalyzerID = "builtin.kubernetes_pod_monitor_without_matched_pod"

type KubernetesPodMonitorWithoutMatchedPodAnalyzer struct{}

func NewKubernetesPodMonitorWithoutMatchedPodAnalyzer() *KubernetesPodMonitorWithoutMatchedPodAnalyzer {
	return &KubernetesPodMonitorWithoutMatchedPodAnalyzer{}
}

func (a *KubernetesPodMonitorWithoutMatchedPodAnalyzer) ID() string {
	return KubernetesPodMonitorWithoutMatchedPodAnalyzerID
}

func (a *KubernetesPodMonitorWithoutMatchedPodAnalyzer) Name() string {
	return "Kubernetes PodMonitor Without Matched Pod"
}

func (a *KubernetesPodMonitorWithoutMatchedPodAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesPodMonitorWithoutMatchedPodAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesPodMonitorWithoutMatchedPodAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if !isKubernetesPodMonitorTarget(target) || strings.TrimSpace(target.Metadata["selector"]) == "" {
			continue
		}
		if len(kubernetesPodsForMonitor(target.ID, analysis)) > 0 {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesPodMonitorWithoutMatchedPod",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Kubernetes PodMonitor %q in namespace %q has selector %q but does not reference any Pod", target.Name, namespace, target.Metadata["selector"]),
			},
			Recommendation: "检查该 PodMonitor 的 selector、namespaceSelector 和目标 Pod 标签是否一致；无匹配 Pod 时 Prometheus Operator 不会为它生成有效 scrape 目标。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"kubernetes_kind": "PodMonitor",
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

func kubernetesPodsForMonitor(monitorID string, analysis Context) []model.Resource {
	pods := make([]model.Resource, 0)
	seen := make(map[string]bool)
	for _, relationship := range analysis.Graph.Outgoing(monitorID) {
		if relationship.Type != model.RelationshipReferences || seen[relationship.ToID] {
			continue
		}
		pod, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok || pod.Source.System != "kubernetes" || pod.Type != model.ResourceTypeInstance || pod.Metadata["kubernetes_kind"] != "Pod" || pod.Status != model.ResourceStatusActive {
			continue
		}
		seen[pod.ID] = true
		pods = append(pods, pod)
	}
	return pods
}

func isKubernetesPodMonitorTarget(resource model.Resource) bool {
	return isKubernetesMonitorTarget(resource) && strings.TrimSpace(resource.Metadata["kubernetes_kind"]) == "PodMonitor"
}
