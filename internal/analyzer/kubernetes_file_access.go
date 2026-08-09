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

const KubernetesMonitorArbitraryFileAccessAnalyzerID = "builtin.kubernetes_monitor_arbitrary_file_access"

type KubernetesMonitorArbitraryFileAccessAnalyzer struct{}

func NewKubernetesMonitorArbitraryFileAccessAnalyzer() *KubernetesMonitorArbitraryFileAccessAnalyzer {
	return &KubernetesMonitorArbitraryFileAccessAnalyzer{}
}

func (a *KubernetesMonitorArbitraryFileAccessAnalyzer) ID() string {
	return KubernetesMonitorArbitraryFileAccessAnalyzerID
}
func (a *KubernetesMonitorArbitraryFileAccessAnalyzer) Name() string {
	return "Kubernetes Monitor Arbitrary File Access"
}
func (a *KubernetesMonitorArbitraryFileAccessAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorArbitraryFileAccessAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorArbitraryFileAccessAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "ServiceMonitor" && kind != "PodMonitor" && kind != "Probe") {
			continue
		}
		referenceCount := kubernetesFileAccessMetadataInt(resource, "monitor_arbitrary_file_reference_count")
		selectedCount := kubernetesFileAccessMetadataInt(resource, "prometheus_selected_count")
		unprotectedCount := kubernetesFileAccessMetadataInt(resource, "prometheus_arbitrary_file_access_unprotected_count")
		if referenceCount == 0 || selectedCount == 0 || unprotectedCount == 0 {
			continue
		}
		metadata := map[string]string{
			"analyzer_id":                a.ID(),
			"kubernetes_kind":            kind,
			"namespace":                  resource.Metadata["namespace"],
			"file_reference_count":       strconv.Itoa(referenceCount),
			"unprotected_workload_count": strconv.Itoa(unprotectedCount),
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "KubernetesMonitorArbitraryFileAccess",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategorySecurity,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Kubernetes %s %q declares %d arbitrary file reference(s) and %d selecting workload(s) allow them", kind, resource.Name, referenceCount, unprotectedCount)},
			Recommendation: "在所有选中该 Monitor 的 Prometheus/Agent 设置 arbitraryFSAccessThroughSMs.deny=true，并用 Secret/ConfigMap selector 或 authorization 替代 bearerTokenFile 和 TLS file paths。",
			Metadata:       metadata,
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesFileAccessMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil {
		return 0
	}
	return value
}
