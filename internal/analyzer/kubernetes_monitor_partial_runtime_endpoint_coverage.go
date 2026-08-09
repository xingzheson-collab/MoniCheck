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

const KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzerID = "builtin.kubernetes_monitor_partial_runtime_endpoint_coverage"

type KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer struct{}

func NewKubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer() *KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer {
	return &KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer{}
}

func (a *KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer) ID() string {
	return KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzerID
}

func (a *KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer) Name() string {
	return "Kubernetes Monitor Partial Runtime Endpoint Coverage"
}

func (a *KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		if target.Source.System != "kubernetes" || target.Status != model.ResourceStatusActive || (kind != "ServiceMonitor" && kind != "PodMonitor") {
			continue
		}
		runtimeTargets, targetErr := strconv.Atoi(strings.TrimSpace(target.Metadata[model.MetadataRuntimeTargetCount]))
		missingCount, missingErr := strconv.Atoi(strings.TrimSpace(target.Metadata[model.MetadataRuntimeMissingEndpointCount]))
		if target.Metadata[model.MetadataRuntimeEndpointEvaluable] != "true" || targetErr != nil || runtimeTargets <= 0 || missingErr != nil || missingCount <= 0 {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		expectedCount := strings.TrimSpace(target.Metadata["endpoint_count"])
		coveredCount := strings.TrimSpace(target.Metadata[model.MetadataRuntimeEndpointCount])
		missingEndpoints := strings.TrimSpace(target.Metadata[model.MetadataRuntimeMissingEndpoints])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorPartialRuntimeEndpointCoverage",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q declares %s endpoints but only %s endpoint indexes have live runtime targets; missing indexes: %s", kind, target.Name, namespace, expectedCount, coveredCount, missingEndpoints),
			},
			Recommendation: "逐项检查缺失 endpoint 的 port/targetPort、path、scheme、TLS/auth 配置、relabeling 和目标 Service/Pod 端口，并确认对应 endpoint 索引出现在 Prometheus /api/v1/targets。",
			Metadata: map[string]string{
				"analyzer_id":                       a.ID(),
				"kubernetes_kind":                   kind,
				"namespace":                         namespace,
				"endpoint_count":                    expectedCount,
				"prometheus_runtime_endpoint_count": coveredCount,
				"prometheus_runtime_missing_endpoint_count": strconv.Itoa(missingCount),
				"prometheus_runtime_missing_endpoints":      missingEndpoints,
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
