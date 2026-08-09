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

const KubernetesMonitorMissingRuntimeTargetAnalyzerID = "builtin.kubernetes_monitor_missing_runtime_target"

type KubernetesMonitorMissingRuntimeTargetAnalyzer struct{}

func NewKubernetesMonitorMissingRuntimeTargetAnalyzer() *KubernetesMonitorMissingRuntimeTargetAnalyzer {
	return &KubernetesMonitorMissingRuntimeTargetAnalyzer{}
}

func (a *KubernetesMonitorMissingRuntimeTargetAnalyzer) ID() string {
	return KubernetesMonitorMissingRuntimeTargetAnalyzerID
}

func (a *KubernetesMonitorMissingRuntimeTargetAnalyzer) Name() string {
	return "Kubernetes Monitor Missing From Prometheus Runtime Targets"
}

func (a *KubernetesMonitorMissingRuntimeTargetAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorMissingRuntimeTargetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorMissingRuntimeTargetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		if target.Source.System != "kubernetes" || target.Status != model.ResourceStatusActive || !isPrometheusOperatorTargetKind(kind) {
			continue
		}
		if target.Metadata[model.MetadataRuntimeCoverageEvaluable] != "true" || target.Metadata[model.MetadataRuntimeTargetCount] != "0" || target.Metadata[model.MetadataRuntimeDroppedTargetCount] != "0" || target.Metadata["prometheus_nonzero_selected_count"] == "0" {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorMissingRuntimeTarget",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q is selected by a nonzero-replica Prometheus but has no matching live target pool in the successfully queried Prometheus-compatible runtimes", kind, target.Name, namespace),
			},
			Recommendation: "检查 Prometheus Operator 事件和生成配置、monitor selector/endpoint、目标 Service 或 Pod、Prometheus RBAC 以及 config-reloader 状态；修复后确认 /api/v1/targets 出现对应 Operator scrape pool。",
			Metadata: map[string]string{
				"analyzer_id":                       a.ID(),
				"kubernetes_kind":                   kind,
				"namespace":                         namespace,
				"prometheus_runtime_coverage_scope": strings.TrimSpace(target.Metadata[model.MetadataRuntimeCoverageScope]),
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
