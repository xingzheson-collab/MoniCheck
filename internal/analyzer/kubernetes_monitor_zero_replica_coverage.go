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

const KubernetesMonitorZeroReplicaCoverageAnalyzerID = "builtin.kubernetes_monitor_zero_replica_coverage"

type KubernetesMonitorZeroReplicaCoverageAnalyzer struct{}

func NewKubernetesMonitorZeroReplicaCoverageAnalyzer() *KubernetesMonitorZeroReplicaCoverageAnalyzer {
	return &KubernetesMonitorZeroReplicaCoverageAnalyzer{}
}

func (a *KubernetesMonitorZeroReplicaCoverageAnalyzer) ID() string {
	return KubernetesMonitorZeroReplicaCoverageAnalyzerID
}

func (a *KubernetesMonitorZeroReplicaCoverageAnalyzer) Name() string {
	return "Kubernetes Monitor Covered Only By Zero-Replica Prometheus"
}

func (a *KubernetesMonitorZeroReplicaCoverageAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorZeroReplicaCoverageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorZeroReplicaCoverageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if target.Metadata["prometheus_selection_candidate"] != "true" || target.Metadata["prometheus_selected_count"] == "0" || target.Metadata["prometheus_nonzero_selected_count"] != "0" {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorZeroReplicaCoverage",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q is selected only by Prometheus resources whose desired pod count is zero", kind, target.Name, namespace),
			},
			Recommendation: "将至少一个选择该对象的 Prometheus spec.replicas 和 spec.shards 调整为非零值，或让其他可部署的 Prometheus 选择该对象；当前声明不会创建负责采集它的 Prometheus Pod。",
			Metadata: map[string]string{
				"analyzer_id":                       a.ID(),
				"kubernetes_kind":                   kind,
				"namespace":                         namespace,
				"prometheus_selected_count":         strings.TrimSpace(target.Metadata["prometheus_selected_count"]),
				"prometheus_nonzero_selected_count": "0",
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
