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

const KubernetesMonitorNotSelectedAnalyzerID = "builtin.kubernetes_monitor_not_selected"

type KubernetesMonitorNotSelectedAnalyzer struct{}

func NewKubernetesMonitorNotSelectedAnalyzer() *KubernetesMonitorNotSelectedAnalyzer {
	return &KubernetesMonitorNotSelectedAnalyzer{}
}

func (a *KubernetesMonitorNotSelectedAnalyzer) ID() string {
	return KubernetesMonitorNotSelectedAnalyzerID
}

func (a *KubernetesMonitorNotSelectedAnalyzer) Name() string {
	return "Kubernetes Monitor Not Selected By Prometheus"
}

func (a *KubernetesMonitorNotSelectedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorNotSelectedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorNotSelectedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if target.Metadata["prometheus_selection_candidate"] != "true" || target.Metadata["prometheus_selection_evaluable"] != "true" || target.Metadata["prometheus_selected_count"] != "0" {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorNotSelected",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q is not selected by any Prometheus resource in the imported manifests", kind, target.Name, namespace),
			},
			Recommendation: "检查 Prometheus 的对象 selector 与 namespace selector，并让该对象标签和所在 Namespace 标签满足至少一个 Prometheus 实例；未被选择的对象不会生成采集配置。",
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

func isPrometheusOperatorTargetKind(kind string) bool {
	switch kind {
	case "ServiceMonitor", "PodMonitor", "Probe", "ScrapeConfig":
		return true
	default:
		return false
	}
}
