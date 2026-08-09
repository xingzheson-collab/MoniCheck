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

const KubernetesPrometheusPausedAnalyzerID = "builtin.kubernetes_prometheus_paused"

type KubernetesPrometheusPausedAnalyzer struct{}

func NewKubernetesPrometheusPausedAnalyzer() *KubernetesPrometheusPausedAnalyzer {
	return &KubernetesPrometheusPausedAnalyzer{}
}

func (a *KubernetesPrometheusPausedAnalyzer) ID() string {
	return KubernetesPrometheusPausedAnalyzerID
}

func (a *KubernetesPrometheusPausedAnalyzer) Name() string {
	return "Kubernetes Prometheus Reconciliation Paused"
}

func (a *KubernetesPrometheusPausedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesPrometheusPausedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusPausedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_paused"] != "true" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "KubernetesPrometheusPaused",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has spec.paused=true; the Operator will not reconcile underlying objects except deletions", kind, resource.Name, namespace),
			},
			Recommendation: "确认调谐暂停仍是有意的维护状态；完成维护后将 spec.paused 恢复为 false，并验证 StatefulSet、配置 Secret 与 Prometheus reload 状态，避免声明配置长期漂移。",
			Metadata: map[string]string{
				"analyzer_id":                  a.ID(),
				"kubernetes_kind":              kind,
				"namespace":                    namespace,
				"prometheus_desired_pod_count": strings.TrimSpace(resource.Metadata["prometheus_desired_pod_count"]),
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
