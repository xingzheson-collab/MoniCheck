package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesPrometheusAgentWithoutRemoteWriteAnalyzerID = "builtin.kubernetes_prometheus_agent_without_remote_write"

type KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer struct{}

func NewKubernetesPrometheusAgentWithoutRemoteWriteAnalyzer() *KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer {
	return &KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer{}
}

func (a *KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer) ID() string {
	return KubernetesPrometheusAgentWithoutRemoteWriteAnalyzerID
}
func (a *KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer) Name() string {
	return "Kubernetes PrometheusAgent Without Remote Write"
}
func (a *KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusAgentWithoutRemoteWriteAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "PrometheusAgent" || resource.Metadata["prometheus_remote_write_count"] != "0" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesPrometheusAgentWithoutRemoteWrite",
			Severity: model.SeverityCritical, Category: model.FindingCategoryConfiguration,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Kubernetes PrometheusAgent %q in namespace %q has no spec.remoteWrite destination", resource.Name, namespace)},
			Recommendation: "至少配置一个可用的 spec.remoteWrite 目标，并验证认证、队列积压和远端写入错误；Agent 模式不提供本地查询或规则评估能力。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "kubernetes_kind": "PrometheusAgent", "namespace": namespace, "prometheus_remote_write_count": "0"},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
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
