package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesThanosRulerPausedAnalyzerID               = "builtin.kubernetes_thanos_ruler_paused"
	KubernetesThanosRulerWithoutQueryEndpointAnalyzerID = "builtin.kubernetes_thanos_ruler_without_query_endpoint"
)

type KubernetesThanosRulerPausedAnalyzer struct{}
type KubernetesThanosRulerWithoutQueryEndpointAnalyzer struct{}

func NewKubernetesThanosRulerPausedAnalyzer() *KubernetesThanosRulerPausedAnalyzer {
	return &KubernetesThanosRulerPausedAnalyzer{}
}
func NewKubernetesThanosRulerWithoutQueryEndpointAnalyzer() *KubernetesThanosRulerWithoutQueryEndpointAnalyzer {
	return &KubernetesThanosRulerWithoutQueryEndpointAnalyzer{}
}

func (a *KubernetesThanosRulerPausedAnalyzer) ID() string {
	return KubernetesThanosRulerPausedAnalyzerID
}
func (a *KubernetesThanosRulerPausedAnalyzer) Name() string {
	return "Kubernetes ThanosRuler Reconciliation Paused"
}
func (a *KubernetesThanosRulerPausedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerPausedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}
func (a *KubernetesThanosRulerPausedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesThanosRulerDeploymentFindings(ctx, analysis, a.ID(), true)
}

func (a *KubernetesThanosRulerWithoutQueryEndpointAnalyzer) ID() string {
	return KubernetesThanosRulerWithoutQueryEndpointAnalyzerID
}
func (a *KubernetesThanosRulerWithoutQueryEndpointAnalyzer) Name() string {
	return "Kubernetes ThanosRuler Without Query Endpoint"
}
func (a *KubernetesThanosRulerWithoutQueryEndpointAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerWithoutQueryEndpointAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}
func (a *KubernetesThanosRulerWithoutQueryEndpointAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesThanosRulerDeploymentFindings(ctx, analysis, a.ID(), false)
}

func kubernetesThanosRulerDeploymentFindings(ctx context.Context, analysis Context, analyzerID string, pausedCheck bool) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" {
			continue
		}
		if pausedCheck {
			if resource.Metadata["thanos_ruler_paused"] != "true" {
				continue
			}
		} else if resource.Metadata["thanos_ruler_query_endpoint_count"] != "0" || resource.Metadata["thanos_ruler_query_config_declared"] == "true" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findingType := "KubernetesThanosRulerPaused"
		severity := model.SeverityWarning
		evidence := fmt.Sprintf("Kubernetes ThanosRuler %q in namespace %q has spec.paused=true", resource.Name, namespace)
		recommendation := "确认调谐暂停仍是有意维护状态；完成后恢复 spec.paused=false，并验证 StatefulSet、规则配置和 Ruler reload 状态。"
		if !pausedCheck {
			findingType = "KubernetesThanosRulerWithoutQueryEndpoint"
			severity = model.SeverityCritical
			evidence = fmt.Sprintf("Kubernetes ThanosRuler %q in namespace %q declares neither spec.queryEndpoints nor spec.queryConfig", resource.Name, namespace)
			recommendation = "配置至少一个可用的 Thanos Querier 或 Prometheus Query API，优先使用 spec.queryConfig 或 spec.queryEndpoints，并验证 Ruler 查询错误。"
		}
		findings = append(findings, model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": namespace}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}
