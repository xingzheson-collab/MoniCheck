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
	KubernetesInvalidPrometheusRolloutConfigurationAnalyzerID  = "builtin.kubernetes_invalid_prometheus_rollout_configuration"
	KubernetesPrometheusHAWithoutSchedulingIsolationAnalyzerID = "builtin.kubernetes_prometheus_ha_without_scheduling_isolation"
)

type KubernetesPrometheusRolloutAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusRolloutConfigurationAnalyzer() *KubernetesPrometheusRolloutAnalyzer {
	return &KubernetesPrometheusRolloutAnalyzer{id: KubernetesInvalidPrometheusRolloutConfigurationAnalyzerID, name: "Kubernetes Invalid Prometheus Rollout Configuration"}
}

func NewKubernetesPrometheusHAWithoutSchedulingIsolationAnalyzer() *KubernetesPrometheusRolloutAnalyzer {
	return &KubernetesPrometheusRolloutAnalyzer{id: KubernetesPrometheusHAWithoutSchedulingIsolationAnalyzerID, name: "Kubernetes HA Prometheus Without Scheduling Isolation"}
}

func (a *KubernetesPrometheusRolloutAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusRolloutAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusRolloutAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusRolloutAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusRolloutAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_rollout_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusRolloutFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusRolloutFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	invalidSchedulingCount := prometheusStorageMetadataInt64(resource, "prometheus_scheduling_invalid_setting_count")
	minReadyInvalid := resource.Metadata["prometheus_min_ready_seconds_declared"] == "true" && resource.Metadata["prometheus_min_ready_seconds_valid"] != "true"
	desiredPods := prometheusStorageMetadataInt64(resource, "prometheus_desired_pod_count")
	switch analyzerID {
	case KubernetesInvalidPrometheusRolloutConfigurationAnalyzerID:
		if !minReadyInvalid && invalidSchedulingCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidPrometheusRolloutConfiguration"
		evidence = fmt.Sprintf("Kubernetes %s %q has invalid rollout settings: minReadySeconds invalid=%t, scheduling settings invalid=%d", kind, resource.Name, minReadyInvalid, invalidSchedulingCount)
		recommendation = "将 minReadySeconds 配置为非负 int32，并为 affinity 与 topologySpreadConstraints 使用合法 Kubernetes 对象结构。"
		metadata["prometheus_min_ready_seconds_invalid"] = fmt.Sprintf("%t", minReadyInvalid)
		metadata["prometheus_scheduling_invalid_setting_count"] = fmt.Sprintf("%d", invalidSchedulingCount)
	case KubernetesPrometheusHAWithoutSchedulingIsolationAnalyzerID:
		if resource.Metadata["prometheus_rollout_applicable"] != "true" || desiredPods <= 1 || invalidSchedulingCount > 0 || resource.Metadata["prometheus_ha_scheduling_isolation"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesPrometheusHAWithoutSchedulingIsolation"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d desired Pods without pod anti-affinity or topology spread constraints", kind, resource.Name, desiredPods)
		recommendation = "配置 podAntiAffinity 或 topologySpreadConstraints，将 HA 副本/分片分散到不同节点或可用区，并验证滚动升级和节点故障场景。"
		metadata["prometheus_desired_pod_count"] = fmt.Sprintf("%d", desiredPods)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
