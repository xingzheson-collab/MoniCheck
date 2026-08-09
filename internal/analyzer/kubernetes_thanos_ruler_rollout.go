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
	KubernetesInvalidThanosRulerRolloutConfigurationAnalyzerID  = "builtin.kubernetes_invalid_thanos_ruler_rollout_configuration"
	KubernetesThanosRulerHAWithoutSchedulingIsolationAnalyzerID = "builtin.kubernetes_thanos_ruler_ha_without_scheduling_isolation"
)

type KubernetesThanosRulerRolloutAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerRolloutConfigurationAnalyzer() *KubernetesThanosRulerRolloutAnalyzer {
	return &KubernetesThanosRulerRolloutAnalyzer{id: KubernetesInvalidThanosRulerRolloutConfigurationAnalyzerID, name: "Kubernetes Invalid ThanosRuler Rollout Configuration"}
}

func NewKubernetesThanosRulerHAWithoutSchedulingIsolationAnalyzer() *KubernetesThanosRulerRolloutAnalyzer {
	return &KubernetesThanosRulerRolloutAnalyzer{id: KubernetesThanosRulerHAWithoutSchedulingIsolationAnalyzerID, name: "Kubernetes HA ThanosRuler Without Scheduling Isolation"}
}

func (a *KubernetesThanosRulerRolloutAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerRolloutAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerRolloutAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerRolloutAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerRolloutAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_rollout_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerRolloutFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerRolloutFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	invalidSchedulingCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_scheduling_invalid_setting_count")
	minReadyInvalid := resource.Metadata["thanos_ruler_min_ready_seconds_declared"] == "true" && resource.Metadata["thanos_ruler_min_ready_seconds_valid"] != "true"
	replicas := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_replicas")
	switch analyzerID {
	case KubernetesInvalidThanosRulerRolloutConfigurationAnalyzerID:
		if !minReadyInvalid && invalidSchedulingCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerRolloutConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has invalid rollout settings: minReadySeconds invalid=%t, scheduling settings invalid=%d", resource.Name, minReadyInvalid, invalidSchedulingCount)
		recommendation = "将 minReadySeconds 配置为非负 int32，并为 affinity 与 topologySpreadConstraints 使用合法 Kubernetes 对象结构。"
		metadata["thanos_ruler_min_ready_seconds_invalid"] = fmt.Sprintf("%t", minReadyInvalid)
		metadata["thanos_ruler_scheduling_invalid_setting_count"] = fmt.Sprintf("%d", invalidSchedulingCount)
	case KubernetesThanosRulerHAWithoutSchedulingIsolationAnalyzerID:
		if replicas <= 1 || invalidSchedulingCount > 0 || resource.Metadata["thanos_ruler_ha_scheduling_isolation"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesThanosRulerHAWithoutSchedulingIsolation"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d replicas without pod anti-affinity or topology spread constraints", resource.Name, replicas)
		recommendation = "配置 podAntiAffinity 或 topologySpreadConstraints，将 HA 规则执行副本分散到不同节点或可用区，并验证滚动升级和节点故障场景。"
		metadata["thanos_ruler_replicas"] = fmt.Sprintf("%d", replicas)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
