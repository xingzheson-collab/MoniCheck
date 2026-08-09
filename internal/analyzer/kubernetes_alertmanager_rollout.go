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
	KubernetesInvalidAlertmanagerRolloutConfigurationAnalyzerID  = "builtin.kubernetes_invalid_alertmanager_rollout_configuration"
	KubernetesAlertmanagerHAWithoutSchedulingIsolationAnalyzerID = "builtin.kubernetes_alertmanager_ha_without_scheduling_isolation"
	KubernetesAlertmanagerHAWithoutRolloutDelayAnalyzerID        = "builtin.kubernetes_alertmanager_ha_without_rollout_delay"
)

type KubernetesAlertmanagerRolloutAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerRolloutConfigurationAnalyzer() *KubernetesAlertmanagerRolloutAnalyzer {
	return &KubernetesAlertmanagerRolloutAnalyzer{id: KubernetesInvalidAlertmanagerRolloutConfigurationAnalyzerID, name: "Kubernetes Invalid Alertmanager Rollout Configuration"}
}

func NewKubernetesAlertmanagerHAWithoutSchedulingIsolationAnalyzer() *KubernetesAlertmanagerRolloutAnalyzer {
	return &KubernetesAlertmanagerRolloutAnalyzer{id: KubernetesAlertmanagerHAWithoutSchedulingIsolationAnalyzerID, name: "Kubernetes HA Alertmanager Without Scheduling Isolation"}
}

func NewKubernetesAlertmanagerHAWithoutRolloutDelayAnalyzer() *KubernetesAlertmanagerRolloutAnalyzer {
	return &KubernetesAlertmanagerRolloutAnalyzer{id: KubernetesAlertmanagerHAWithoutRolloutDelayAnalyzerID, name: "Kubernetes HA Alertmanager Without Rollout Delay"}
}

func (a *KubernetesAlertmanagerRolloutAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerRolloutAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerRolloutAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerRolloutAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerRolloutAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_rollout_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerRolloutFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerRolloutFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	invalidSchedulingCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_scheduling_invalid_setting_count")
	minReadyInvalid := resource.Metadata["alertmanager_min_ready_seconds_declared"] == "true" && resource.Metadata["alertmanager_min_ready_seconds_valid"] != "true"
	replicas := alertmanagerStorageMetadataInt64(resource, "alertmanager_replicas")
	switch analyzerID {
	case KubernetesInvalidAlertmanagerRolloutConfigurationAnalyzerID:
		if !minReadyInvalid && invalidSchedulingCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidAlertmanagerRolloutConfiguration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has invalid rollout settings: minReadySeconds invalid=%t, scheduling settings invalid=%d", resource.Name, minReadyInvalid, invalidSchedulingCount)
		recommendation = "将 minReadySeconds 配置为非负 int32，并为 affinity 与 topologySpreadConstraints 使用合法 Kubernetes 对象结构。"
		metadata["alertmanager_min_ready_seconds_invalid"] = fmt.Sprintf("%t", minReadyInvalid)
		metadata["alertmanager_scheduling_invalid_setting_count"] = fmt.Sprintf("%d", invalidSchedulingCount)
	case KubernetesAlertmanagerHAWithoutSchedulingIsolationAnalyzerID:
		if replicas <= 1 || invalidSchedulingCount > 0 || resource.Metadata["alertmanager_ha_scheduling_isolation"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerHAWithoutSchedulingIsolation"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d replicas without pod anti-affinity or topology spread constraints", resource.Name, replicas)
		recommendation = "配置 podAntiAffinity 或 topologySpreadConstraints，将 HA 副本分散到不同节点或可用区，并验证滚动升级和节点故障场景。"
		metadata["alertmanager_replicas"] = fmt.Sprintf("%d", replicas)
	case KubernetesAlertmanagerHAWithoutRolloutDelayAnalyzerID:
		if replicas <= 1 || minReadyInvalid || resource.Metadata["alertmanager_dispatch_delay_version_evaluable"] != "true" || resource.Metadata["alertmanager_dispatch_delay_supported"] != "true" || alertmanagerStorageMetadataInt64(resource, "alertmanager_min_ready_seconds") > 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerHAWithoutRolloutDelay"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q runs version 0.30 or newer with %d replicas and no positive minReadySeconds rollout stabilization window", resource.Name, replicas)
		recommendation = "设置正 minReadySeconds，让新 Pod 稳定 Ready，并在 Alertmanager 0.30+ rollout 后延迟首次聚合 flush，等待 Prometheus 重发告警。"
		metadata["alertmanager_replicas"] = fmt.Sprintf("%d", replicas)
		metadata["alertmanager_min_ready_seconds"] = resource.Metadata["alertmanager_min_ready_seconds"]
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
