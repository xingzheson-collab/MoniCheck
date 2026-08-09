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
	KubernetesInvalidPrometheusPlacementAnalyzerID              = "builtin.kubernetes_invalid_prometheus_placement"
	KubernetesPrometheusBroadTolerationAnalyzerID               = "builtin.kubernetes_prometheus_broad_toleration"
	KubernetesPrometheusIndefiniteNoExecuteTolerationAnalyzerID = "builtin.kubernetes_prometheus_indefinite_no_execute_toleration"
	KubernetesPrometheusCustomSchedulerAnalyzerID               = "builtin.kubernetes_prometheus_custom_scheduler"
)

type KubernetesPrometheusPlacementAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusPlacementAnalyzer() *KubernetesPrometheusPlacementAnalyzer {
	return &KubernetesPrometheusPlacementAnalyzer{id: KubernetesInvalidPrometheusPlacementAnalyzerID, name: "Kubernetes Invalid Prometheus Placement"}
}

func NewKubernetesPrometheusBroadTolerationAnalyzer() *KubernetesPrometheusPlacementAnalyzer {
	return &KubernetesPrometheusPlacementAnalyzer{id: KubernetesPrometheusBroadTolerationAnalyzerID, name: "Kubernetes Prometheus Broad Toleration"}
}

func NewKubernetesPrometheusIndefiniteNoExecuteTolerationAnalyzer() *KubernetesPrometheusPlacementAnalyzer {
	return &KubernetesPrometheusPlacementAnalyzer{id: KubernetesPrometheusIndefiniteNoExecuteTolerationAnalyzerID, name: "Kubernetes Prometheus Indefinite NoExecute Toleration"}
}

func NewKubernetesPrometheusCustomSchedulerAnalyzer() *KubernetesPrometheusPlacementAnalyzer {
	return &KubernetesPrometheusPlacementAnalyzer{id: KubernetesPrometheusCustomSchedulerAnalyzerID, name: "Kubernetes Prometheus Custom Scheduler"}
}

func (a *KubernetesPrometheusPlacementAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusPlacementAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusPlacementAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusPlacementAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusPlacementAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (resource.Metadata["kubernetes_kind"] != "Prometheus" && resource.Metadata["kubernetes_kind"] != "PrometheusAgent") || resource.Metadata["prometheus_placement_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusPlacementFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusPlacementFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	tolerationInvalidCount := prometheusStorageMetadataInt64(resource, "prometheus_toleration_invalid_setting_count")
	nodeSelectorInvalid := resource.Metadata["prometheus_node_selector_declared"] == "true" && resource.Metadata["prometheus_node_selector_valid"] != "true"
	schedulerInvalid := resource.Metadata["prometheus_scheduler_name_declared"] == "true" && resource.Metadata["prometheus_scheduler_name_valid"] != "true"
	priorityClassInvalid := resource.Metadata["prometheus_priority_class_name_declared"] == "true" && resource.Metadata["prometheus_priority_class_name_valid"] != "true"
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	kind := resource.Metadata["kubernetes_kind"]
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusPlacementAnalyzerID:
		if !nodeSelectorInvalid && !schedulerInvalid && !priorityClassInvalid && tolerationInvalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusPlacement"
		evidence = fmt.Sprintf("Kubernetes %s %q has invalid placement settings: nodeSelector invalid=%t, schedulerName invalid=%t, priorityClassName invalid=%t, toleration settings invalid=%d", kind, resource.Name, nodeSelectorInvalid, schedulerInvalid, priorityClassInvalid, tolerationInvalidCount)
		recommendation = "使用合法 Kubernetes nodeSelector 标签、非空 schedulerName/priorityClassName，并按 key/operator/value/effect/tolerationSeconds 约束修正 tolerations。"
		metadata["prometheus_node_selector_invalid"] = fmt.Sprintf("%t", nodeSelectorInvalid)
		metadata["prometheus_scheduler_name_invalid"] = fmt.Sprintf("%t", schedulerInvalid)
		metadata["prometheus_priority_class_name_invalid"] = fmt.Sprintf("%t", priorityClassInvalid)
		metadata["prometheus_toleration_invalid_setting_count"] = fmt.Sprintf("%d", tolerationInvalidCount)
	case KubernetesPrometheusBroadTolerationAnalyzerID:
		count := prometheusStorageMetadataInt64(resource, "prometheus_broad_toleration_count")
		if tolerationInvalidCount > 0 || count == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesPrometheusBroadToleration"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d toleration(s) with an empty key and Exists operator, matching every taint key for the selected effect", kind, resource.Name, count)
		recommendation = "将 toleration 限定到明确的 taint key、effect 和必要 value，并配合 nodeSelector 或 required node affinity 约束到预期节点池。"
		metadata["prometheus_broad_toleration_count"] = fmt.Sprintf("%d", count)
	case KubernetesPrometheusIndefiniteNoExecuteTolerationAnalyzerID:
		count := prometheusStorageMetadataInt64(resource, "prometheus_indefinite_no_execute_toleration_count")
		if tolerationInvalidCount > 0 || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusIndefiniteNoExecuteToleration"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d NoExecute-capable toleration(s) without tolerationSeconds, allowing Pods to remain bound indefinitely", kind, resource.Name, count)
		recommendation = "为 NoExecute toleration 设置符合恢复目标的有限 tolerationSeconds；仅对经过验证且应永久驻留的专用节点场景保留无限容忍。"
		metadata["prometheus_indefinite_no_execute_toleration_count"] = fmt.Sprintf("%d", count)
	case KubernetesPrometheusCustomSchedulerAnalyzerID:
		if resource.Metadata["prometheus_scheduler_name_valid"] != "true" || resource.Metadata["prometheus_custom_scheduler"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusCustomScheduler"
		evidence = fmt.Sprintf("Kubernetes %s %q delegates Pod placement to an explicit non-default scheduler", kind, resource.Name)
		recommendation = "确认自定义 scheduler 高可用、升级兼容、调度失败告警和回退到 default-scheduler 的流程，并验证其遵守资源、亲和性、污点及拓扑约束。"
		metadata["prometheus_custom_scheduler"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
