package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusWithoutActiveAlertmanagerAnalyzerID  = "builtin.prometheus_without_active_alertmanager"
	PrometheusDroppedAlertmanagerTargetsAnalyzerID = "builtin.prometheus_dropped_alertmanager_targets"
	PrometheusSingleAlertmanagerTargetAnalyzerID   = "builtin.prometheus_single_alertmanager_target"
)

type PrometheusAlertmanagerDeliveryAnalyzer struct {
	id   string
	name string
}

func NewPrometheusWithoutActiveAlertmanagerAnalyzer() *PrometheusAlertmanagerDeliveryAnalyzer {
	return &PrometheusAlertmanagerDeliveryAnalyzer{id: PrometheusWithoutActiveAlertmanagerAnalyzerID, name: "Prometheus Without Active Alertmanager"}
}

func NewPrometheusDroppedAlertmanagerTargetsAnalyzer() *PrometheusAlertmanagerDeliveryAnalyzer {
	return &PrometheusAlertmanagerDeliveryAnalyzer{id: PrometheusDroppedAlertmanagerTargetsAnalyzerID, name: "Prometheus Dropped Alertmanager Targets"}
}

func NewPrometheusSingleAlertmanagerTargetAnalyzer() *PrometheusAlertmanagerDeliveryAnalyzer {
	return &PrometheusAlertmanagerDeliveryAnalyzer{id: PrometheusSingleAlertmanagerTargetAnalyzerID, name: "Prometheus Single Alertmanager Target"}
}

func (a *PrometheusAlertmanagerDeliveryAnalyzer) ID() string      { return a.id }
func (a *PrometheusAlertmanagerDeliveryAnalyzer) Name() string    { return a.name }
func (a *PrometheusAlertmanagerDeliveryAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusAlertmanagerDeliveryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusAlertmanagerDeliveryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataRulesDiscoveryAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAMDiscoveryAvailable] != "true" {
			continue
		}
		alertingRules := prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataAlertingRuleCount)
		if alertingRules == 0 {
			continue
		}
		active := prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataPrometheusActiveAMCount)
		dropped := prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataPrometheusDroppedAMCount)
		if finding, ok := a.finding(resource, alertingRules, active, dropped, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *PrometheusAlertmanagerDeliveryAnalyzer) finding(resource model.Resource, alertingRules int, active int, dropped int, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityWarning
	evidence := ""
	recommendation := ""
	switch a.id {
	case PrometheusWithoutActiveAlertmanagerAnalyzerID:
		if active != 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusWithoutActiveAlertmanager"
		severity = model.SeverityCritical
		evidence = fmt.Sprintf("Prometheus has %d alerting rule(s) but discovered no active Alertmanager target", alertingRules)
		recommendation = "检查 Prometheus alerting 配置、服务发现和网络连通性，确保至少一个 Alertmanager 目标处于 active 状态。"
	case PrometheusDroppedAlertmanagerTargetsAnalyzerID:
		if dropped == 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusDroppedAlertmanagerTargets"
		evidence = fmt.Sprintf("Prometheus reports %d dropped Alertmanager target(s) and %d active target(s)", dropped, active)
		recommendation = "检查 Alertmanager 服务发现、relabel 配置和目标标签，移除错误目标并恢复预期实例。"
	case PrometheusSingleAlertmanagerTargetAnalyzerID:
		if active != 1 {
			return model.Finding{}, false
		}
		findingType = "PrometheusSingleAlertmanagerTarget"
		evidence = "Prometheus discovered exactly one active Alertmanager target"
		recommendation = "让 Prometheus 直接发现并向至少两个 Alertmanager 实例发送告警，降低通知链路的单点风险。"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       model.FindingCategoryReliability,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata: map[string]string{
			"analyzer_id":          a.id,
			"alerting_rule_count":  strconv.Itoa(alertingRules),
			"active_target_count":  strconv.Itoa(active),
			"dropped_target_count": strconv.Itoa(dropped),
		},
		Status:    model.FindingStatusOpen,
		CreatedAt: now,
		UpdatedAt: now,
	}, true
}

func prometheusDeliveryMetadataInt(metadata map[string]string, key string) int {
	value, _ := strconv.Atoi(metadata[key])
	return value
}
