package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusShortAlertOutageToleranceAnalyzerID = "builtin.prometheus_short_alert_outage_tolerance"
	PrometheusAlertForBelowGracePeriodAnalyzerID  = "builtin.prometheus_alert_for_below_grace_period"

	prometheusDefaultAlertOutageToleranceSeconds = int64(3600)
)

type PrometheusAlertStateRestorationAnalyzer struct {
	id   string
	name string
}

func NewPrometheusShortAlertOutageToleranceAnalyzer() *PrometheusAlertStateRestorationAnalyzer {
	return &PrometheusAlertStateRestorationAnalyzer{
		id:   PrometheusShortAlertOutageToleranceAnalyzerID,
		name: "Prometheus Short Alert Outage Tolerance",
	}
}

func NewPrometheusAlertForBelowGracePeriodAnalyzer() *PrometheusAlertStateRestorationAnalyzer {
	return &PrometheusAlertStateRestorationAnalyzer{
		id:   PrometheusAlertForBelowGracePeriodAnalyzerID,
		name: "Prometheus Alert For Below Grace Period",
	}
}

func (a *PrometheusAlertStateRestorationAnalyzer) ID() string      { return a.id }
func (a *PrometheusAlertStateRestorationAnalyzer) Name() string    { return a.name }
func (a *PrometheusAlertStateRestorationAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusAlertStateRestorationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusAlertStateRestorationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataRulesDiscoveryAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAgentMode] == "true" ||
			prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataAlertingRuleCount) <= 0 {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusAlertStateRestorationAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusShortAlertOutageToleranceAnalyzerID:
		tolerance, ok := prometheusAlertRestorationMetadataInt(resource, model.MetadataPrometheusAlertForOutageTolerance)
		if !ok || tolerance <= 0 || tolerance >= prometheusDefaultAlertOutageToleranceSeconds {
			return model.Finding{}, false
		}
		ruleCount := prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataAlertingRuleCount)
		findingType = "PrometheusShortAlertOutageTolerance"
		evidence = fmt.Sprintf("Prometheus has %d local alerting rules but restores pending alert state after outages for only %d seconds, below the official 3600-second default", ruleCount, tolerance)
		recommendation = "将 --rules.alert.for-outage-tolerance 恢复到官方 1h 默认值或经过故障恢复目标验证的更长窗口，并用滚动重启测试确认 pending 告警状态连续。"
		metadata[model.MetadataPrometheusAlertForOutageTolerance] = strconv.FormatInt(tolerance, 10)
		metadata[model.MetadataAlertingRuleCount] = strconv.Itoa(ruleCount)
	case PrometheusAlertForBelowGracePeriodAnalyzerID:
		grace, graceOK := prometheusAlertRestorationMetadataInt(resource, model.MetadataPrometheusAlertForGracePeriod)
		belowCount, countOK := prometheusAlertRestorationMetadataInt(resource, model.MetadataPrometheusAlertForBelowGraceCount)
		if !graceOK || !countOK || grace <= 0 || belowCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusAlertForBelowGracePeriod"
		evidence = fmt.Sprintf("%d local alerting rules have a positive for duration shorter than the explicit %d-second restoration grace period and will not restore pending state after restart", belowCount, grace)
		recommendation = "将 --rules.alert.for-grace-period 调低到关键告警最短 for 时长以下，或在告警语义允许时延长这些规则的 for；随后通过重启演练验证 pending 状态连续性。"
		metadata[model.MetadataPrometheusAlertForGracePeriod] = strconv.FormatInt(grace, 10)
		metadata[model.MetadataPrometheusAlertForBelowGraceCount] = strconv.FormatInt(belowCount, 10)
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategoryReliability,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func prometheusAlertRestorationMetadataInt(resource model.Resource, key string) (int64, bool) {
	value, ok := resource.Metadata[key]
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}
