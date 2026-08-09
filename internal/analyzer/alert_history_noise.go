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
	NoisyAlertRuleAnalyzerID               = "builtin.noisy_alert_rule"
	FlappingAlertRuleAnalyzerID            = "builtin.flapping_alert_rule"
	PoorAlertRecoveryAnalyzerID            = "builtin.poor_alert_recovery"
	AlertNotificationStormID               = "builtin.alert_notification_storm"
	DormantAlertRuleAnalyzerID             = "builtin.dormant_alert_rule"
	SlowAlertRecoveryAnalyzerID            = "builtin.slow_alert_recovery"
	RecoveryNotificationDisabledAnalyzerID = "builtin.recovery_notification_disabled"
	AlertSeverityDriftAnalyzerID           = "builtin.alert_severity_drift"
	AlertRoutingDriftAnalyzerID            = "builtin.alert_routing_drift"

	defaultNoisyAlertEventThreshold    = 20
	defaultFlappingShortLivedThreshold = 5
	defaultFlappingShortLivedRatio     = 0.5
	defaultPoorRecoveryEventThreshold  = 10
	defaultPoorRecoveryRatioThreshold  = 0.5
	defaultNotificationStormThreshold  = 50
	defaultNotificationsPerEvent       = 3.0
	defaultDormantAlertMinimumWindow   = 24
	defaultSlowAlertRecoveryThreshold  = time.Hour
	defaultSlowAlertRecoveryMinimum    = 3
	defaultRecoveryNotificationMinimum = 3
)

type AlertRoutingDriftAnalyzer struct{}

func NewAlertRoutingDriftAnalyzer() *AlertRoutingDriftAnalyzer { return &AlertRoutingDriftAnalyzer{} }
func (a *AlertRoutingDriftAnalyzer) ID() string                { return AlertRoutingDriftAnalyzerID }
func (a *AlertRoutingDriftAnalyzer) Name() string              { return "Alert Routing Drift" }
func (a *AlertRoutingDriftAnalyzer) Version() string           { return "0.1.0" }
func (a *AlertRoutingDriftAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *AlertRoutingDriftAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		observed := historyInt(resource, "history_notification_route_observed_count")
		variants := historyInt(resource, "history_notification_route_variant_count")
		if resource.Status != model.ResourceStatusActive || resource.Metadata["disabled"] == "true" || resource.Metadata["history_observed"] != "true" || observed < 2 || variants <= 1 {
			continue
		}
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "AlertRoutingDrift",
			Severity: model.SeverityWarning, Category: model.FindingCategoryConfiguration,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q used %d distinct notification-rule sets across %d explicitly observed historical events (sampled=%t)", resource.Name, variants, observed, sampled)},
			Recommendation: "确认通知路由变更经过评审，并核对当前通知规则、订阅和升级链路；移除临时或重复路由，避免同一告警在不同时间投递到不一致的接收方。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "route_variant_count": strconv.Itoa(variants),
				"observed_event_count": strconv.Itoa(observed), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type AlertSeverityDriftAnalyzer struct{}

func NewAlertSeverityDriftAnalyzer() *AlertSeverityDriftAnalyzer {
	return &AlertSeverityDriftAnalyzer{}
}
func (a *AlertSeverityDriftAnalyzer) ID() string      { return AlertSeverityDriftAnalyzerID }
func (a *AlertSeverityDriftAnalyzer) Name() string    { return "Alert Severity Drift" }
func (a *AlertSeverityDriftAnalyzer) Version() string { return "0.1.0" }
func (a *AlertSeverityDriftAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *AlertSeverityDriftAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		variants := historyInt(resource, "history_severity_variant_count")
		if resource.Status != model.ResourceStatusActive || resource.Metadata["disabled"] == "true" || resource.Metadata["history_observed"] != "true" || variants <= 1 {
			continue
		}
		events := historyInt(resource, "history_event_count")
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "AlertSeverityDrift",
			Severity: model.SeverityWarning, Category: model.FindingCategoryConfiguration,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q produced %d distinct severity values across %d historical events (sampled=%t)", resource.Name, variants, events, sampled)},
			Recommendation: "确认严重级别变更是否经过评审，并统一当前规则、通知路由和升级策略；如历史漂移来自临时变更，应验证配置已稳定并清理遗留路由。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "severity_variant_count": strconv.Itoa(variants),
				"event_count": strconv.Itoa(events), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type RecoveryNotificationDisabledAnalyzer struct{}

func NewRecoveryNotificationDisabledAnalyzer() *RecoveryNotificationDisabledAnalyzer {
	return &RecoveryNotificationDisabledAnalyzer{}
}
func (a *RecoveryNotificationDisabledAnalyzer) ID() string {
	return RecoveryNotificationDisabledAnalyzerID
}
func (a *RecoveryNotificationDisabledAnalyzer) Name() string {
	return "Recovery Notification Disabled"
}
func (a *RecoveryNotificationDisabledAnalyzer) Version() string { return "0.1.0" }
func (a *RecoveryNotificationDisabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *RecoveryNotificationDisabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	minimum := intConfig(analysis.Config, "recovery_notification_minimum_events", defaultRecoveryNotificationMinimum)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		observed := historyInt(resource, "history_recovery_notification_observed_count")
		disabled := historyInt(resource, "history_recovery_notification_disabled_count")
		if resource.Status != model.ResourceStatusActive || resource.Metadata["disabled"] == "true" || resource.Metadata["history_observed"] != "true" || observed < minimum || disabled != observed {
			continue
		}
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "RecoveryNotificationDisabled",
			Severity: model.SeverityWarning, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q had recovery notifications disabled for all %d observed recovered events (minimum %d, sampled=%t)", resource.Name, observed, minimum, sampled)},
			Recommendation: "启用恢复通知，或确认下游事件平台会可靠地自动关闭事件；恢复消息应沿用告警分组与路由上下文，避免值班人员持续认为故障未恢复。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "observed_recovered_events": strconv.Itoa(observed),
				"disabled_recovery_notifications": strconv.Itoa(disabled), "minimum_events": strconv.Itoa(minimum), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type DormantAlertRuleAnalyzer struct{}

func NewDormantAlertRuleAnalyzer() *DormantAlertRuleAnalyzer { return &DormantAlertRuleAnalyzer{} }
func (a *DormantAlertRuleAnalyzer) ID() string               { return DormantAlertRuleAnalyzerID }
func (a *DormantAlertRuleAnalyzer) Name() string             { return "Dormant Alert Rule" }
func (a *DormantAlertRuleAnalyzer) Version() string          { return "0.1.0" }
func (a *DormantAlertRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *DormantAlertRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	minimumWindow := intConfig(analysis.Config, "dormant_alert_minimum_window_hours", defaultDormantAlertMinimumWindow)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		window := historyInt(resource, "history_window_hours")
		if resource.Status != model.ResourceStatusActive || resource.Metadata["disabled"] == "true" || resource.Metadata["history_observed"] != "true" || resource.Metadata["history_events_truncated"] == "true" || window < minimumWindow || historyInt(resource, "history_event_count") != 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "DormantAlertRule",
			Severity: model.SeverityWarning, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("active alert rule %q had no trigger events in a complete %d-hour observation window (minimum %d hours)", resource.Name, window, minimumWindow)},
			Recommendation: "确认规则查询仍能返回预期数据并使用正确阈值；结合业务故障演练或历史事件验证覆盖度，确认长期无触发且无保留价值后再归档规则。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "window_hours": strconv.Itoa(window),
				"minimum_window_hours": strconv.Itoa(minimumWindow), "event_count": "0"},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type SlowAlertRecoveryAnalyzer struct{}

func NewSlowAlertRecoveryAnalyzer() *SlowAlertRecoveryAnalyzer { return &SlowAlertRecoveryAnalyzer{} }
func (a *SlowAlertRecoveryAnalyzer) ID() string                { return SlowAlertRecoveryAnalyzerID }
func (a *SlowAlertRecoveryAnalyzer) Name() string              { return "Slow Alert Recovery" }
func (a *SlowAlertRecoveryAnalyzer) Version() string           { return "0.1.0" }
func (a *SlowAlertRecoveryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *SlowAlertRecoveryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	threshold := durationConfig(analysis.Config, "slow_alert_recovery_threshold", defaultSlowAlertRecoveryThreshold)
	minimum := intConfig(analysis.Config, "slow_alert_recovery_minimum_events", defaultSlowAlertRecoveryMinimum)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		recovered := historyInt(resource, "history_recovered_count")
		averageSeconds := historyInt(resource, "history_average_duration_seconds")
		if resource.Status != model.ResourceStatusActive || resource.Metadata["disabled"] == "true" || resource.Metadata["history_observed"] != "true" || recovered < minimum || time.Duration(averageSeconds)*time.Second < threshold {
			continue
		}
		maxSeconds := historyInt(resource, "history_max_duration_seconds")
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "SlowAlertRecovery",
			Severity: model.SeverityWarning, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q averaged %s to recover across %d events (threshold %s, maximum %s, sampled=%t)", resource.Name, (time.Duration(averageSeconds) * time.Second).String(), recovered, threshold.String(), (time.Duration(maxSeconds) * time.Second).String(), sampled)},
			Recommendation: "检查恢复条件、查询窗口和数据延迟，确认恢复信号是否过于保守或缺失；为长故障补充分级升级和明确的恢复验证，减少事件长期占用值班队列。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "recovered_count": strconv.Itoa(recovered),
				"average_duration_seconds": strconv.Itoa(averageSeconds), "maximum_duration_seconds": strconv.Itoa(maxSeconds),
				"threshold_seconds": strconv.FormatInt(int64(threshold/time.Second), 10), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type NoisyAlertRuleAnalyzer struct{}

func NewNoisyAlertRuleAnalyzer() *NoisyAlertRuleAnalyzer { return &NoisyAlertRuleAnalyzer{} }
func (a *NoisyAlertRuleAnalyzer) ID() string             { return NoisyAlertRuleAnalyzerID }
func (a *NoisyAlertRuleAnalyzer) Name() string           { return "Noisy Alert Rule" }
func (a *NoisyAlertRuleAnalyzer) Version() string        { return "0.1.0" }
func (a *NoisyAlertRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *NoisyAlertRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	threshold := intConfig(analysis.Config, "noisy_alert_event_threshold", defaultNoisyAlertEventThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		count := historyInt(resource, "history_event_count")
		if resource.Status != model.ResourceStatusActive || count <= threshold {
			continue
		}
		window := resource.Metadata["history_window_hours"]
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "NoisyAlertRule",
			Severity: model.SeverityWarning, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q triggered %d times in the observed %s-hour window (threshold %d, sampled=%t)", resource.Name, count, window, threshold, sampled)},
			Recommendation: "复核阈值、for duration、查询窗口和标签维度，合并重复实例或增加抑制/聚合；高频告警应先降低噪声再进入值班通知链路。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "event_count": strconv.Itoa(count), "window_hours": window,
				"threshold": strconv.Itoa(threshold), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type FlappingAlertRuleAnalyzer struct{}

func NewFlappingAlertRuleAnalyzer() *FlappingAlertRuleAnalyzer { return &FlappingAlertRuleAnalyzer{} }
func (a *FlappingAlertRuleAnalyzer) ID() string                { return FlappingAlertRuleAnalyzerID }
func (a *FlappingAlertRuleAnalyzer) Name() string              { return "Flapping Alert Rule" }
func (a *FlappingAlertRuleAnalyzer) Version() string           { return "0.1.0" }
func (a *FlappingAlertRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *FlappingAlertRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	countThreshold := intConfig(analysis.Config, "flapping_alert_short_lived_threshold", defaultFlappingShortLivedThreshold)
	ratioThreshold := floatConfig(analysis.Config, "flapping_alert_short_lived_ratio_threshold", defaultFlappingShortLivedRatio)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		shortLived := historyInt(resource, "history_short_lived_count")
		recovered := historyInt(resource, "history_recovered_count")
		if resource.Status != model.ResourceStatusActive || recovered == 0 || shortLived < countThreshold {
			continue
		}
		ratio := float64(shortLived) / float64(recovered)
		if ratio < ratioThreshold {
			continue
		}
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "FlappingAlertRule",
			Severity: model.SeverityWarning, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q had %d short-lived recoveries out of %d recovered events (ratio %.2f, threshold %.2f, sampled=%t)", resource.Name, shortLived, recovered, ratio, ratioThreshold, sampled)},
			Recommendation: "增加合理的 for duration、迟滞或恢复阈值，检查数据抖动和缺失点，并避免同一临界值反复触发与恢复。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "short_lived_count": strconv.Itoa(shortLived), "recovered_count": strconv.Itoa(recovered),
				"short_lived_ratio": fmt.Sprintf("%.4f", ratio), "ratio_threshold": fmt.Sprintf("%.4f", ratioThreshold), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func historyInt(resource model.Resource, key string) int {
	value, _ := strconv.Atoi(resource.Metadata[key])
	return value
}

type PoorAlertRecoveryAnalyzer struct{}

func NewPoorAlertRecoveryAnalyzer() *PoorAlertRecoveryAnalyzer { return &PoorAlertRecoveryAnalyzer{} }
func (a *PoorAlertRecoveryAnalyzer) ID() string                { return PoorAlertRecoveryAnalyzerID }
func (a *PoorAlertRecoveryAnalyzer) Name() string              { return "Poor Alert Recovery" }
func (a *PoorAlertRecoveryAnalyzer) Version() string           { return "0.1.0" }
func (a *PoorAlertRecoveryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *PoorAlertRecoveryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	minimum := intConfig(analysis.Config, "poor_alert_recovery_event_threshold", defaultPoorRecoveryEventThreshold)
	ratioThreshold := floatConfig(analysis.Config, "poor_alert_recovery_ratio_threshold", defaultPoorRecoveryRatioThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		events := historyInt(resource, "history_event_count")
		unrecovered := historyInt(resource, "history_unrecovered_count")
		if resource.Status != model.ResourceStatusActive || events < minimum || events == 0 {
			continue
		}
		ratio := float64(unrecovered) / float64(events)
		if ratio < ratioThreshold {
			continue
		}
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "PoorAlertRecovery",
			Severity: model.SeverityCritical, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q left %d of %d historical events unrecovered (ratio %.2f, threshold %.2f, sampled=%t)", resource.Name, unrecovered, events, ratio, ratioThreshold, sampled)},
			Recommendation: "检查恢复表达式、数据缺失处理和告警生命周期更新链路；确认真实故障是否仍在持续，并避免无法自动恢复的事件长期占用值班队列。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "event_count": strconv.Itoa(events), "unrecovered_count": strconv.Itoa(unrecovered),
				"unrecovered_ratio": fmt.Sprintf("%.4f", ratio), "ratio_threshold": fmt.Sprintf("%.4f", ratioThreshold), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type AlertNotificationStormAnalyzer struct{}

func NewAlertNotificationStormAnalyzer() *AlertNotificationStormAnalyzer {
	return &AlertNotificationStormAnalyzer{}
}
func (a *AlertNotificationStormAnalyzer) ID() string      { return AlertNotificationStormID }
func (a *AlertNotificationStormAnalyzer) Name() string    { return "Alert Notification Storm" }
func (a *AlertNotificationStormAnalyzer) Version() string { return "0.1.0" }
func (a *AlertNotificationStormAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *AlertNotificationStormAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	minimum := intConfig(analysis.Config, "alert_notification_storm_threshold", defaultNotificationStormThreshold)
	perEventThreshold := floatConfig(analysis.Config, "alert_notifications_per_event_threshold", defaultNotificationsPerEvent)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range rules {
		events := historyInt(resource, "history_event_count")
		notifications := historyInt(resource, "history_notification_count")
		if resource.Status != model.ResourceStatusActive || events == 0 || notifications < minimum {
			continue
		}
		perEvent := float64(notifications) / float64(events)
		if perEvent < perEventThreshold {
			continue
		}
		sampled := resource.Metadata["history_events_truncated"] == "true"
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "AlertNotificationStorm",
			Severity: model.SeverityCritical, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("alert rule %q emitted %d notifications for %d events (%.2f per event, threshold %.2f, sampled=%t)", resource.Name, notifications, events, perEvent, perEventThreshold, sampled)},
			Recommendation: "延长 repeat interval、启用合理分组与抑制，并检查多通知规则或订阅是否重复命中；为同一事件设置明确的升级节奏，避免重复轰炸接收人。",
			Metadata: map[string]string{"analyzer_id": a.ID(), "event_count": strconv.Itoa(events), "notification_count": strconv.Itoa(notifications),
				"notifications_per_event": fmt.Sprintf("%.4f", perEvent), "per_event_threshold": fmt.Sprintf("%.4f", perEventThreshold), "sampled": strconv.FormatBool(sampled)},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
