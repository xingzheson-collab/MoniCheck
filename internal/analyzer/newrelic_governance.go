package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	NewRelicEntityNotReportingAnalyzerID                         = "builtin.newrelic_entity_not_reporting"
	NewRelicEntityCriticalAnalyzerID                             = "builtin.newrelic_entity_critical"
	NewRelicEntityWithoutOwnerAnalyzerID                         = "builtin.newrelic_entity_without_owner"
	NewRelicCriticalConditionNoDescriptionAnalyzerID             = "builtin.newrelic_critical_condition_without_description"
	NewRelicCriticalConditionNoTitleTemplateAnalyzerID           = "builtin.newrelic_critical_condition_without_title_template"
	NewRelicCriticalConditionNoRunbookAnalyzerID                 = "builtin.newrelic_critical_condition_without_runbook"
	NewRelicCriticalConditionNoEntityScopeAnalyzerID             = "builtin.newrelic_critical_condition_without_entity_scope"
	NewRelicConditionIncompatibleNRQLClauseAnalyzerID            = "builtin.newrelic_condition_incompatible_nrql_clause"
	NewRelicCriticalConditionNoLossSignalAnalyzerID              = "builtin.newrelic_critical_condition_without_loss_of_signal"
	NewRelicCriticalConditionShortTimeLimitAnalyzerID            = "builtin.newrelic_critical_condition_short_violation_time_limit"
	NewRelicCriticalConditionCadenceAnalyzerID                   = "builtin.newrelic_critical_condition_cadence_aggregation"
	NewRelicCriticalConditionInvalidAggregationDelayAnalyzerID   = "builtin.newrelic_critical_condition_invalid_aggregation_delay"
	NewRelicCriticalConditionInvalidEventTimerAnalyzerID         = "builtin.newrelic_critical_condition_invalid_event_timer"
	NewRelicCriticalConditionInvalidWindowAnalyzerID             = "builtin.newrelic_critical_condition_invalid_aggregation_window"
	NewRelicCriticalConditionShortEventTimerAnalyzerID           = "builtin.newrelic_critical_condition_event_timer_shorter_than_window"
	NewRelicCriticalConditionInvalidThresholdAnalyzerID          = "builtin.newrelic_critical_condition_invalid_threshold_duration"
	NewRelicBaselineConditionInvalidThresholdAnalyzerID          = "builtin.newrelic_baseline_condition_invalid_threshold_duration"
	NewRelicBaselineConditionInvalidDirectionAnalyzerID          = "builtin.newrelic_baseline_condition_invalid_direction"
	NewRelicStaticConditionInvalidValueFunctionAnalyzerID        = "builtin.newrelic_static_condition_invalid_value_function"
	NewRelicCriticalConditionInvalidSlidingWindowAnalyzerID      = "builtin.newrelic_critical_condition_invalid_sliding_window"
	NewRelicConditionSlidingWindowCostAnalyzerID                 = "builtin.newrelic_condition_sliding_window_cost"
	NewRelicConditionInvalidThresholdPriorityCountAnalyzerID     = "builtin.newrelic_condition_invalid_threshold_priority_count"
	NewRelicConditionInvalidThresholdTermSemanticsAnalyzerID     = "builtin.newrelic_condition_invalid_threshold_term_semantics"
	NewRelicConditionInvalidThresholdValueAnalyzerID             = "builtin.newrelic_condition_invalid_threshold_value"
	NewRelicConditionInvalidGapFillOptionAnalyzerID              = "builtin.newrelic_condition_invalid_gap_fill_option"
	NewRelicConditionInvalidStaticGapFillValueAnalyzerID         = "builtin.newrelic_condition_invalid_static_gap_fill_value"
	NewRelicConditionPerTargetIncidentFanoutAnalyzerID           = "builtin.newrelic_condition_per_target_incident_fanout"
	NewRelicCriticalConditionAtLeastOnceAnalyzerID               = "builtin.newrelic_critical_condition_at_least_once_threshold"
	NewRelicCriticalConditionInvalidLossSignalDurationAnalyzerID = "builtin.newrelic_critical_condition_invalid_loss_of_signal_duration"
	NewRelicCriticalConditionShortLossSignalDurationAnalyzerID   = "builtin.newrelic_critical_condition_short_loss_of_signal_duration"
	NewRelicCriticalConditionEvaluationDelayAnalyzerID           = "builtin.newrelic_critical_condition_evaluation_delay"
	NewRelicCriticalConditionLastValueGapFillAnalyzerID          = "builtin.newrelic_critical_condition_last_value_gap_filling"
	NewRelicCriticalConditionStaticGapFillBreachAnalyzerID       = "builtin.newrelic_critical_condition_static_gap_fill_breaches_threshold"
	NewRelicCriticalConditionNoCloseOnSignalLossAnalyzerID       = "builtin.newrelic_critical_condition_without_close_on_signal_loss"
	NewRelicDisabledConditionAnalyzerID                          = "builtin.newrelic_disabled_condition"
	newRelicDefaultViolationTimeLimitSeconds                     = 3 * 24 * 60 * 60
)

type NewRelicGovernanceAnalyzer struct {
	id           string
	name         string
	kind         string
	resourceType model.ResourceType
}

func NewNewRelicEntityNotReportingAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicEntityNotReportingAnalyzerID, "New Relic Entity Not Reporting", "not_reporting", model.ResourceTypeService)
}

func NewNewRelicEntityCriticalAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicEntityCriticalAnalyzerID, "New Relic Entity Critical", "critical", model.ResourceTypeService)
}

func NewNewRelicEntityWithoutOwnerAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicEntityWithoutOwnerAnalyzerID, "New Relic Entity Without Owner", "missing_owner", model.ResourceTypeService)
}

func NewNewRelicCriticalConditionWithoutRunbookAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionNoRunbookAnalyzerID, "New Relic Critical Condition Without Runbook", "missing_runbook", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionWithoutEntityScopeAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionNoEntityScopeAnalyzerID, "New Relic Critical Condition Without Entity Scope", "missing_entity_scope", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionIncompatibleNRQLClauseAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionIncompatibleNRQLClauseAnalyzerID, "New Relic Condition With Incompatible NRQL Clause", "incompatible_nrql_clause", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionWithoutDescriptionAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionNoDescriptionAnalyzerID, "New Relic Critical Condition Without Description", "missing_description", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionWithoutTitleTemplateAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionNoTitleTemplateAnalyzerID, "New Relic Critical Condition Without Title Template", "missing_title_template", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionWithoutLossOfSignalAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionNoLossSignalAnalyzerID, "New Relic Critical Condition Without Loss of Signal", "missing_loss_of_signal", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionShortTimeLimitAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionShortTimeLimitAnalyzerID, "New Relic Critical Condition With Short Violation Time Limit", "short_violation_time_limit", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionCadenceAggregationAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionCadenceAnalyzerID, "New Relic Critical Condition With Cadence Aggregation", "cadence_aggregation", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionInvalidAggregationDelayAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionInvalidAggregationDelayAnalyzerID, "New Relic Critical Condition With Invalid Aggregation Delay", "invalid_aggregation_delay", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionInvalidEventTimerAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionInvalidEventTimerAnalyzerID, "New Relic Critical Condition With Invalid Event Timer", "invalid_event_timer", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionInvalidAggregationWindowAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionInvalidWindowAnalyzerID, "New Relic Critical Condition With Invalid Aggregation Window", "invalid_aggregation_window", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionEventTimerShorterThanWindowAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionShortEventTimerAnalyzerID, "New Relic Critical Condition With Event Timer Shorter Than Window", "event_timer_shorter_than_window", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionInvalidThresholdDurationAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionInvalidThresholdAnalyzerID, "New Relic Critical Condition With Invalid Threshold Duration", "invalid_threshold_duration", model.ResourceTypeAlertRule)
}

func NewNewRelicBaselineConditionInvalidThresholdDurationAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicBaselineConditionInvalidThresholdAnalyzerID, "New Relic Baseline Condition With Invalid Threshold Duration", "invalid_baseline_threshold_duration", model.ResourceTypeAlertRule)
}

func NewNewRelicBaselineConditionInvalidDirectionAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicBaselineConditionInvalidDirectionAnalyzerID, "New Relic Baseline Condition With Invalid Direction", "invalid_baseline_direction", model.ResourceTypeAlertRule)
}

func NewNewRelicStaticConditionInvalidValueFunctionAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicStaticConditionInvalidValueFunctionAnalyzerID, "New Relic Static Condition With Invalid Value Function", "invalid_static_value_function", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionInvalidSlidingWindowAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionInvalidSlidingWindowAnalyzerID, "New Relic Critical Condition With Invalid Sliding Window", "invalid_sliding_window", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionSlidingWindowCostAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionSlidingWindowCostAnalyzerID, "New Relic Condition Sliding Window Cost", "sliding_window_cost", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionInvalidThresholdPriorityCountAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionInvalidThresholdPriorityCountAnalyzerID, "New Relic Condition With Invalid Threshold Priority Count", "invalid_threshold_priority_count", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionInvalidThresholdTermSemanticsAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionInvalidThresholdTermSemanticsAnalyzerID, "New Relic Condition With Invalid Threshold Term Semantics", "invalid_threshold_term_semantics", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionInvalidThresholdValueAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionInvalidThresholdValueAnalyzerID, "New Relic Condition With Invalid Threshold Value", "invalid_threshold_value", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionInvalidGapFillOptionAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionInvalidGapFillOptionAnalyzerID, "New Relic Condition With Invalid Gap Fill Option", "invalid_gap_fill_option", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionInvalidStaticGapFillValueAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionInvalidStaticGapFillValueAnalyzerID, "New Relic Condition With Invalid Static Gap Fill Value", "invalid_static_gap_fill_value", model.ResourceTypeAlertRule)
}

func NewNewRelicConditionPerTargetIncidentFanoutAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicConditionPerTargetIncidentFanoutAnalyzerID, "New Relic Condition With Per-Target Incident Fanout", "per_target_incident_fanout", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionAtLeastOnceAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionAtLeastOnceAnalyzerID, "New Relic Critical Condition With At-Least-Once Threshold", "critical_at_least_once", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionInvalidLossOfSignalDurationAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionInvalidLossSignalDurationAnalyzerID, "New Relic Critical Condition With Invalid Loss-of-Signal Duration", "invalid_loss_of_signal_duration", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionShortLossOfSignalDurationAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionShortLossSignalDurationAnalyzerID, "New Relic Critical Condition With Short Loss-of-Signal Duration", "short_loss_of_signal_duration", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionEvaluationDelayAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionEvaluationDelayAnalyzerID, "New Relic Critical Condition With Evaluation Delay", "evaluation_delay", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionLastValueGapFillingAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionLastValueGapFillAnalyzerID, "New Relic Critical Condition With Last-Value Gap Filling", "last_value_gap_filling", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionStaticGapFillBreachesThresholdAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionStaticGapFillBreachAnalyzerID, "New Relic Critical Condition Whose Static Gap Fill Breaches Threshold", "static_gap_fill_breaches_threshold", model.ResourceTypeAlertRule)
}

func NewNewRelicCriticalConditionWithoutCloseOnSignalLossAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicCriticalConditionNoCloseOnSignalLossAnalyzerID, "New Relic Critical Condition Without Close-on-Signal-Loss", "missing_close_on_signal_loss", model.ResourceTypeAlertRule)
}

func NewNewRelicDisabledConditionAnalyzer() *NewRelicGovernanceAnalyzer {
	return newNewRelicGovernanceAnalyzer(NewRelicDisabledConditionAnalyzerID, "New Relic Disabled Condition", "disabled", model.ResourceTypeAlertRule)
}

func newNewRelicGovernanceAnalyzer(id, name, kind string, resourceType model.ResourceType) *NewRelicGovernanceAnalyzer {
	return &NewRelicGovernanceAnalyzer{id: id, name: name, kind: kind, resourceType: resourceType}
}

func (a *NewRelicGovernanceAnalyzer) ID() string      { return a.id }
func (a *NewRelicGovernanceAnalyzer) Name() string    { return a.name }
func (a *NewRelicGovernanceAnalyzer) Version() string { return "0.1.0" }
func (a *NewRelicGovernanceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{a.resourceType}
}

func (a *NewRelicGovernanceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: a.resourceType})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *NewRelicGovernanceAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	if resource.Source.System != "newrelic" {
		return model.Finding{}, false
	}
	if a.kind == "disabled" {
		if resource.Status != model.ResourceStatusDeprecated {
			return model.Finding{}, false
		}
	} else if resource.Status != model.ResourceStatusActive {
		return model.Finding{}, false
	}

	severity := model.SeverityWarning
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.ID()}

	switch a.kind {
	case "not_reporting":
		if resource.Metadata[model.MetadataNewRelicEntity] != "true" ||
			resource.Metadata[model.MetadataNewRelicReportingDeclared] != "true" ||
			resource.Metadata[model.MetadataNewRelicReporting] != "false" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		findingType = "NewRelicEntityNotReporting"
		evidence = fmt.Sprintf("New Relic service %q explicitly reports that telemetry is not arriving", resource.Name)
		recommendation = "检查 agent、采集网络、license key、部署状态和最近变更，恢复实体 reporting 后重新执行治理分析。"
	case "critical":
		if resource.Metadata[model.MetadataNewRelicEntity] != "true" ||
			resource.Metadata[model.MetadataNewRelicAlertSeverityDeclared] != "true" ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicAlertSeverity], "CRITICAL") {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		findingType = "NewRelicEntityCritical"
		evidence = fmt.Sprintf("New Relic service %q has explicit CRITICAL alert severity", resource.Name)
		recommendation = "检查该服务当前 issue、关联条件和依赖影响，完成止血与恢复验证后再关闭告警事件。"
	case "missing_owner":
		if resource.Metadata[model.MetadataNewRelicEntity] != "true" ||
			resource.Metadata[model.MetadataNewRelicOwnershipDeclared] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "NewRelicEntityWithoutOwner"
		evidence = fmt.Sprintf("New Relic service %q has neither an allowlisted team nor owner tag", resource.Name)
		recommendation = "为实体补充统一的 team 或 owner tag，并将其关联到有效的值班与升级路径。"
	case "missing_runbook":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			resource.Metadata[model.MetadataNewRelicRunbookConfigured] == "true" {
			return model.Finding{}, false
		}
		findingType = "NewRelicCriticalConditionWithoutRunbook"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and no runbook", resource.Name, criticalTerms)
		recommendation = "为 critical NRQL condition 配置 runbook URL，覆盖诊断入口、止血动作、升级路径和恢复验证。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
	case "missing_entity_scope":
		criticalTerms, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicQueryScopeEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicQueryScopeClausePresent] == "true" ||
			err != nil || criticalTerms <= 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionWithoutEntityScope"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and its evaluable NRQL query has neither a top-level WHERE nor FACET scope clause", resource.Name, criticalTerms)
		recommendation = "使用顶层 WHERE 将 NRQL condition 限定到单一实体，或使用 FACET 将每个 signal 映射到实体；若通过显式 target entity 关联健康状态，记录并验证该例外。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
	case "incompatible_nrql_clause":
		incompatibleClauseCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicQueryIncompatibleClauseCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicQueryCompatibilityEvaluable] != "true" ||
			err != nil || incompatibleClauseCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "NewRelicConditionIncompatibleNRQLClause"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d top-level NRQL clause(s) incompatible with streaming alert evaluation", resource.Name, incompatibleClauseCount)
		recommendation = "移除 NRQL 中的 SINCE、UNTIL、TIMESERIES、COMPARE WITH 和 LIMIT；将 SLIDE BY 转换为 condition 的 aggregation window 与 sliding-window 设置，并重新验证流式告警结果。"
		metadata["incompatible_clause_count"] = strconv.Itoa(incompatibleClauseCount)
	case "missing_description":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			resource.Metadata[model.MetadataNewRelicDescriptionConfigured] == "true" {
			return model.Finding{}, false
		}
		findingType = "NewRelicCriticalConditionWithoutDescription"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and no custom alert-event description", resource.Name, criticalTerms)
		recommendation = "为 critical NRQL condition 增加自定义 description，说明监控原因、信号含义、影响范围、下一步和必要的下游响应元数据。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
	case "missing_title_template":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			resource.Metadata[model.MetadataNewRelicTitleTemplateConfigured] == "true" {
			return model.Finding{}, false
		}
		findingType = "NewRelicCriticalConditionWithoutTitleTemplate"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and no custom alert-event title template", resource.Name, criticalTerms)
		recommendation = "为 critical NRQL condition 配置简洁且可区分的 title template，包含必要的 condition、entity 或 facet 上下文，以便值班人员快速定位问题。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
	case "missing_loss_of_signal":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionWithoutLossOfSignal"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) but cannot open an event when its signal expires", resource.Name, criticalTerms)
		recommendation = "为 critical NRQL condition 配置 expiration duration 并启用 open violation on expiration，按信号上报周期验证断流告警与恢复行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
	case "short_violation_time_limit":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		limitSeconds, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicViolationTimeLimitSeconds])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			err != nil || limitSeconds <= 0 ||
			limitSeconds >= newRelicDefaultViolationTimeLimitSeconds {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionShortViolationTimeLimit"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and force-closes a continuing alert event after %d seconds", resource.Name, criticalTerms, limitSeconds)
		recommendation = "将 critical NRQL condition 的 alert event time limit 提高到至少 3 天，或确认该条件只覆盖短生命周期实体并记录强制关闭后的重新开事件行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["violation_time_limit_seconds"] = strconv.Itoa(limitSeconds)
	case "cadence_aggregation":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicAggregationMethod], "CADENCE") {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionCadenceAggregation"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and uses legacy CADENCE aggregation", resource.Name, criticalTerms)
		recommendation = "根据数据到达模式迁移到 EVENT_FLOW 或 EVENT_TIMER 并验证迟到数据与告警延迟；仅在事件时间戳存在无法修正的 clock skew 时保留 CADENCE 并记录例外。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["aggregation_method"] = "CADENCE"
	case "invalid_aggregation_delay":
		criticalTerms, criticalErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		delaySeconds, delayErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationDelay])
		method := strings.ToUpper(strings.TrimSpace(resource.Metadata[model.MetadataNewRelicAggregationMethod]))
		maxDelay := 0
		switch method {
		case "EVENT_FLOW":
			maxDelay = 20 * 60
		case "CADENCE":
			maxDelay = 60 * 60
		}
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicAggregationDelayEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicAggregationDelayInvalid] != "true" ||
			criticalErr != nil || delayErr != nil || criticalTerms <= 0 ||
			maxDelay == 0 || (delaySeconds >= 0 && delaySeconds <= maxDelay) {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionInvalidAggregationDelay"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and a %s aggregation delay of %d seconds outside the supported 0-%d second range", resource.Name, criticalTerms, method, delaySeconds, maxDelay)
		recommendation = fmt.Sprintf("将 %s aggregation delay 调整到 0-%d 秒范围内，并根据数据到达延迟回放告警准确性与检测时延。", method, maxDelay)
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["aggregation_method"] = method
		metadata["aggregation_delay_seconds"] = strconv.Itoa(delaySeconds)
	case "invalid_event_timer":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		timerSeconds, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationTimer])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicAggregationMethod], "EVENT_TIMER") ||
			err != nil || (timerSeconds >= 5 && timerSeconds <= 20*60) {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionInvalidEventTimer"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and EVENT_TIMER set to %d seconds outside the supported 5-1200 second range", resource.Name, criticalTerms, timerSeconds)
		recommendation = "将 EVENT_TIMER aggregation timer 配置在 5–1200 秒范围内，并根据批次到达间隔验证告警评估延迟、迟到数据和恢复行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["aggregation_method"] = "EVENT_TIMER"
		metadata["aggregation_timer_seconds"] = strconv.Itoa(timerSeconds)
	case "invalid_aggregation_window":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		windowSeconds, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationWindow])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			err != nil || (windowSeconds >= 30 && windowSeconds <= 6*60*60) {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionInvalidAggregationWindow"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and an aggregation window of %d seconds outside the supported 30-21600 second range", resource.Name, criticalTerms, windowSeconds)
		recommendation = "将 aggregation window 配置在 30–21600 秒范围内，并结合数据上报频率、平滑需求、检测延迟和 threshold duration 验证告警行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["aggregation_window_seconds"] = strconv.Itoa(windowSeconds)
	case "event_timer_shorter_than_window":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		timerSeconds, timerErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationTimer])
		windowSeconds, windowErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationWindow])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicAggregationMethod], "EVENT_TIMER") ||
			resource.Metadata[model.MetadataNewRelicEventTimerWindowEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicEventTimerShorterThanWindow] != "true" ||
			timerErr != nil || windowErr != nil ||
			timerSeconds < 5 || timerSeconds > 20*60 ||
			windowSeconds < 30 || windowSeconds > 6*60*60 ||
			timerSeconds >= windowSeconds {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionEventTimerShorterThanWindow"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s), an EVENT_TIMER of %d seconds, and an aggregation window of %d seconds", resource.Name, criticalTerms, timerSeconds, windowSeconds)
		recommendation = "将 EVENT_TIMER timer 调整为不短于 aggregation window，并按批次到达间隔验证窗口关闭、迟到数据和误通知风险。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["aggregation_method"] = "EVENT_TIMER"
		metadata["aggregation_timer_seconds"] = strconv.Itoa(timerSeconds)
		metadata["aggregation_window_seconds"] = strconv.Itoa(windowSeconds)
	case "invalid_threshold_duration":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		invalidCount, invalidErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidCriticalThresholdDurationCount])
		minSeconds, minErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalThresholdDurationMin])
		maxSeconds, maxErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalThresholdDurationMax])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			strings.EqualFold(resource.Metadata[model.MetadataNewRelicConditionType], "BASELINE") ||
			criticalTerms <= 0 ||
			invalidErr != nil || minErr != nil || maxErr != nil || invalidCount <= 0 ||
			minSeconds < 0 || maxSeconds < minSeconds ||
			(minSeconds >= 30 && maxSeconds <= 2*60*60) {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionInvalidThresholdDuration"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s), %d invalid critical threshold duration(s), and an observed range of %d-%d seconds outside the supported 30-7200 second range", resource.Name, criticalTerms, invalidCount, minSeconds, maxSeconds)
		recommendation = "将 critical threshold duration 配置在 30–7200 秒范围内，并结合 aggregation window、信号波动和响应时效验证告警触发行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["invalid_threshold_duration_count"] = strconv.Itoa(invalidCount)
		metadata["threshold_duration_min_seconds"] = strconv.Itoa(minSeconds)
		metadata["threshold_duration_max_seconds"] = strconv.Itoa(maxSeconds)
	case "invalid_baseline_threshold_duration":
		termCount, termErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		invalidCount, invalidErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidBaselineThresholdDurationCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicConditionType], "BASELINE") ||
			termErr != nil || termCount <= 0 ||
			invalidErr != nil || invalidCount <= 0 || invalidCount > termCount {
			return model.Finding{}, false
		}
		findingType = "NewRelicBaselineConditionInvalidThresholdDuration"
		evidence = fmt.Sprintf("Enabled New Relic baseline condition %q has %d of %d threshold term(s) outside the 120-3600 second whole-minute contract", resource.Name, invalidCount, termCount)
		recommendation = "将 Baseline condition 的每个 threshold duration 调整到 120–3600 秒，并使用 60 秒的整数倍；随后回放异常检测延迟、噪声和恢复行为。"
		metadata["term_count"] = strconv.Itoa(termCount)
		metadata["invalid_baseline_threshold_duration_count"] = strconv.Itoa(invalidCount)
	case "invalid_baseline_direction":
		termCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicConditionType], "BASELINE") ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
			resource.Metadata[model.MetadataNewRelicBaselineDirectionEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicBaselineDirectionInvalid] != "true" ||
			err != nil || termCount <= 0 || termCount > 2 {
			return model.Finding{}, false
		}
		findingType = "NewRelicBaselineConditionInvalidDirection"
		evidence = fmt.Sprintf("Enabled New Relic baseline condition %q has %d validly structured threshold term(s) but its anomaly direction is missing or unsupported", resource.Name, termCount)
		recommendation = "将 Baseline condition 的 anomaly direction 明确配置为 UPPER_ONLY、LOWER_ONLY 或 UPPER_AND_LOWER，并根据业务信号验证上偏、下偏或双向异常的触发与恢复行为。"
		metadata["term_count"] = strconv.Itoa(termCount)
	case "invalid_static_value_function":
		termCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicConditionType], "STATIC") ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
			resource.Metadata[model.MetadataNewRelicStaticValueFunctionEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicStaticValueFunctionInvalid] != "true" ||
			err != nil || termCount <= 0 || termCount > 2 {
			return model.Finding{}, false
		}
		findingType = "NewRelicStaticConditionInvalidValueFunction"
		evidence = fmt.Sprintf("Enabled New Relic static condition %q has %d validly structured threshold term(s) but its value function is missing or unsupported", resource.Name, termCount)
		recommendation = "将 Static NRQL condition 的 value function 明确配置为 SINGLE_VALUE 或 SUM，并按查询返回语义验证聚合值、阈值触发和恢复行为。"
		metadata["term_count"] = strconv.Itoa(termCount)
	case "invalid_sliding_window":
		criticalTerms, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		windowSeconds, windowErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationWindow])
		slideBySeconds, slideByErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicSlideBySeconds])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || criticalTerms <= 0 ||
			resource.Metadata[model.MetadataNewRelicSlideByDeclared] != "true" ||
			resource.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicSlidingWindowInvalid] != "true" ||
			windowErr != nil || slideByErr != nil ||
			windowSeconds < 30 || windowSeconds > 6*60*60 ||
			(slideBySeconds > 0 && slideBySeconds < windowSeconds && windowSeconds%slideBySeconds == 0) {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionInvalidSlidingWindow"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s), an aggregation window of %d seconds, and slideBy of %d seconds that is not a positive, shorter, even divisor of the window", resource.Name, criticalTerms, windowSeconds, slideBySeconds)
		recommendation = "将 slideBy 配置为小于 aggregation window 且可整除 window 的正秒数，并验证重叠窗口带来的平滑效果、检测延迟和计算成本。"
		metadata["critical_term_count"] = strconv.Itoa(criticalTerms)
		metadata["aggregation_window_seconds"] = strconv.Itoa(windowSeconds)
		metadata["slide_by_seconds"] = strconv.Itoa(slideBySeconds)
	case "sliding_window_cost":
		termCount, _ := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		windowSeconds, windowErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicAggregationWindow])
		slideBySeconds, slideByErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicSlideBySeconds])
		overlapFactor, factorErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicSlidingWindowOverlapFactor])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" || termCount <= 0 ||
			resource.Metadata[model.MetadataNewRelicSlideByDeclared] != "true" ||
			resource.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicSlidingWindowInvalid] != "false" ||
			windowErr != nil || slideByErr != nil || factorErr != nil ||
			windowSeconds < 30 || windowSeconds > 6*60*60 ||
			slideBySeconds <= 0 || slideBySeconds >= windowSeconds ||
			windowSeconds%slideBySeconds != 0 ||
			overlapFactor <= 1 || overlapFactor != windowSeconds/slideBySeconds {
			return model.Finding{}, false
		}
		category = model.FindingCategoryCost
		findingType = "NewRelicConditionSlidingWindowCost"
		evidence = fmt.Sprintf("Enabled New Relic condition %q uses a valid sliding window with a %d-second aggregation window, %d-second slideBy, and configuration overlap factor %d", resource.Name, windowSeconds, slideBySeconds, overlapFactor)
		recommendation = "确认 sliding window 的平滑收益值得额外 New Relic Compute 成本；记录账户计费计划，并对变更前后的 CCU、误报率和检测延迟做基线验证，无明确收益时恢复非重叠窗口。"
		metadata["term_count"] = strconv.Itoa(termCount)
		metadata["aggregation_window_seconds"] = strconv.Itoa(windowSeconds)
		metadata["slide_by_seconds"] = strconv.Itoa(slideBySeconds)
		metadata["sliding_window_overlap_factor"] = strconv.Itoa(overlapFactor)
	case "invalid_threshold_priority_count":
		termCount, termErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		criticalCount, criticalErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		warningCount, warningErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicWarningTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "true" ||
			termErr != nil || criticalErr != nil || warningErr != nil ||
			!newRelicThresholdPriorityCountsInvalid(termCount, criticalCount, warningCount) {
			return model.Finding{}, false
		}
		findingType = "NewRelicConditionInvalidThresholdPriorityCount"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d threshold term(s): %d CRITICAL and %d WARNING, outside the supported maximum of one per priority", resource.Name, termCount, criticalCount, warningCount)
		recommendation = "将 NRQL condition 配置为一个 WARNING 或一个 CRITICAL threshold，或各一个；删除重复/未知 priority，并验证两个阈值的触发与恢复顺序。"
		metadata["term_count"] = strconv.Itoa(termCount)
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
		metadata["warning_term_count"] = strconv.Itoa(warningCount)
	case "invalid_threshold_term_semantics":
		termCount, termErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		invalidOperatorCount, operatorErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount])
		invalidOccurrenceCount, occurrenceErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
			termErr != nil || operatorErr != nil || occurrenceErr != nil ||
			termCount <= 0 || termCount > 2 ||
			invalidOperatorCount < 0 || invalidOperatorCount > termCount ||
			invalidOccurrenceCount < 0 || invalidOccurrenceCount > termCount ||
			invalidOperatorCount+invalidOccurrenceCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "NewRelicConditionInvalidThresholdTermSemantics"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d validly structured threshold term(s), with %d unsupported operator value(s) and %d unsupported occurrence value(s)", resource.Name, termCount, invalidOperatorCount, invalidOccurrenceCount)
		recommendation = "将每个 NRQL threshold term 的 operator 配置为受支持的比较枚举，并将 thresholdOccurrences 明确配置为 ALL 或 AT_LEAST_ONCE；随后验证阈值触发与恢复行为。"
		metadata["term_count"] = strconv.Itoa(termCount)
		metadata["invalid_threshold_operator_count"] = strconv.Itoa(invalidOperatorCount)
		metadata["invalid_threshold_occurrence_count"] = strconv.Itoa(invalidOccurrenceCount)
	case "invalid_threshold_value":
		termCount, termErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		invalidOperatorCount, operatorErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount])
		invalidOccurrenceCount, occurrenceErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount])
		invalidValueCount, valueErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicInvalidThresholdValueCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
			termErr != nil || operatorErr != nil || occurrenceErr != nil || valueErr != nil ||
			termCount <= 0 || termCount > 2 ||
			invalidOperatorCount != 0 || invalidOccurrenceCount != 0 ||
			invalidValueCount <= 0 || invalidValueCount > termCount {
			return model.Finding{}, false
		}
		findingType = "NewRelicConditionInvalidThresholdValue"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d validly structured threshold term(s), with %d missing, negative, or non-finite threshold value(s)", resource.Name, termCount, invalidValueCount)
		recommendation = "为每个 NRQL threshold term 配置有限的非负数值，并结合 operator、duration、触发与恢复行为回放验证。"
		metadata["term_count"] = strconv.Itoa(termCount)
		metadata["invalid_threshold_value_count"] = strconv.Itoa(invalidValueCount)
	case "invalid_gap_fill_option":
		termCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
			resource.Metadata[model.MetadataNewRelicGapFillOptionEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicGapFillOptionInvalid] != "true" ||
			resource.Metadata[model.MetadataNewRelicGapFillOption] != "" ||
			err != nil || termCount <= 0 || termCount > 2 {
			return model.Finding{}, false
		}
		findingType = "NewRelicConditionInvalidGapFillOption"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d validly structured threshold term(s) but its gap-filling option is missing or unsupported", resource.Name, termCount)
		recommendation = "将 NRQL condition 的 gap-filling option 明确配置为 NONE、LAST_VALUE 或 STATIC；使用 STATIC 时同时验证 fillValue、threshold 与 Loss of Signal 的交互行为。"
		metadata["term_count"] = strconv.Itoa(termCount)
	case "invalid_static_gap_fill_value":
		termCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
			resource.Metadata[model.MetadataNewRelicGapFillOptionEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicGapFillOptionInvalid] != "false" ||
			!strings.EqualFold(resource.Metadata[model.MetadataNewRelicGapFillOption], "STATIC") ||
			resource.Metadata[model.MetadataNewRelicStaticGapFillValueEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicStaticGapFillValueInvalid] != "true" ||
			err != nil || termCount <= 0 || termCount > 2 {
			return model.Finding{}, false
		}
		findingType = "NewRelicConditionInvalidStaticGapFillValue"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d validly structured threshold term(s) and selects STATIC gap filling, but its fill value is missing or invalid", resource.Name, termCount)
		recommendation = "为 STATIC gap filling 配置有限数值 fillValue，并结合每个 threshold、空窗口和 Loss of Signal 回放触发与恢复行为；不需要合成值时改用 NONE。"
		metadata["term_count"] = strconv.Itoa(termCount)
	case "per_target_incident_fanout":
		termCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicTermCount])
		preference := strings.ToUpper(strings.TrimSpace(resource.Metadata[model.MetadataNewRelicIncidentPreference]))
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicPolicyDeclared] != "true" ||
			err != nil || termCount <= 0 ||
			preference != "PER_CONDITION_AND_TARGET" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicConditionPerTargetIncidentFanout"
		evidence = fmt.Sprintf("Enabled New Relic condition %q uses PER_CONDITION_AND_TARGET issue creation, the most granular preference, which can create a separate issue and notification for each condition-and-signal combination", resource.Name)
		recommendation = "核对该 condition 的 signal/facet 基数和实际 issue 数量；仅在每个目标都需要独立响应时保留该偏好，否则改为 PER_CONDITION 或 PER_POLICY，并验证 workflow 通知量。"
		metadata["term_count"] = strconv.Itoa(termCount)
		metadata["incident_preference"] = preference
	case "critical_at_least_once":
		criticalCount, criticalErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		atLeastOnceCount, occurrenceErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalAtLeastOnceTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			criticalErr != nil || occurrenceErr != nil ||
			criticalCount <= 0 || atLeastOnceCount <= 0 ||
			atLeastOnceCount > criticalCount {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionAtLeastOnceThreshold"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d of %d critical threshold term(s) using AT_LEAST_ONCE, which opens an alert event as soon as one aggregated data point breaches", resource.Name, atLeastOnceCount, criticalCount)
		recommendation = "确认该 critical condition 确实需要单个聚合点立即开事件；若目标是持续异常，改用 ALL，并对变更前后的误报率、检测延迟和恢复周期做回放验证。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
		metadata["critical_at_least_once_term_count"] = strconv.Itoa(atLeastOnceCount)
	case "invalid_loss_of_signal_duration":
		criticalCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] != "true" ||
			err != nil || criticalCount <= 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionInvalidLossOfSignalDuration"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and an open-on-expiration Loss of Signal duration outside the supported 30-second to 48-hour range", resource.Name, criticalCount)
		recommendation = "将 Loss of Signal expiration duration 调整到 30–172800 秒；通常至少使用 3–5 分钟，并按实际信号上报周期验证断流检测、误报和恢复行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
	case "short_loss_of_signal_duration":
		criticalCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] != "false" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationShort] != "true" ||
			err != nil || criticalCount <= 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionShortLossOfSignalDuration"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and a valid Loss of Signal duration below New Relic's recommended three-minute minimum", resource.Name, criticalCount)
		recommendation = "将 Loss of Signal expiration duration 提高到至少 180 秒，并按信号上报周期、允许抖动和检测时效选择 3–5 分钟或更长窗口；验证断流误报与恢复行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
	case "evaluation_delay":
		criticalCount, criticalErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		delaySeconds, delayErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicEvaluationDelaySeconds])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicEvaluationDelayDeclared] != "true" ||
			resource.Metadata[model.MetadataNewRelicEvaluationDelayInvalid] != "false" ||
			criticalErr != nil || delayErr != nil ||
			criticalCount <= 0 || delaySeconds <= 0 || delaySeconds > 2*60*60 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionEvaluationDelay"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and delays evaluation of new signals by %d seconds", resource.Name, criticalCount, delaySeconds)
		recommendation = "确认 evaluation delay 只用于新实体或自动扩缩容启动期降噪，并接受对应的 critical 检测延迟；记录适用场景，按部署事件回放误报与漏报风险，不需要时设为 0。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
		metadata["evaluation_delay_seconds"] = strconv.Itoa(delaySeconds)
	case "last_value_gap_filling":
		criticalCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			err != nil || criticalCount <= 0 ||
			!strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataNewRelicGapFillOption]), "LAST_VALUE") {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionLastValueGapFilling"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s) and fills empty aggregation windows with the last observed value", resource.Name, criticalCount)
		recommendation = "确认 LAST_VALUE gap filling 不会让陈旧值延续 critical 触发或恢复状态；结合 Loss of Signal、阈值持续时间和真实空窗口回放验证行为，不需要状态延续时改为 NONE。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
		metadata["gap_fill_option"] = "LAST_VALUE"
	case "static_gap_fill_breaches_threshold":
		criticalCount, criticalErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		breachCount, breachErr := strconv.Atoi(resource.Metadata[model.MetadataNewRelicStaticGapFillCriticalBreachCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			!strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataNewRelicGapFillOption]), "STATIC") ||
			resource.Metadata[model.MetadataNewRelicStaticGapFillEvaluable] != "true" ||
			criticalErr != nil || breachErr != nil ||
			criticalCount <= 0 || breachCount <= 0 || breachCount > criticalCount {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionStaticGapFillBreachesThreshold"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has a static gap-fill value that breaches %d of %d critical threshold term(s) during empty aggregation windows", resource.Name, breachCount, criticalCount)
		recommendation = "将 STATIC fillValue 调整为不会触发 Critical 的安全值，或改用 NONE；结合真实空窗口、threshold duration 与 Loss of Signal 回放验证，避免数据缺失被合成值直接转化为 Critical 事件。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
		metadata["static_gap_fill_critical_breach_count"] = strconv.Itoa(breachCount)
	case "missing_close_on_signal_loss":
		criticalCount, err := strconv.Atoi(resource.Metadata[model.MetadataNewRelicCriticalTermCount])
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataEnabled] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] != "false" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalCloseEvaluable] != "true" ||
			resource.Metadata[model.MetadataNewRelicLossOfSignalCloseConfigured] == "true" ||
			err != nil || criticalCount <= 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "NewRelicCriticalConditionWithoutCloseOnSignalLoss"
		evidence = fmt.Sprintf("Enabled New Relic condition %q has %d critical term(s), opens an event on signal loss, but explicitly leaves existing signal-specific alert events open", resource.Name, criticalCount)
		recommendation = "评估在 signal loss 时启用 closeViolationsOnExpiration，使该 signal 的已有告警事件先关闭再打开断流事件；若业务要求保留原事件，记录原因并验证恢复与自动关闭行为。"
		metadata["critical_term_count"] = strconv.Itoa(criticalCount)
	case "disabled":
		if resource.Metadata[model.MetadataNewRelicNRQLCondition] != "true" ||
			resource.Metadata[model.MetadataDisabled] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityInfo
		category = model.FindingCategoryLifecycle
		findingType = "NewRelicDisabledCondition"
		evidence = fmt.Sprintf("New Relic NRQL condition %q is disabled but remains in the alert estate", resource.Name)
		recommendation = "确认该条件是否仍有恢复计划；若已废弃则按变更流程删除，若仍需要则修复后重新启用。"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.ID(), resource.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       category,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func newRelicThresholdPriorityCountsInvalid(termCount, criticalCount, warningCount int) bool {
	return termCount < 1 ||
		termCount > 2 ||
		criticalCount < 0 ||
		criticalCount > 1 ||
		warningCount < 0 ||
		warningCount > 1 ||
		criticalCount+warningCount != termCount
}
