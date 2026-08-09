package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestNewRelicGovernanceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	notReporting := newRelicEntityTestResource("not-reporting")
	notReporting.Metadata[model.MetadataNewRelicReporting] = "false"
	critical := newRelicEntityTestResource("critical")
	critical.Metadata[model.MetadataNewRelicAlertSeverity] = "CRITICAL"
	missingOwner := newRelicEntityTestResource("missing-owner")
	missingOwner.Metadata[model.MetadataNewRelicOwnershipDeclared] = "false"
	missingDescription := newRelicConditionTestResource("missing-description")
	missingDescription.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	missingDescription.Metadata[model.MetadataNewRelicDescriptionConfigured] = "false"
	missingTitleTemplate := newRelicConditionTestResource("missing-title-template")
	missingTitleTemplate.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	missingTitleTemplate.Metadata[model.MetadataNewRelicTitleTemplateConfigured] = "false"
	missingRunbook := newRelicConditionTestResource("missing-runbook")
	missingRunbook.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	missingRunbook.Metadata[model.MetadataNewRelicRunbookConfigured] = "false"
	missingEntityScope := newRelicConditionTestResource("missing-entity-scope")
	missingEntityScope.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	missingEntityScope.Metadata[model.MetadataNewRelicQueryScopeEvaluable] = "true"
	missingEntityScope.Metadata[model.MetadataNewRelicQueryScopeClausePresent] = "false"
	incompatibleNRQLClause := newRelicConditionTestResource("incompatible-nrql-clause")
	incompatibleNRQLClause.Metadata[model.MetadataNewRelicQueryCompatibilityEvaluable] = "true"
	incompatibleNRQLClause.Metadata[model.MetadataNewRelicQueryIncompatibleClauseCount] = "2"
	missingLossOfSignal := newRelicConditionTestResource("missing-loss-of-signal")
	missingLossOfSignal.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	missingLossOfSignal.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] = "true"
	missingLossOfSignal.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = "false"
	shortTimeLimit := newRelicConditionTestResource("short-time-limit")
	shortTimeLimit.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	shortTimeLimit.Metadata[model.MetadataNewRelicViolationTimeLimitSeconds] = "3600"
	cadence := newRelicConditionTestResource("cadence")
	cadence.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	cadence.Metadata[model.MetadataNewRelicAggregationMethod] = "CADENCE"
	invalidAggregationDelay := newRelicConditionTestResource("invalid-aggregation-delay")
	invalidAggregationDelay.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	invalidAggregationDelay.Metadata[model.MetadataNewRelicAggregationMethod] = "EVENT_FLOW"
	invalidAggregationDelay.Metadata[model.MetadataNewRelicAggregationDelay] = "1201"
	invalidAggregationDelay.Metadata[model.MetadataNewRelicAggregationDelayEvaluable] = "true"
	invalidAggregationDelay.Metadata[model.MetadataNewRelicAggregationDelayInvalid] = "true"
	invalidEventTimer := newRelicConditionTestResource("invalid-event-timer")
	invalidEventTimer.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	invalidEventTimer.Metadata[model.MetadataNewRelicAggregationMethod] = "EVENT_TIMER"
	invalidEventTimer.Metadata[model.MetadataNewRelicAggregationTimer] = "0"
	invalidWindow := newRelicConditionTestResource("invalid-window")
	invalidWindow.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	invalidWindow.Metadata[model.MetadataNewRelicAggregationWindow] = "0"
	shortEventTimer := newRelicConditionTestResource("short-event-timer")
	shortEventTimer.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	shortEventTimer.Metadata[model.MetadataNewRelicAggregationMethod] = "EVENT_TIMER"
	shortEventTimer.Metadata[model.MetadataNewRelicAggregationTimer] = "30"
	shortEventTimer.Metadata[model.MetadataNewRelicAggregationWindow] = "60"
	shortEventTimer.Metadata[model.MetadataNewRelicEventTimerWindowEvaluable] = "true"
	shortEventTimer.Metadata[model.MetadataNewRelicEventTimerShorterThanWindow] = "true"
	invalidThresholdDuration := newRelicConditionTestResource("invalid-threshold-duration")
	invalidThresholdDuration.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	invalidThresholdDuration.Metadata[model.MetadataNewRelicCriticalThresholdDurationMin] = "29"
	invalidThresholdDuration.Metadata[model.MetadataNewRelicCriticalThresholdDurationMax] = "29"
	invalidThresholdDuration.Metadata[model.MetadataNewRelicInvalidCriticalThresholdDurationCount] = "1"
	invalidBaselineThresholdDuration := newRelicConditionTestResource("invalid-baseline-threshold-duration")
	invalidBaselineThresholdDuration.Metadata[model.MetadataNewRelicConditionType] = "BASELINE"
	invalidBaselineThresholdDuration.Metadata[model.MetadataNewRelicTermCount] = "2"
	invalidBaselineThresholdDuration.Metadata[model.MetadataNewRelicInvalidBaselineThresholdDurationCount] = "1"
	invalidBaselineDirection := newRelicConditionTestResource("invalid-baseline-direction")
	invalidBaselineDirection.Metadata[model.MetadataNewRelicConditionType] = "BASELINE"
	invalidBaselineDirection.Metadata[model.MetadataNewRelicBaselineDirectionEvaluable] = "true"
	invalidBaselineDirection.Metadata[model.MetadataNewRelicBaselineDirectionInvalid] = "true"
	invalidStaticValueFunction := newRelicConditionTestResource("invalid-static-value-function")
	invalidStaticValueFunction.Metadata[model.MetadataNewRelicStaticValueFunctionEvaluable] = "true"
	invalidStaticValueFunction.Metadata[model.MetadataNewRelicStaticValueFunctionInvalid] = "true"
	invalidSlidingWindow := newRelicConditionTestResource("invalid-sliding-window")
	invalidSlidingWindow.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	invalidSlidingWindow.Metadata[model.MetadataNewRelicAggregationWindow] = "60"
	invalidSlidingWindow.Metadata[model.MetadataNewRelicSlideByDeclared] = "true"
	invalidSlidingWindow.Metadata[model.MetadataNewRelicSlideBySeconds] = "40"
	invalidSlidingWindow.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] = "true"
	invalidSlidingWindow.Metadata[model.MetadataNewRelicSlidingWindowInvalid] = "true"
	slidingWindowCost := newRelicConditionTestResource("sliding-window-cost")
	slidingWindowCost.Metadata[model.MetadataNewRelicTermCount] = "1"
	slidingWindowCost.Metadata[model.MetadataNewRelicAggregationWindow] = "60"
	slidingWindowCost.Metadata[model.MetadataNewRelicSlideByDeclared] = "true"
	slidingWindowCost.Metadata[model.MetadataNewRelicSlideBySeconds] = "30"
	slidingWindowCost.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] = "true"
	slidingWindowCost.Metadata[model.MetadataNewRelicSlidingWindowInvalid] = "false"
	slidingWindowCost.Metadata[model.MetadataNewRelicSlidingWindowOverlapFactor] = "2"
	invalidThresholdPriorityCount := newRelicConditionTestResource("invalid-threshold-priority-count")
	invalidThresholdPriorityCount.Metadata[model.MetadataNewRelicTermCount] = "2"
	invalidThresholdPriorityCount.Metadata[model.MetadataNewRelicCriticalTermCount] = "2"
	invalidThresholdPriorityCount.Metadata[model.MetadataNewRelicWarningTermCount] = "0"
	invalidThresholdPriorityCount.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = "true"
	invalidThresholdTermSemantics := newRelicConditionTestResource("invalid-threshold-term-semantics")
	invalidThresholdTermSemantics.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount] = "1"
	invalidThresholdTermSemantics.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount] = "1"
	invalidThresholdValue := newRelicConditionTestResource("invalid-threshold-value")
	invalidThresholdValue.Metadata[model.MetadataNewRelicInvalidThresholdValueCount] = "1"
	invalidGapFillOption := newRelicConditionTestResource("invalid-gap-fill-option")
	invalidGapFillOption.Metadata[model.MetadataNewRelicGapFillOption] = ""
	invalidGapFillOption.Metadata[model.MetadataNewRelicGapFillOptionInvalid] = "true"
	invalidStaticGapFillValue := newRelicConditionTestResource("invalid-static-gap-fill-value")
	invalidStaticGapFillValue.Metadata[model.MetadataNewRelicGapFillOption] = "STATIC"
	invalidStaticGapFillValue.Metadata[model.MetadataNewRelicStaticGapFillValueEvaluable] = "true"
	invalidStaticGapFillValue.Metadata[model.MetadataNewRelicStaticGapFillValueInvalid] = "true"
	perTargetIncidentFanout := newRelicConditionTestResource("per-target-incident-fanout")
	perTargetIncidentFanout.Metadata[model.MetadataNewRelicPolicyDeclared] = "true"
	perTargetIncidentFanout.Metadata[model.MetadataNewRelicIncidentPreference] = "PER_CONDITION_AND_TARGET"
	criticalAtLeastOnce := newRelicConditionTestResource("critical-at-least-once")
	criticalAtLeastOnce.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	criticalAtLeastOnce.Metadata[model.MetadataNewRelicWarningTermCount] = "0"
	criticalAtLeastOnce.Metadata[model.MetadataNewRelicCriticalAtLeastOnceTermCount] = "1"
	invalidLossSignalDuration := newRelicConditionTestResource("invalid-loss-signal-duration")
	invalidLossSignalDuration.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	invalidLossSignalDuration.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = "true"
	invalidLossSignalDuration.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] = "true"
	shortLossSignalDuration := newRelicConditionTestResource("short-loss-signal-duration")
	shortLossSignalDuration.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	shortLossSignalDuration.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = "true"
	shortLossSignalDuration.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] = "false"
	shortLossSignalDuration.Metadata[model.MetadataNewRelicLossOfSignalDurationShort] = "true"
	evaluationDelay := newRelicConditionTestResource("evaluation-delay")
	evaluationDelay.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	evaluationDelay.Metadata[model.MetadataNewRelicEvaluationDelayDeclared] = "true"
	evaluationDelay.Metadata[model.MetadataNewRelicEvaluationDelaySeconds] = "900"
	evaluationDelay.Metadata[model.MetadataNewRelicEvaluationDelayInvalid] = "false"
	lastValueGapFilling := newRelicConditionTestResource("last-value-gap-filling")
	lastValueGapFilling.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	lastValueGapFilling.Metadata[model.MetadataNewRelicGapFillOption] = "LAST_VALUE"
	staticGapFillBreach := newRelicConditionTestResource("static-gap-fill-breach")
	staticGapFillBreach.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	staticGapFillBreach.Metadata[model.MetadataNewRelicGapFillOption] = "STATIC"
	staticGapFillBreach.Metadata[model.MetadataNewRelicStaticGapFillEvaluable] = "true"
	staticGapFillBreach.Metadata[model.MetadataNewRelicStaticGapFillCriticalBreachCount] = "1"
	missingCloseOnSignalLoss := newRelicConditionTestResource("missing-close-on-signal-loss")
	missingCloseOnSignalLoss.Metadata[model.MetadataNewRelicCriticalTermCount] = "1"
	missingCloseOnSignalLoss.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = "true"
	missingCloseOnSignalLoss.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] = "false"
	missingCloseOnSignalLoss.Metadata[model.MetadataNewRelicLossOfSignalCloseEvaluable] = "true"
	missingCloseOnSignalLoss.Metadata[model.MetadataNewRelicLossOfSignalCloseConfigured] = "false"
	disabled := newRelicConditionTestResource("disabled")
	disabled.Status = model.ResourceStatusDeprecated
	disabled.Metadata[model.MetadataEnabled] = "false"
	disabled.Metadata[model.MetadataDisabled] = "true"
	for _, resource := range []model.Resource{notReporting, critical, missingOwner, missingDescription, missingTitleTemplate, missingRunbook, missingEntityScope, incompatibleNRQLClause, missingLossOfSignal, shortTimeLimit, cadence, invalidAggregationDelay, invalidEventTimer, invalidWindow, shortEventTimer, invalidThresholdDuration, invalidBaselineThresholdDuration, invalidBaselineDirection, invalidStaticValueFunction, invalidSlidingWindow, slidingWindowCost, invalidThresholdPriorityCount, invalidThresholdTermSemantics, invalidThresholdValue, invalidGapFillOption, invalidStaticGapFillValue, perTargetIncidentFanout, criticalAtLeastOnce, invalidLossSignalDuration, shortLossSignalDuration, evaluationDelay, lastValueGapFilling, staticGapFillBreach, missingCloseOnSignalLoss, disabled} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		typ      string
		severity model.Severity
		category model.FindingCategory
	}{
		{NewNewRelicEntityNotReportingAnalyzer(), "not-reporting", "NewRelicEntityNotReporting", model.SeverityCritical, model.FindingCategoryReliability},
		{NewNewRelicEntityCriticalAnalyzer(), "critical", "NewRelicEntityCritical", model.SeverityCritical, model.FindingCategoryReliability},
		{NewNewRelicEntityWithoutOwnerAnalyzer(), "missing-owner", "NewRelicEntityWithoutOwner", model.SeverityWarning, model.FindingCategoryLifecycle},
		{NewNewRelicCriticalConditionWithoutDescriptionAnalyzer(), "missing-description", "NewRelicCriticalConditionWithoutDescription", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicCriticalConditionWithoutTitleTemplateAnalyzer(), "missing-title-template", "NewRelicCriticalConditionWithoutTitleTemplate", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicCriticalConditionWithoutRunbookAnalyzer(), "missing-runbook", "NewRelicCriticalConditionWithoutRunbook", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicCriticalConditionWithoutEntityScopeAnalyzer(), "missing-entity-scope", "NewRelicCriticalConditionWithoutEntityScope", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicConditionIncompatibleNRQLClauseAnalyzer(), "incompatible-nrql-clause", "NewRelicConditionIncompatibleNRQLClause", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicCriticalConditionWithoutLossOfSignalAnalyzer(), "missing-loss-of-signal", "NewRelicCriticalConditionWithoutLossOfSignal", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionShortTimeLimitAnalyzer(), "short-time-limit", "NewRelicCriticalConditionShortViolationTimeLimit", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionCadenceAggregationAnalyzer(), "cadence", "NewRelicCriticalConditionCadenceAggregation", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionInvalidAggregationDelayAnalyzer(), "invalid-aggregation-delay", "NewRelicCriticalConditionInvalidAggregationDelay", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionInvalidEventTimerAnalyzer(), "invalid-event-timer", "NewRelicCriticalConditionInvalidEventTimer", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionInvalidAggregationWindowAnalyzer(), "invalid-window", "NewRelicCriticalConditionInvalidAggregationWindow", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionEventTimerShorterThanWindowAnalyzer(), "short-event-timer", "NewRelicCriticalConditionEventTimerShorterThanWindow", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionInvalidThresholdDurationAnalyzer(), "invalid-threshold-duration", "NewRelicCriticalConditionInvalidThresholdDuration", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicBaselineConditionInvalidThresholdDurationAnalyzer(), "invalid-baseline-threshold-duration", "NewRelicBaselineConditionInvalidThresholdDuration", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicBaselineConditionInvalidDirectionAnalyzer(), "invalid-baseline-direction", "NewRelicBaselineConditionInvalidDirection", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicStaticConditionInvalidValueFunctionAnalyzer(), "invalid-static-value-function", "NewRelicStaticConditionInvalidValueFunction", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicCriticalConditionInvalidSlidingWindowAnalyzer(), "invalid-sliding-window", "NewRelicCriticalConditionInvalidSlidingWindow", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicConditionSlidingWindowCostAnalyzer(), "sliding-window-cost", "NewRelicConditionSlidingWindowCost", model.SeverityWarning, model.FindingCategoryCost},
		{NewNewRelicConditionInvalidThresholdPriorityCountAnalyzer(), "invalid-threshold-priority-count", "NewRelicConditionInvalidThresholdPriorityCount", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicConditionInvalidThresholdTermSemanticsAnalyzer(), "invalid-threshold-term-semantics", "NewRelicConditionInvalidThresholdTermSemantics", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicConditionInvalidThresholdValueAnalyzer(), "invalid-threshold-value", "NewRelicConditionInvalidThresholdValue", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicConditionInvalidGapFillOptionAnalyzer(), "invalid-gap-fill-option", "NewRelicConditionInvalidGapFillOption", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicConditionInvalidStaticGapFillValueAnalyzer(), "invalid-static-gap-fill-value", "NewRelicConditionInvalidStaticGapFillValue", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewNewRelicConditionPerTargetIncidentFanoutAnalyzer(), "per-target-incident-fanout", "NewRelicConditionPerTargetIncidentFanout", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionAtLeastOnceAnalyzer(), "critical-at-least-once", "NewRelicCriticalConditionAtLeastOnceThreshold", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionInvalidLossOfSignalDurationAnalyzer(), "invalid-loss-signal-duration", "NewRelicCriticalConditionInvalidLossOfSignalDuration", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionShortLossOfSignalDurationAnalyzer(), "short-loss-signal-duration", "NewRelicCriticalConditionShortLossOfSignalDuration", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionEvaluationDelayAnalyzer(), "evaluation-delay", "NewRelicCriticalConditionEvaluationDelay", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionLastValueGapFillingAnalyzer(), "last-value-gap-filling", "NewRelicCriticalConditionLastValueGapFilling", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionStaticGapFillBreachesThresholdAnalyzer(), "static-gap-fill-breach", "NewRelicCriticalConditionStaticGapFillBreachesThreshold", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicCriticalConditionWithoutCloseOnSignalLossAnalyzer(), "missing-close-on-signal-loss", "NewRelicCriticalConditionWithoutCloseOnSignalLoss", model.SeverityWarning, model.FindingCategoryReliability},
		{NewNewRelicDisabledConditionAnalyzer(), "disabled", "NewRelicDisabledCondition", model.SeverityInfo, model.FindingCategoryLifecycle},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil {
			t.Fatalf("%s: %v", test.analyzer.ID(), err)
		}
		if len(findings) != 1 || findings[0].Resource.ID != test.resource ||
			findings[0].Type != test.typ || findings[0].Severity != test.severity ||
			findings[0].Category != test.category {
			t.Fatalf("%s unexpected findings %#v", test.analyzer.ID(), findings)
		}
		if got := model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type); got != test.category {
			t.Fatalf("%s default category %s", test.analyzer.ID(), got)
		}
	}
}

func TestNewRelicCriticalConditionShortTimeLimitAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		limit         string
		enabled       string
	}{
		{name: "unknown zero", criticalTerms: "1", limit: "0", enabled: "true"},
		{name: "default boundary", criticalTerms: "1", limit: "259200", enabled: "true"},
		{name: "above default", criticalTerms: "1", limit: "259201", enabled: "true"},
		{name: "malformed", criticalTerms: "1", limit: "private-value", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", limit: "3600", enabled: "true"},
		{name: "disabled", criticalTerms: "1", limit: "3600", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionShortTimeLimitAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicViolationTimeLimitSeconds] = test.limit
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			if finding, ok := analyzer.finding(resource, time.Now().UTC()); ok {
				t.Fatalf("expected suppression, got %#v", finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionInvalidAggregationDelayAnalyzerGates(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		delay       string
		evaluable   string
		invalid     string
		critical    string
		enabled     string
		wantFinding bool
	}{
		{name: "event flow below minimum", method: "EVENT_FLOW", delay: "-1", evaluable: "true", invalid: "true", critical: "1", enabled: "true", wantFinding: true},
		{name: "event flow above maximum", method: "EVENT_FLOW", delay: "1201", evaluable: "true", invalid: "true", critical: "1", enabled: "true", wantFinding: true},
		{name: "cadence above maximum", method: "CADENCE", delay: "3601", evaluable: "true", invalid: "true", critical: "1", enabled: "true", wantFinding: true},
		{name: "event flow minimum", method: "EVENT_FLOW", delay: "0", evaluable: "true", invalid: "false", critical: "1", enabled: "true"},
		{name: "event flow maximum", method: "EVENT_FLOW", delay: "1200", evaluable: "true", invalid: "false", critical: "1", enabled: "true"},
		{name: "cadence maximum", method: "CADENCE", delay: "3600", evaluable: "true", invalid: "false", critical: "1", enabled: "true"},
		{name: "inconsistent derived state", method: "EVENT_FLOW", delay: "1200", evaluable: "true", invalid: "true", critical: "1", enabled: "true"},
		{name: "event timer", method: "EVENT_TIMER", delay: "1201", evaluable: "false", invalid: "false", critical: "1", enabled: "true"},
		{name: "unknown method", method: "FUTURE", delay: "1201", evaluable: "false", invalid: "false", critical: "1", enabled: "true"},
		{name: "malformed delay", method: "EVENT_FLOW", delay: "private-value", evaluable: "true", invalid: "true", critical: "1", enabled: "true"},
		{name: "no critical term", method: "EVENT_FLOW", delay: "1201", evaluable: "true", invalid: "true", critical: "0", enabled: "true"},
		{name: "malformed critical count", method: "EVENT_FLOW", delay: "1201", evaluable: "true", invalid: "true", critical: "unknown", enabled: "true"},
		{name: "disabled", method: "EVENT_FLOW", delay: "1201", evaluable: "true", invalid: "true", critical: "1", enabled: "false"},
	}
	item := NewNewRelicCriticalConditionInvalidAggregationDelayAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicAggregationMethod] = test.method
			resource.Metadata[model.MetadataNewRelicAggregationDelay] = test.delay
			resource.Metadata[model.MetadataNewRelicAggregationDelayEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicAggregationDelayInvalid] = test.invalid
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.critical
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("got finding=%t %#v, want %t", ok, finding, test.wantFinding)
			}
		})
	}
}

func TestNewRelicCriticalConditionWithoutEntityScopeAnalyzerGates(t *testing.T) {
	tests := []struct {
		name        string
		evaluable   string
		scopeClause string
		critical    string
		enabled     string
		wantFinding bool
	}{
		{name: "missing scope clause", evaluable: "true", scopeClause: "false", critical: "1", enabled: "true", wantFinding: true},
		{name: "where or facet present", evaluable: "true", scopeClause: "true", critical: "1", enabled: "true"},
		{name: "nested or malformed query", evaluable: "false", scopeClause: "false", critical: "1", enabled: "true"},
		{name: "missing evaluability metadata", scopeClause: "false", critical: "1", enabled: "true"},
		{name: "warning only", evaluable: "true", scopeClause: "false", critical: "0", enabled: "true"},
		{name: "malformed critical count", evaluable: "true", scopeClause: "false", critical: "unknown", enabled: "true"},
		{name: "disabled", evaluable: "true", scopeClause: "false", critical: "1", enabled: "false"},
	}
	item := NewNewRelicCriticalConditionWithoutEntityScopeAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicQueryScopeEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicQueryScopeClausePresent] = test.scopeClause
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.critical
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("got finding=%t %#v, want %t", ok, finding, test.wantFinding)
			}
		})
	}
}

func TestNewRelicConditionIncompatibleNRQLClauseAnalyzerGates(t *testing.T) {
	tests := []struct {
		name         string
		evaluable    string
		incompatible string
		enabled      string
		wantFinding  bool
	}{
		{name: "one incompatible clause", evaluable: "true", incompatible: "1", enabled: "true", wantFinding: true},
		{name: "multiple incompatible clauses", evaluable: "true", incompatible: "6", enabled: "true", wantFinding: true},
		{name: "compatible", evaluable: "true", incompatible: "0", enabled: "true"},
		{name: "nested or malformed", evaluable: "false", incompatible: "1", enabled: "true"},
		{name: "missing evaluability metadata", incompatible: "1", enabled: "true"},
		{name: "negative count", evaluable: "true", incompatible: "-1", enabled: "true"},
		{name: "malformed count", evaluable: "true", incompatible: "unknown", enabled: "true"},
		{name: "disabled", evaluable: "true", incompatible: "1", enabled: "false"},
	}
	item := NewNewRelicConditionIncompatibleNRQLClauseAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicQueryCompatibilityEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicQueryIncompatibleClauseCount] = test.incompatible
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("got finding=%t %#v, want %t", ok, finding, test.wantFinding)
			}
		})
	}
}

func TestNewRelicCriticalConditionTitleTemplateAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		configured    string
		enabled       string
	}{
		{name: "configured", criticalTerms: "1", configured: "true", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", configured: "false", enabled: "true"},
		{name: "malformed critical count", criticalTerms: "unknown", configured: "false", enabled: "true"},
		{name: "disabled", criticalTerms: "1", configured: "false", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionWithoutTitleTemplateAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicTitleTemplateConfigured] = test.configured
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			if finding, ok := analyzer.finding(resource, time.Now().UTC()); ok {
				t.Fatalf("expected suppression, got %#v", finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionCadenceAggregationAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		method        string
		enabled       string
	}{
		{name: "event flow", criticalTerms: "1", method: "EVENT_FLOW", enabled: "true"},
		{name: "event timer", criticalTerms: "1", method: "EVENT_TIMER", enabled: "true"},
		{name: "unknown method", criticalTerms: "1", method: "", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", method: "CADENCE", enabled: "true"},
		{name: "malformed critical count", criticalTerms: "unknown", method: "CADENCE", enabled: "true"},
		{name: "disabled", criticalTerms: "1", method: "CADENCE", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionCadenceAggregationAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicAggregationMethod] = test.method
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			if finding, ok := analyzer.finding(resource, time.Now().UTC()); ok {
				t.Fatalf("expected suppression, got %#v", finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionInvalidEventTimerAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		method        string
		timer         string
		enabled       string
		wantFinding   bool
	}{
		{name: "missing timer", criticalTerms: "1", method: "EVENT_TIMER", timer: "0", enabled: "true", wantFinding: true},
		{name: "below minimum", criticalTerms: "1", method: "EVENT_TIMER", timer: "4", enabled: "true", wantFinding: true},
		{name: "minimum", criticalTerms: "1", method: "EVENT_TIMER", timer: "5", enabled: "true"},
		{name: "maximum", criticalTerms: "1", method: "EVENT_TIMER", timer: "1200", enabled: "true"},
		{name: "above maximum", criticalTerms: "1", method: "EVENT_TIMER", timer: "1201", enabled: "true", wantFinding: true},
		{name: "malformed timer", criticalTerms: "1", method: "EVENT_TIMER", timer: "unknown", enabled: "true"},
		{name: "event flow", criticalTerms: "1", method: "EVENT_FLOW", timer: "0", enabled: "true"},
		{name: "cadence", criticalTerms: "1", method: "CADENCE", timer: "0", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", method: "EVENT_TIMER", timer: "0", enabled: "true"},
		{name: "disabled", criticalTerms: "1", method: "EVENT_TIMER", timer: "0", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionInvalidEventTimerAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicAggregationMethod] = test.method
			resource.Metadata[model.MetadataNewRelicAggregationTimer] = test.timer
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionInvalidAggregationWindowAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		window        string
		enabled       string
		wantFinding   bool
	}{
		{name: "missing window", criticalTerms: "1", window: "0", enabled: "true", wantFinding: true},
		{name: "below minimum", criticalTerms: "1", window: "29", enabled: "true", wantFinding: true},
		{name: "minimum", criticalTerms: "1", window: "30", enabled: "true"},
		{name: "maximum", criticalTerms: "1", window: "21600", enabled: "true"},
		{name: "above maximum", criticalTerms: "1", window: "21601", enabled: "true", wantFinding: true},
		{name: "malformed window", criticalTerms: "1", window: "unknown", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", window: "0", enabled: "true"},
		{name: "disabled", criticalTerms: "1", window: "0", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionInvalidAggregationWindowAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicAggregationWindow] = test.window
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionEventTimerShorterThanWindowAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		method        string
		timer         string
		window        string
		evaluable     string
		shorter       string
		enabled       string
		wantFinding   bool
	}{
		{name: "shorter", criticalTerms: "1", method: "EVENT_TIMER", timer: "30", window: "60", evaluable: "true", shorter: "true", enabled: "true", wantFinding: true},
		{name: "equal boundary", criticalTerms: "1", method: "EVENT_TIMER", timer: "60", window: "60", evaluable: "true", shorter: "false", enabled: "true"},
		{name: "longer", criticalTerms: "1", method: "EVENT_TIMER", timer: "90", window: "60", evaluable: "true", shorter: "false", enabled: "true"},
		{name: "invalid timer", criticalTerms: "1", method: "EVENT_TIMER", timer: "4", window: "60", evaluable: "false", shorter: "false", enabled: "true"},
		{name: "invalid window", criticalTerms: "1", method: "EVENT_TIMER", timer: "30", window: "29", evaluable: "false", shorter: "false", enabled: "true"},
		{name: "malformed timer", criticalTerms: "1", method: "EVENT_TIMER", timer: "unknown", window: "60", evaluable: "true", shorter: "true", enabled: "true"},
		{name: "malformed window", criticalTerms: "1", method: "EVENT_TIMER", timer: "30", window: "unknown", evaluable: "true", shorter: "true", enabled: "true"},
		{name: "inconsistent derived flag", criticalTerms: "1", method: "EVENT_TIMER", timer: "60", window: "30", evaluable: "true", shorter: "true", enabled: "true"},
		{name: "event flow", criticalTerms: "1", method: "EVENT_FLOW", timer: "30", window: "60", evaluable: "false", shorter: "false", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", method: "EVENT_TIMER", timer: "30", window: "60", evaluable: "true", shorter: "true", enabled: "true"},
		{name: "disabled", criticalTerms: "1", method: "EVENT_TIMER", timer: "30", window: "60", evaluable: "true", shorter: "true", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionEventTimerShorterThanWindowAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicAggregationMethod] = test.method
			resource.Metadata[model.MetadataNewRelicAggregationTimer] = test.timer
			resource.Metadata[model.MetadataNewRelicAggregationWindow] = test.window
			resource.Metadata[model.MetadataNewRelicEventTimerWindowEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicEventTimerShorterThanWindow] = test.shorter
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionInvalidThresholdDurationAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		conditionType string
		criticalTerms string
		invalidCount  string
		minSeconds    string
		maxSeconds    string
		enabled       string
		wantFinding   bool
	}{
		{name: "missing duration", criticalTerms: "1", invalidCount: "1", minSeconds: "0", maxSeconds: "0", enabled: "true", wantFinding: true},
		{name: "below minimum", criticalTerms: "1", invalidCount: "1", minSeconds: "29", maxSeconds: "29", enabled: "true", wantFinding: true},
		{name: "minimum", criticalTerms: "1", invalidCount: "0", minSeconds: "30", maxSeconds: "30", enabled: "true"},
		{name: "maximum", criticalTerms: "1", invalidCount: "0", minSeconds: "7200", maxSeconds: "7200", enabled: "true"},
		{name: "above maximum", criticalTerms: "1", invalidCount: "1", minSeconds: "7201", maxSeconds: "7201", enabled: "true", wantFinding: true},
		{name: "mixed invalid range", criticalTerms: "2", invalidCount: "2", minSeconds: "29", maxSeconds: "7201", enabled: "true", wantFinding: true},
		{name: "malformed invalid count", criticalTerms: "1", invalidCount: "unknown", minSeconds: "29", maxSeconds: "29", enabled: "true"},
		{name: "malformed minimum", criticalTerms: "1", invalidCount: "1", minSeconds: "unknown", maxSeconds: "29", enabled: "true"},
		{name: "malformed maximum", criticalTerms: "1", invalidCount: "1", minSeconds: "29", maxSeconds: "unknown", enabled: "true"},
		{name: "inconsistent invalid flag", criticalTerms: "1", invalidCount: "1", minSeconds: "30", maxSeconds: "7200", enabled: "true"},
		{name: "inverted range", criticalTerms: "1", invalidCount: "1", minSeconds: "7201", maxSeconds: "29", enabled: "true"},
		{name: "baseline owned by type-specific analyzer", conditionType: "BASELINE", criticalTerms: "1", invalidCount: "1", minSeconds: "29", maxSeconds: "29", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", invalidCount: "0", minSeconds: "0", maxSeconds: "0", enabled: "true"},
		{name: "disabled", criticalTerms: "1", invalidCount: "1", minSeconds: "29", maxSeconds: "29", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionInvalidThresholdDurationAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicConditionType] = test.conditionType
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicInvalidCriticalThresholdDurationCount] = test.invalidCount
			resource.Metadata[model.MetadataNewRelicCriticalThresholdDurationMin] = test.minSeconds
			resource.Metadata[model.MetadataNewRelicCriticalThresholdDurationMax] = test.maxSeconds
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicBaselineConditionInvalidThresholdDurationAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		conditionType string
		termCount     string
		invalidCount  string
		enabled       string
		wantFinding   bool
	}{
		{name: "one invalid term", conditionType: "BASELINE", termCount: "1", invalidCount: "1", enabled: "true", wantFinding: true},
		{name: "mixed valid and invalid terms", conditionType: "baseline", termCount: "2", invalidCount: "1", enabled: "true", wantFinding: true},
		{name: "all valid", conditionType: "BASELINE", termCount: "2", invalidCount: "0", enabled: "true"},
		{name: "static", conditionType: "STATIC", termCount: "1", invalidCount: "1", enabled: "true"},
		{name: "zero terms", conditionType: "BASELINE", termCount: "0", invalidCount: "0", enabled: "true"},
		{name: "malformed term count", conditionType: "BASELINE", termCount: "unknown", invalidCount: "1", enabled: "true"},
		{name: "malformed invalid count", conditionType: "BASELINE", termCount: "1", invalidCount: "unknown", enabled: "true"},
		{name: "negative invalid count", conditionType: "BASELINE", termCount: "1", invalidCount: "-1", enabled: "true"},
		{name: "invalid count exceeds terms", conditionType: "BASELINE", termCount: "1", invalidCount: "2", enabled: "true"},
		{name: "disabled", conditionType: "BASELINE", termCount: "1", invalidCount: "1", enabled: "false"},
	}
	item := NewNewRelicBaselineConditionInvalidThresholdDurationAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicConditionType] = test.conditionType
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicInvalidBaselineThresholdDurationCount] = test.invalidCount
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("got finding=%t %#v, want %t", ok, finding, test.wantFinding)
			}
		})
	}
}

func TestNewRelicBaselineConditionInvalidDirectionAnalyzerGates(t *testing.T) {
	tests := []struct {
		name            string
		conditionType   string
		termCount       string
		priorityInvalid string
		evaluable       string
		invalid         string
		enabled         string
		wantFinding     bool
	}{
		{name: "missing direction", conditionType: "BASELINE", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "unknown direction", conditionType: "baseline", termCount: "2", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "valid direction", conditionType: "BASELINE", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "static", conditionType: "STATIC", termCount: "1", priorityInvalid: "false", evaluable: "false", invalid: "false", enabled: "true"},
		{name: "zero terms", conditionType: "BASELINE", termCount: "0", priorityInvalid: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "too many terms owned by priority analyzer", conditionType: "BASELINE", termCount: "3", priorityInvalid: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "invalid priority owned elsewhere", conditionType: "BASELINE", termCount: "1", priorityInvalid: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "malformed term count", conditionType: "BASELINE", termCount: "unknown", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "unevaluable", conditionType: "BASELINE", termCount: "1", priorityInvalid: "false", evaluable: "false", invalid: "true", enabled: "true"},
		{name: "inconsistent invalid flag", conditionType: "BASELINE", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "disabled", conditionType: "BASELINE", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "false"},
	}
	item := NewNewRelicBaselineConditionInvalidDirectionAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicConditionType] = test.conditionType
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.priorityInvalid
			resource.Metadata[model.MetadataNewRelicBaselineDirectionEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicBaselineDirectionInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("got finding=%t %#v, want %t", ok, finding, test.wantFinding)
			}
			if ok {
				if finding.Metadata["term_count"] != test.termCount ||
					finding.Metadata["baseline_direction"] != "" {
					t.Fatalf("unexpected privacy-safe finding metadata: %#v", finding.Metadata)
				}
			}
		})
	}
}

func TestNewRelicStaticConditionInvalidValueFunctionAnalyzerGates(t *testing.T) {
	tests := []struct {
		name            string
		conditionType   string
		termCount       string
		priorityInvalid string
		evaluable       string
		invalid         string
		enabled         string
		wantFinding     bool
	}{
		{name: "missing value function", conditionType: "STATIC", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "unknown value function", conditionType: "static", termCount: "2", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "valid value function", conditionType: "STATIC", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "baseline", conditionType: "BASELINE", termCount: "1", priorityInvalid: "false", evaluable: "false", invalid: "false", enabled: "true"},
		{name: "zero terms", conditionType: "STATIC", termCount: "0", priorityInvalid: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "too many terms owned by priority analyzer", conditionType: "STATIC", termCount: "3", priorityInvalid: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "invalid priority owned elsewhere", conditionType: "STATIC", termCount: "1", priorityInvalid: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "malformed term count", conditionType: "STATIC", termCount: "unknown", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "unevaluable", conditionType: "STATIC", termCount: "1", priorityInvalid: "false", evaluable: "false", invalid: "true", enabled: "true"},
		{name: "inconsistent invalid flag", conditionType: "STATIC", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "disabled", conditionType: "STATIC", termCount: "1", priorityInvalid: "false", evaluable: "true", invalid: "true", enabled: "false"},
	}
	item := NewNewRelicStaticConditionInvalidValueFunctionAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicConditionType] = test.conditionType
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.priorityInvalid
			resource.Metadata[model.MetadataNewRelicStaticValueFunctionEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicStaticValueFunctionInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("got finding=%t %#v, want %t", ok, finding, test.wantFinding)
			}
			if ok {
				if finding.Metadata["term_count"] != test.termCount ||
					finding.Metadata["value_function"] != "" {
					t.Fatalf("unexpected privacy-safe finding metadata: %#v", finding.Metadata)
				}
			}
		})
	}
}

func TestNewRelicCriticalConditionInvalidSlidingWindowAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		criticalTerms string
		window        string
		declared      string
		slideBy       string
		evaluable     string
		invalid       string
		enabled       string
		wantFinding   bool
	}{
		{name: "not configured", criticalTerms: "1", window: "60", declared: "false", slideBy: "0", evaluable: "false", invalid: "false", enabled: "true"},
		{name: "zero", criticalTerms: "1", window: "60", declared: "true", slideBy: "0", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "negative", criticalTerms: "1", window: "60", declared: "true", slideBy: "-30", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "equal window", criticalTerms: "1", window: "60", declared: "true", slideBy: "60", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "above window", criticalTerms: "1", window: "60", declared: "true", slideBy: "90", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "not divisor", criticalTerms: "1", window: "60", declared: "true", slideBy: "40", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "valid divisor", criticalTerms: "1", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "invalid window owned elsewhere", criticalTerms: "1", window: "29", declared: "true", slideBy: "10", evaluable: "false", invalid: "false", enabled: "true"},
		{name: "malformed window", criticalTerms: "1", window: "unknown", declared: "true", slideBy: "40", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "malformed slide by", criticalTerms: "1", window: "60", declared: "true", slideBy: "unknown", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "inconsistent invalid flag", criticalTerms: "1", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "invalid but derived healthy", criticalTerms: "1", window: "60", declared: "true", slideBy: "40", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "no critical term", criticalTerms: "0", window: "60", declared: "true", slideBy: "40", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "disabled", criticalTerms: "1", window: "60", declared: "true", slideBy: "40", evaluable: "true", invalid: "true", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionInvalidSlidingWindowAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalTerms
			resource.Metadata[model.MetadataNewRelicAggregationWindow] = test.window
			resource.Metadata[model.MetadataNewRelicSlideByDeclared] = test.declared
			resource.Metadata[model.MetadataNewRelicSlideBySeconds] = test.slideBy
			resource.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicSlidingWindowInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionSlidingWindowCostAnalyzerGates(t *testing.T) {
	tests := []struct {
		name        string
		termCount   string
		window      string
		declared    string
		slideBy     string
		evaluable   string
		invalid     string
		factor      string
		enabled     string
		wantFinding bool
	}{
		{name: "valid warning-only condition", termCount: "1", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "2", enabled: "true", wantFinding: true},
		{name: "higher overlap", termCount: "1", window: "60", declared: "true", slideBy: "15", evaluable: "true", invalid: "false", factor: "4", enabled: "true", wantFinding: true},
		{name: "not configured", termCount: "1", window: "60", declared: "false", slideBy: "0", evaluable: "false", invalid: "false", factor: "0", enabled: "true"},
		{name: "invalid configuration", termCount: "1", window: "60", declared: "true", slideBy: "40", evaluable: "true", invalid: "true", factor: "0", enabled: "true"},
		{name: "invalid window", termCount: "1", window: "29", declared: "true", slideBy: "10", evaluable: "false", invalid: "false", factor: "0", enabled: "true"},
		{name: "no term", termCount: "0", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "2", enabled: "true"},
		{name: "malformed term count", termCount: "unknown", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "2", enabled: "true"},
		{name: "malformed window", termCount: "1", window: "unknown", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "2", enabled: "true"},
		{name: "malformed slide by", termCount: "1", window: "60", declared: "true", slideBy: "unknown", evaluable: "true", invalid: "false", factor: "2", enabled: "true"},
		{name: "malformed factor", termCount: "1", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "unknown", enabled: "true"},
		{name: "inconsistent factor", termCount: "1", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "4", enabled: "true"},
		{name: "disabled", termCount: "1", window: "60", declared: "true", slideBy: "30", evaluable: "true", invalid: "false", factor: "2", enabled: "false"},
	}
	analyzer := NewNewRelicConditionSlidingWindowCostAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicAggregationWindow] = test.window
			resource.Metadata[model.MetadataNewRelicSlideByDeclared] = test.declared
			resource.Metadata[model.MetadataNewRelicSlideBySeconds] = test.slideBy
			resource.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicSlidingWindowInvalid] = test.invalid
			resource.Metadata[model.MetadataNewRelicSlidingWindowOverlapFactor] = test.factor
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionInvalidThresholdPriorityCountAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		termCount     string
		criticalCount string
		warningCount  string
		invalid       string
		enabled       string
		wantFinding   bool
	}{
		{name: "no threshold", termCount: "0", criticalCount: "0", warningCount: "0", invalid: "true", enabled: "true", wantFinding: true},
		{name: "one critical", termCount: "1", criticalCount: "1", warningCount: "0", invalid: "false", enabled: "true"},
		{name: "one warning", termCount: "1", criticalCount: "0", warningCount: "1", invalid: "false", enabled: "true"},
		{name: "one each", termCount: "2", criticalCount: "1", warningCount: "1", invalid: "false", enabled: "true"},
		{name: "duplicate critical", termCount: "2", criticalCount: "2", warningCount: "0", invalid: "true", enabled: "true", wantFinding: true},
		{name: "duplicate warning", termCount: "2", criticalCount: "0", warningCount: "2", invalid: "true", enabled: "true", wantFinding: true},
		{name: "three thresholds", termCount: "3", criticalCount: "1", warningCount: "2", invalid: "true", enabled: "true", wantFinding: true},
		{name: "unknown priority", termCount: "1", criticalCount: "0", warningCount: "0", invalid: "true", enabled: "true", wantFinding: true},
		{name: "malformed term count", termCount: "unknown", criticalCount: "0", warningCount: "0", invalid: "true", enabled: "true"},
		{name: "malformed critical count", termCount: "1", criticalCount: "unknown", warningCount: "0", invalid: "true", enabled: "true"},
		{name: "malformed warning count", termCount: "1", criticalCount: "0", warningCount: "unknown", invalid: "true", enabled: "true"},
		{name: "inconsistent invalid flag", termCount: "1", criticalCount: "1", warningCount: "0", invalid: "true", enabled: "true"},
		{name: "invalid but derived healthy", termCount: "2", criticalCount: "2", warningCount: "0", invalid: "false", enabled: "true"},
		{name: "disabled", termCount: "2", criticalCount: "2", warningCount: "0", invalid: "true", enabled: "false"},
	}
	analyzer := NewNewRelicConditionInvalidThresholdPriorityCountAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicWarningTermCount] = test.warningCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionInvalidThresholdTermSemanticsAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name              string
		termCount         string
		invalidPriority   string
		invalidOperators  string
		invalidOccurrence string
		enabled           string
		wantFinding       bool
	}{
		{name: "invalid operator", termCount: "1", invalidPriority: "false", invalidOperators: "1", invalidOccurrence: "0", enabled: "true", wantFinding: true},
		{name: "invalid occurrence", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "1", enabled: "true", wantFinding: true},
		{name: "both invalid", termCount: "2", invalidPriority: "false", invalidOperators: "1", invalidOccurrence: "2", enabled: "true", wantFinding: true},
		{name: "healthy", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", enabled: "true"},
		{name: "no terms owned by structure", termCount: "0", invalidPriority: "true", invalidOperators: "0", invalidOccurrence: "0", enabled: "true"},
		{name: "too many terms owned by structure", termCount: "3", invalidPriority: "true", invalidOperators: "1", invalidOccurrence: "1", enabled: "true"},
		{name: "invalid priority owns condition", termCount: "1", invalidPriority: "true", invalidOperators: "1", invalidOccurrence: "1", enabled: "true"},
		{name: "malformed term count", termCount: "unknown", invalidPriority: "false", invalidOperators: "1", invalidOccurrence: "0", enabled: "true"},
		{name: "malformed operator count", termCount: "1", invalidPriority: "false", invalidOperators: "unknown", invalidOccurrence: "0", enabled: "true"},
		{name: "malformed occurrence count", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "unknown", enabled: "true"},
		{name: "negative operator count", termCount: "1", invalidPriority: "false", invalidOperators: "-1", invalidOccurrence: "1", enabled: "true"},
		{name: "operator count exceeds terms", termCount: "1", invalidPriority: "false", invalidOperators: "2", invalidOccurrence: "0", enabled: "true"},
		{name: "occurrence count exceeds terms", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "2", enabled: "true"},
		{name: "disabled", termCount: "1", invalidPriority: "false", invalidOperators: "1", invalidOccurrence: "1", enabled: "false"},
	}
	item := NewNewRelicConditionInvalidThresholdTermSemanticsAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.invalidPriority
			resource.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount] = test.invalidOperators
			resource.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount] = test.invalidOccurrence
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionInvalidThresholdValueAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name              string
		termCount         string
		invalidPriority   string
		invalidOperators  string
		invalidOccurrence string
		invalidValues     string
		enabled           string
		wantFinding       bool
	}{
		{name: "one invalid value", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "1", enabled: "true", wantFinding: true},
		{name: "one of two invalid", termCount: "2", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "1", enabled: "true", wantFinding: true},
		{name: "both invalid", termCount: "2", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "2", enabled: "true", wantFinding: true},
		{name: "healthy", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "0", enabled: "true"},
		{name: "invalid operator owned by semantics", termCount: "1", invalidPriority: "false", invalidOperators: "1", invalidOccurrence: "0", invalidValues: "1", enabled: "true"},
		{name: "invalid occurrence owned by semantics", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "1", invalidValues: "1", enabled: "true"},
		{name: "invalid priority owned by structure", termCount: "1", invalidPriority: "true", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "1", enabled: "true"},
		{name: "zero terms owned by structure", termCount: "0", invalidPriority: "true", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "0", enabled: "true"},
		{name: "too many terms owned by structure", termCount: "3", invalidPriority: "true", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "1", enabled: "true"},
		{name: "malformed term count", termCount: "unknown", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "1", enabled: "true"},
		{name: "malformed value count", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "unknown", enabled: "true"},
		{name: "negative value count", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "-1", enabled: "true"},
		{name: "value count exceeds terms", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "2", enabled: "true"},
		{name: "disabled", termCount: "1", invalidPriority: "false", invalidOperators: "0", invalidOccurrence: "0", invalidValues: "1", enabled: "false"},
	}
	item := NewNewRelicConditionInvalidThresholdValueAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.invalidPriority
			resource.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount] = test.invalidOperators
			resource.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount] = test.invalidOccurrence
			resource.Metadata[model.MetadataNewRelicInvalidThresholdValueCount] = test.invalidValues
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionInvalidGapFillOptionAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name            string
		termCount       string
		invalidPriority string
		option          string
		evaluable       string
		invalid         string
		enabled         string
		wantFinding     bool
	}{
		{name: "missing option", termCount: "1", invalidPriority: "false", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "unknown option normalized away", termCount: "2", invalidPriority: "false", evaluable: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "none", termCount: "1", invalidPriority: "false", option: "NONE", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "last value", termCount: "1", invalidPriority: "false", option: "LAST_VALUE", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "static", termCount: "1", invalidPriority: "false", option: "STATIC", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "raw unknown value rejected", termCount: "1", invalidPriority: "false", option: "PRIVATE_MODE", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "inconsistent valid option and invalid flag", termCount: "1", invalidPriority: "false", option: "NONE", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "inconsistent empty healthy state", termCount: "1", invalidPriority: "false", evaluable: "true", invalid: "false", enabled: "true"},
		{name: "not evaluable", termCount: "1", invalidPriority: "false", evaluable: "false", invalid: "true", enabled: "true"},
		{name: "zero terms owned by structure", termCount: "0", invalidPriority: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "too many terms owned by structure", termCount: "3", invalidPriority: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "invalid priority owns condition", termCount: "1", invalidPriority: "true", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "malformed term count", termCount: "unknown", invalidPriority: "false", evaluable: "true", invalid: "true", enabled: "true"},
		{name: "disabled", termCount: "1", invalidPriority: "false", evaluable: "true", invalid: "true", enabled: "false"},
	}
	item := NewNewRelicConditionInvalidGapFillOptionAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.invalidPriority
			resource.Metadata[model.MetadataNewRelicGapFillOption] = test.option
			resource.Metadata[model.MetadataNewRelicGapFillOptionEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicGapFillOptionInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionInvalidStaticGapFillValueAnalyzerBoundaries(t *testing.T) {
	tests := []struct {
		name            string
		termCount       string
		invalidPriority string
		option          string
		optionEvaluable string
		optionInvalid   string
		valueEvaluable  string
		valueInvalid    string
		enabled         string
		wantFinding     bool
	}{
		{name: "missing static fill value", termCount: "1", invalidPriority: "false", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true", wantFinding: true},
		{name: "invalid static fill value with two terms", termCount: "2", invalidPriority: "false", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true", wantFinding: true},
		{name: "valid static fill value", termCount: "1", invalidPriority: "false", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "false", enabled: "true"},
		{name: "none does not require value", termCount: "1", invalidPriority: "false", option: "NONE", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "false", valueInvalid: "false", enabled: "true"},
		{name: "last value does not require value", termCount: "1", invalidPriority: "false", option: "LAST_VALUE", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "false", valueInvalid: "false", enabled: "true"},
		{name: "invalid option owned by M109", termCount: "1", invalidPriority: "false", optionEvaluable: "true", optionInvalid: "true", valueEvaluable: "false", valueInvalid: "false", enabled: "true"},
		{name: "option unevaluable", termCount: "1", invalidPriority: "false", option: "STATIC", optionEvaluable: "false", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true"},
		{name: "value unevaluable", termCount: "1", invalidPriority: "false", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "false", valueInvalid: "true", enabled: "true"},
		{name: "inconsistent non-static value state", termCount: "1", invalidPriority: "false", option: "NONE", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true"},
		{name: "zero terms owned by structure", termCount: "0", invalidPriority: "true", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true"},
		{name: "too many terms owned by structure", termCount: "3", invalidPriority: "true", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true"},
		{name: "invalid priority owns condition", termCount: "1", invalidPriority: "true", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true"},
		{name: "malformed term count", termCount: "unknown", invalidPriority: "false", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "true"},
		{name: "disabled", termCount: "1", invalidPriority: "false", option: "STATIC", optionEvaluable: "true", optionInvalid: "false", valueEvaluable: "true", valueInvalid: "true", enabled: "false"},
	}
	item := NewNewRelicConditionInvalidStaticGapFillValueAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] = test.invalidPriority
			resource.Metadata[model.MetadataNewRelicGapFillOption] = test.option
			resource.Metadata[model.MetadataNewRelicGapFillOptionEvaluable] = test.optionEvaluable
			resource.Metadata[model.MetadataNewRelicGapFillOptionInvalid] = test.optionInvalid
			resource.Metadata[model.MetadataNewRelicStaticGapFillValueEvaluable] = test.valueEvaluable
			resource.Metadata[model.MetadataNewRelicStaticGapFillValueInvalid] = test.valueInvalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := item.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicConditionPerTargetIncidentFanoutAnalyzerGates(t *testing.T) {
	tests := []struct {
		name           string
		preference     string
		policyDeclared string
		termCount      string
		enabled        string
		wantFinding    bool
	}{
		{name: "per target", preference: "PER_CONDITION_AND_TARGET", policyDeclared: "true", termCount: "1", enabled: "true", wantFinding: true},
		{name: "normalized lowercase", preference: "per_condition_and_target", policyDeclared: "true", termCount: "1", enabled: "true", wantFinding: true},
		{name: "per condition", preference: "PER_CONDITION", policyDeclared: "true", termCount: "1", enabled: "true"},
		{name: "per policy", preference: "PER_POLICY", policyDeclared: "true", termCount: "1", enabled: "true"},
		{name: "policy unavailable", preference: "PER_CONDITION_AND_TARGET", policyDeclared: "false", termCount: "1", enabled: "true"},
		{name: "no threshold", preference: "PER_CONDITION_AND_TARGET", policyDeclared: "true", termCount: "0", enabled: "true"},
		{name: "malformed threshold", preference: "PER_CONDITION_AND_TARGET", policyDeclared: "true", termCount: "unknown", enabled: "true"},
		{name: "disabled", preference: "PER_CONDITION_AND_TARGET", policyDeclared: "true", termCount: "1", enabled: "false"},
	}
	analyzer := NewNewRelicConditionPerTargetIncidentFanoutAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicIncidentPreference] = test.preference
			resource.Metadata[model.MetadataNewRelicPolicyDeclared] = test.policyDeclared
			resource.Metadata[model.MetadataNewRelicTermCount] = test.termCount
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionAtLeastOnceAnalyzerGates(t *testing.T) {
	tests := []struct {
		name             string
		criticalCount    string
		atLeastOnceCount string
		enabled          string
		wantFinding      bool
	}{
		{name: "one critical at least once", criticalCount: "1", atLeastOnceCount: "1", enabled: "true", wantFinding: true},
		{name: "critical all", criticalCount: "1", atLeastOnceCount: "0", enabled: "true"},
		{name: "warning only at least once", criticalCount: "0", atLeastOnceCount: "0", enabled: "true"},
		{name: "unknown occurrence", criticalCount: "1", atLeastOnceCount: "0", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", atLeastOnceCount: "1", enabled: "true"},
		{name: "malformed occurrence count", criticalCount: "1", atLeastOnceCount: "unknown", enabled: "true"},
		{name: "inconsistent count", criticalCount: "1", atLeastOnceCount: "2", enabled: "true"},
		{name: "disabled", criticalCount: "1", atLeastOnceCount: "1", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionAtLeastOnceAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicCriticalAtLeastOnceTermCount] = test.atLeastOnceCount
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionInvalidLossOfSignalDurationAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount string
		evaluable     string
		configured    string
		invalid       string
		enabled       string
		wantFinding   bool
	}{
		{name: "invalid configured duration", criticalCount: "1", evaluable: "true", configured: "true", invalid: "true", enabled: "true", wantFinding: true},
		{name: "minimum boundary", criticalCount: "1", evaluable: "true", configured: "true", invalid: "false", enabled: "true"},
		{name: "zero owned by missing rule", criticalCount: "1", evaluable: "true", configured: "false", invalid: "false", enabled: "true"},
		{name: "open disabled", criticalCount: "1", evaluable: "true", configured: "false", invalid: "true", enabled: "true"},
		{name: "warning only", criticalCount: "0", evaluable: "true", configured: "true", invalid: "true", enabled: "true"},
		{name: "not evaluable", criticalCount: "1", evaluable: "false", configured: "true", invalid: "true", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", evaluable: "true", configured: "true", invalid: "true", enabled: "true"},
		{name: "disabled", criticalCount: "1", evaluable: "true", configured: "true", invalid: "true", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionInvalidLossOfSignalDurationAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = test.configured
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionShortLossOfSignalDurationAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount string
		evaluable     string
		configured    string
		invalid       string
		short         string
		enabled       string
		wantFinding   bool
	}{
		{name: "valid short duration", criticalCount: "1", evaluable: "true", configured: "true", invalid: "false", short: "true", enabled: "true", wantFinding: true},
		{name: "recommended boundary", criticalCount: "1", evaluable: "true", configured: "true", invalid: "false", short: "false", enabled: "true"},
		{name: "invalid owned by boundary rule", criticalCount: "1", evaluable: "true", configured: "true", invalid: "true", short: "false", enabled: "true"},
		{name: "inconsistent invalid and short", criticalCount: "1", evaluable: "true", configured: "true", invalid: "true", short: "true", enabled: "true"},
		{name: "open disabled", criticalCount: "1", evaluable: "true", configured: "false", invalid: "false", short: "true", enabled: "true"},
		{name: "warning only", criticalCount: "0", evaluable: "true", configured: "true", invalid: "false", short: "true", enabled: "true"},
		{name: "not evaluable", criticalCount: "1", evaluable: "false", configured: "true", invalid: "false", short: "true", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", evaluable: "true", configured: "true", invalid: "false", short: "true", enabled: "true"},
		{name: "disabled", criticalCount: "1", evaluable: "true", configured: "true", invalid: "false", short: "true", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionShortLossOfSignalDurationAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = test.configured
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] = test.invalid
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationShort] = test.short
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionEvaluationDelayAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount string
		declared      string
		delay         string
		invalid       string
		enabled       string
		wantFinding   bool
	}{
		{name: "valid enabled delay", criticalCount: "1", declared: "true", delay: "900", invalid: "false", enabled: "true", wantFinding: true},
		{name: "minimum enabled delay", criticalCount: "1", declared: "true", delay: "1", invalid: "false", enabled: "true", wantFinding: true},
		{name: "maximum enabled delay", criticalCount: "1", declared: "true", delay: "7200", invalid: "false", enabled: "true", wantFinding: true},
		{name: "absent", criticalCount: "1", declared: "false", delay: "0", invalid: "false", enabled: "true"},
		{name: "disabled zero", criticalCount: "1", declared: "true", delay: "0", invalid: "false", enabled: "true"},
		{name: "invalid negative", criticalCount: "1", declared: "true", delay: "-1", invalid: "true", enabled: "true"},
		{name: "invalid above maximum", criticalCount: "1", declared: "true", delay: "7201", invalid: "true", enabled: "true"},
		{name: "inconsistent invalid flag", criticalCount: "1", declared: "true", delay: "900", invalid: "true", enabled: "true"},
		{name: "warning only", criticalCount: "0", declared: "true", delay: "900", invalid: "false", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", declared: "true", delay: "900", invalid: "false", enabled: "true"},
		{name: "malformed delay", criticalCount: "1", declared: "true", delay: "unknown", invalid: "false", enabled: "true"},
		{name: "disabled condition", criticalCount: "1", declared: "true", delay: "900", invalid: "false", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionEvaluationDelayAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicEvaluationDelayDeclared] = test.declared
			resource.Metadata[model.MetadataNewRelicEvaluationDelaySeconds] = test.delay
			resource.Metadata[model.MetadataNewRelicEvaluationDelayInvalid] = test.invalid
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionLastValueGapFillingAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount string
		fillOption    string
		enabled       string
		wantFinding   bool
	}{
		{name: "last value", criticalCount: "1", fillOption: "LAST_VALUE", enabled: "true", wantFinding: true},
		{name: "normalized defensively", criticalCount: "1", fillOption: " last_value ", enabled: "true", wantFinding: true},
		{name: "none", criticalCount: "1", fillOption: "NONE", enabled: "true"},
		{name: "static", criticalCount: "1", fillOption: "STATIC", enabled: "true"},
		{name: "absent", criticalCount: "1", enabled: "true"},
		{name: "unknown", criticalCount: "1", fillOption: "FUTURE_MODE", enabled: "true"},
		{name: "warning only", criticalCount: "0", fillOption: "LAST_VALUE", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", fillOption: "LAST_VALUE", enabled: "true"},
		{name: "disabled condition", criticalCount: "1", fillOption: "LAST_VALUE", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionLastValueGapFillingAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicGapFillOption] = test.fillOption
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionStaticGapFillBreachesThresholdAnalyzerGates(t *testing.T) {
	tests := []struct {
		name          string
		criticalCount string
		fillOption    string
		evaluable     string
		breachCount   string
		enabled       string
		wantFinding   bool
	}{
		{name: "one breach", criticalCount: "1", fillOption: "STATIC", evaluable: "true", breachCount: "1", enabled: "true", wantFinding: true},
		{name: "two breaches", criticalCount: "2", fillOption: "STATIC", evaluable: "true", breachCount: "2", enabled: "true", wantFinding: true},
		{name: "safe static value", criticalCount: "1", fillOption: "STATIC", evaluable: "true", breachCount: "0", enabled: "true"},
		{name: "not evaluable", criticalCount: "1", fillOption: "STATIC", evaluable: "false", breachCount: "1", enabled: "true"},
		{name: "inconsistent over count", criticalCount: "1", fillOption: "STATIC", evaluable: "true", breachCount: "2", enabled: "true"},
		{name: "last value owned by M99", criticalCount: "1", fillOption: "LAST_VALUE", evaluable: "true", breachCount: "1", enabled: "true"},
		{name: "none", criticalCount: "1", fillOption: "NONE", evaluable: "true", breachCount: "1", enabled: "true"},
		{name: "warning only", criticalCount: "0", fillOption: "STATIC", evaluable: "true", breachCount: "1", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", fillOption: "STATIC", evaluable: "true", breachCount: "1", enabled: "true"},
		{name: "malformed breach count", criticalCount: "1", fillOption: "STATIC", evaluable: "true", breachCount: "unknown", enabled: "true"},
		{name: "disabled condition", criticalCount: "1", fillOption: "STATIC", evaluable: "true", breachCount: "1", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionStaticGapFillBreachesThresholdAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicGapFillOption] = test.fillOption
			resource.Metadata[model.MetadataNewRelicStaticGapFillEvaluable] = test.evaluable
			resource.Metadata[model.MetadataNewRelicStaticGapFillCriticalBreachCount] = test.breachCount
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func TestNewRelicCriticalConditionWithoutCloseOnSignalLossAnalyzerGates(t *testing.T) {
	tests := []struct {
		name            string
		criticalCount   string
		lossEvaluable   string
		lossConfigured  string
		durationInvalid string
		closeEvaluable  string
		closeConfigured string
		enabled         string
		wantFinding     bool
	}{
		{name: "explicitly leaves existing events open", criticalCount: "1", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "false", enabled: "true", wantFinding: true},
		{name: "close action enabled", criticalCount: "1", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "true", enabled: "true"},
		{name: "close action unknown", criticalCount: "1", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "false", closeConfigured: "false", enabled: "true"},
		{name: "missing Loss of Signal owned by existing rule", criticalCount: "1", lossEvaluable: "true", lossConfigured: "false", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "false", enabled: "true"},
		{name: "invalid duration owned by M96", criticalCount: "1", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "true", closeEvaluable: "true", closeConfigured: "false", enabled: "true"},
		{name: "Loss of Signal not evaluable", criticalCount: "1", lossEvaluable: "false", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "false", enabled: "true"},
		{name: "warning only", criticalCount: "0", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "false", enabled: "true"},
		{name: "malformed critical count", criticalCount: "unknown", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "false", enabled: "true"},
		{name: "disabled condition", criticalCount: "1", lossEvaluable: "true", lossConfigured: "true", durationInvalid: "false", closeEvaluable: "true", closeConfigured: "false", enabled: "false"},
	}
	analyzer := NewNewRelicCriticalConditionWithoutCloseOnSignalLossAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := newRelicConditionTestResource(test.name)
			resource.Metadata[model.MetadataNewRelicCriticalTermCount] = test.criticalCount
			resource.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] = test.lossEvaluable
			resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] = test.lossConfigured
			resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] = test.durationInvalid
			resource.Metadata[model.MetadataNewRelicLossOfSignalCloseEvaluable] = test.closeEvaluable
			resource.Metadata[model.MetadataNewRelicLossOfSignalCloseConfigured] = test.closeConfigured
			resource.Metadata[model.MetadataEnabled] = test.enabled
			if test.enabled == "false" {
				resource.Status = model.ResourceStatusDeprecated
			}
			finding, ok := analyzer.finding(resource, time.Now().UTC())
			if ok != test.wantFinding {
				t.Fatalf("finding=%t want=%t: %#v", ok, test.wantFinding, finding)
			}
		})
	}
}

func newRelicEntityTestResource(id string) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeService, Name: id,
		Source: model.SourceInfo{System: "newrelic"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataNewRelicEntity:                "true",
			model.MetadataNewRelicReportingDeclared:     "true",
			model.MetadataNewRelicReporting:             "true",
			model.MetadataNewRelicAlertSeverityDeclared: "true",
			model.MetadataNewRelicAlertSeverity:         "NOT_ALERTING",
			model.MetadataNewRelicOwnershipDeclared:     "true",
		},
	}
}

func newRelicConditionTestResource(id string) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeAlertRule, Name: id,
		Source: model.SourceInfo{System: "newrelic"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataNewRelicNRQLCondition:                         "true",
			model.MetadataNewRelicConditionType:                         "STATIC",
			model.MetadataEnabled:                                       "true",
			model.MetadataDisabled:                                      "false",
			model.MetadataNewRelicTermCount:                             "1",
			model.MetadataNewRelicCriticalTermCount:                     "0",
			model.MetadataNewRelicWarningTermCount:                      "1",
			model.MetadataNewRelicCriticalAtLeastOnceTermCount:          "0",
			model.MetadataNewRelicThresholdPriorityCountInvalid:         "false",
			model.MetadataNewRelicInvalidThresholdOperatorCount:         "0",
			model.MetadataNewRelicInvalidThresholdOccurrenceCount:       "0",
			model.MetadataNewRelicInvalidThresholdValueCount:            "0",
			model.MetadataNewRelicCriticalThresholdDurationMin:          "0",
			model.MetadataNewRelicCriticalThresholdDurationMax:          "0",
			model.MetadataNewRelicInvalidCriticalThresholdDurationCount: "0",
			model.MetadataNewRelicInvalidBaselineThresholdDurationCount: "0",
			model.MetadataNewRelicBaselineDirectionEvaluable:            "false",
			model.MetadataNewRelicBaselineDirectionInvalid:              "false",
			model.MetadataNewRelicStaticValueFunctionEvaluable:          "true",
			model.MetadataNewRelicStaticValueFunctionInvalid:            "false",
			model.MetadataNewRelicDescriptionConfigured:                 "true",
			model.MetadataNewRelicTitleTemplateConfigured:               "true",
			model.MetadataNewRelicRunbookConfigured:                     "true",
			model.MetadataNewRelicAggregationMethod:                     "EVENT_FLOW",
			model.MetadataNewRelicAggregationWindow:                     "60",
			model.MetadataNewRelicAggregationTimer:                      "0",
			model.MetadataNewRelicSlideByDeclared:                       "false",
			model.MetadataNewRelicSlideBySeconds:                        "0",
			model.MetadataNewRelicSlidingWindowEvaluable:                "false",
			model.MetadataNewRelicSlidingWindowInvalid:                  "false",
			model.MetadataNewRelicSlidingWindowOverlapFactor:            "0",
			model.MetadataNewRelicEventTimerWindowEvaluable:             "false",
			model.MetadataNewRelicEventTimerShorterThanWindow:           "false",
			model.MetadataNewRelicLossOfSignalEvaluable:                 "true",
			model.MetadataNewRelicLossOfSignalConfigured:                "true",
			model.MetadataNewRelicLossOfSignalDurationInvalid:           "false",
			model.MetadataNewRelicLossOfSignalDurationShort:             "false",
			model.MetadataNewRelicLossOfSignalCloseEvaluable:            "false",
			model.MetadataNewRelicLossOfSignalCloseConfigured:           "false",
			model.MetadataNewRelicEvaluationDelayDeclared:               "false",
			model.MetadataNewRelicEvaluationDelaySeconds:                "0",
			model.MetadataNewRelicEvaluationDelayInvalid:                "false",
			model.MetadataNewRelicGapFillOption:                         "NONE",
			model.MetadataNewRelicGapFillOptionEvaluable:                "true",
			model.MetadataNewRelicGapFillOptionInvalid:                  "false",
			model.MetadataNewRelicStaticGapFillValueEvaluable:           "false",
			model.MetadataNewRelicStaticGapFillValueInvalid:             "false",
			model.MetadataNewRelicStaticGapFillEvaluable:                "false",
			model.MetadataNewRelicStaticGapFillCriticalBreachCount:      "0",
			model.MetadataNewRelicViolationTimeLimitSeconds:             "259200",
			model.MetadataNewRelicPolicyDeclared:                        "false",
		},
	}
}
