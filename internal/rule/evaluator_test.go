package rule

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestEvaluateRuleExpression(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	metric := model.Resource{
		ID:     "metric-1",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"team": "platform"},
		Metadata: map[string]string{
			model.MetadataSeriesCount: "1500",
		},
	}
	panel := model.Resource{ID: "panel-1", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive}
	if err := store.Resources.Upsert(ctx, metric); err != nil {
		t.Fatalf("upsert metric: %v", err)
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert panel: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "rel-1",
		FromID: panel.ID,
		ToID:   metric.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	rule := Rule{
		ID:        "high-cardinality-platform-metric",
		Scope:     []model.ResourceType{model.ResourceTypeMetric},
		Condition: Condition{Expression: `type == "Metric" AND labels["team"] == "platform" AND used_by > 0 AND cardinality >= 1000`},
	}

	evaluation, err := Evaluate(rule, metric, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected rule to match")
	}

	rule.Condition.Expression = `name =~ "^node_.*" OR NOT status == "ACTIVE"`
	evaluation, err = Evaluate(rule, metric, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate regex expression: %v", err)
	}
	if evaluation.Matched {
		t.Fatalf("expected regex expression not to match")
	}
}

func TestEvaluateRecordingRuleOutputUsedByExpression(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	recordingRule := model.Resource{
		ID:     "recording-1",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
	}
	outputMetric := model.Resource{
		ID:     "metric-recorded",
		Type:   model.ResourceTypeMetric,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
	}
	panel := model.Resource{
		ID:     "panel-1",
		Type:   model.ResourceTypePanel,
		Name:   "Request Rate",
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{recordingRule, outputMetric, panel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "recording-produces-output", FromID: recordingRule.ID, ToID: outputMetric.ID, Type: model.RelationshipProduces},
		{ID: "panel-uses-output", FromID: panel.ID, ToID: outputMetric.ID, Type: model.RelationshipUses},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	usedRule := Rule{
		ID:        "recording-output-used",
		Scope:     []model.ResourceType{model.ResourceTypeRecordingRule},
		Condition: Condition{Expression: `status == "ACTIVE" AND output_used_by > 0`},
	}
	evaluation, err := Evaluate(usedRule, recordingRule, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate output_used_by rule: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected output_used_by rule to match")
	}

	unusedRule := Rule{
		ID:        "recording-unused",
		Scope:     []model.ResourceType{model.ResourceTypeRecordingRule},
		Condition: Condition{Expression: `status == "ACTIVE" AND used_by == 0 AND output_used_by == 0`},
	}
	evaluation, err = Evaluate(unusedRule, recordingRule, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate unused recording rule: %v", err)
	}
	if evaluation.Matched {
		t.Fatalf("expected recording rule with consumed output metric not to match unused policy")
	}
}

func TestEvaluateDatasourceUsedByExpression(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-1",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
	}
	recordingRule := model.Resource{
		ID:     "recording-1",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
	}
	deprecatedPanel := model.Resource{
		ID:     "panel-old",
		Type:   model.ResourceTypePanel,
		Name:   "Old Panel",
		Status: model.ResourceStatusDeprecated,
	}
	metric := model.Resource{
		ID:     "metric-1",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{datasource, recordingRule, deprecatedPanel, metric} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "recording-uses-datasource", FromID: recordingRule.ID, ToID: datasource.ID, Type: model.RelationshipUses},
		{ID: "deprecated-panel-uses-datasource", FromID: deprecatedPanel.ID, ToID: datasource.ID, Type: model.RelationshipUses},
		{ID: "metric-uses-datasource", FromID: metric.ID, ToID: datasource.ID, Type: model.RelationshipUses},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	rule := Rule{
		ID:        "datasource-used-by-recording",
		Scope:     []model.ResourceType{model.ResourceTypeDatasource},
		Condition: Condition{Expression: `status == "ACTIVE" AND datasource_used_by == 1`},
	}
	evaluation, err := Evaluate(rule, datasource, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate datasource_used_by rule: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected datasource_used_by to count only active datasource consumers")
	}
}

func TestEvaluateServiceImpactResourcesExpression(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := model.Resource{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive}
	rawMetric := model.Resource{ID: "metric-raw", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	derivedMetric := model.Resource{ID: "metric-derived", Type: model.ResourceTypeMetric, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	recordingRule := model.Resource{ID: "record-api", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	panel := model.Resource{ID: "panel-api", Type: model.ResourceTypePanel, Name: "API throughput", Status: model.ResourceStatusActive}
	deprecatedPanel := model.Resource{ID: "panel-old", Type: model.ResourceTypePanel, Name: "Old throughput", Status: model.ResourceStatusDeprecated}
	for _, resource := range []model.Resource{service, rawMetric, derivedMetric, recordingRule, panel, deprecatedPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "metric-belongs-service", FromID: rawMetric.ID, ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "record-uses-raw", FromID: recordingRule.ID, ToID: rawMetric.ID, Type: model.RelationshipUses},
		{ID: "record-produces-derived", FromID: recordingRule.ID, ToID: derivedMetric.ID, Type: model.RelationshipProduces},
		{ID: "raw-produces-derived", FromID: rawMetric.ID, ToID: derivedMetric.ID, Type: model.RelationshipProduces},
		{ID: "panel-uses-derived", FromID: panel.ID, ToID: derivedMetric.ID, Type: model.RelationshipUses},
		{ID: "deprecated-panel-uses-derived", FromID: deprecatedPanel.ID, ToID: derivedMetric.ID, Type: model.RelationshipUses},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	rule := Rule{
		ID:        "service-impact-derived",
		Scope:     []model.ResourceType{model.ResourceTypeService},
		Condition: Condition{Expression: `status == "ACTIVE" AND service_impact_resources == 4`},
	}
	evaluation, err := Evaluate(rule, service, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate service_impact_resources rule: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected service_impact_resources to count active direct and derived-impact resources")
	}

	if err := ValidateExpression(`service_impact_resources > "10"`); err != nil {
		t.Fatalf("validate service_impact_resources expression: %v", err)
	}
}

func TestEvaluateServiceObservabilitySignalsExpression(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := model.Resource{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive}
	resources := []model.Resource{
		service,
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
		{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Name: "API overview", Status: model.ResourceStatusActive},
		{ID: "alert-api", Type: model.ResourceTypeAlertRule, Name: "APIErrorRate", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataDisabled: "true"}},
		{ID: "trace-global", Type: model.ResourceTypeTraceOperation, Name: "worker GET", Status: model.ResourceStatusActive},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "metric-belongs-service", FromID: "metric-api", ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "dashboard-belongs-service", FromID: "dashboard-api", ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "alert-belongs-service", FromID: "alert-api", ToID: service.ID, Type: model.RelationshipBelongsTo},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	policyRule := Rule{
		ID:        "service-observability-gap",
		Scope:     []model.ResourceType{model.ResourceTypeService},
		Condition: Condition{Expression: `status == "ACTIVE" AND available_observability_signals == 3 AND service_observability_signals == 2`},
	}
	evaluation, err := Evaluate(policyRule, service, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate service observability rule: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected global metric/dashboard/trace availability and two service signals")
	}
	if err := ValidateExpression(`available_observability_signals > "1" AND service_observability_signals < "2"`); err != nil {
		t.Fatalf("validate service observability expression: %v", err)
	}
}

func TestEvaluateServiceSLOCoverageExpression(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := model.Resource{ID: "service-worker", Type: model.ResourceTypeService, Name: "worker", Status: model.ResourceStatusActive}
	resources := []model.Resource{
		service,
		{ID: "metric-worker", Type: model.ResourceTypeMetric, Name: "worker_jobs_total", Status: model.ResourceStatusActive},
		{ID: "slo-global", Type: model.ResourceTypeRecordingRule, Name: "slo:sli_error:ratio_rate5m", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSLORule: "true"}},
		{ID: "slo-disabled", Type: model.ResourceTypeAlertRule, Name: "DisabledBurnRate", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSLORule: "true", model.MetadataDisabled: "true"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{ID: "metric-worker-service", FromID: "metric-worker", ToID: service.ID, Type: model.RelationshipBelongsTo}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	policyRule := Rule{
		ID:        "service-without-slo",
		Scope:     []model.ResourceType{model.ResourceTypeService},
		Condition: Condition{Expression: `status == "ACTIVE" AND available_slo_rules > "0" AND service_metric_resources > "0" AND service_slo_rules == "0"`},
	}
	evaluation, err := Evaluate(policyRule, service, resourceGraph)
	if err != nil || !evaluation.Matched {
		t.Fatalf("expected metric-backed service without SLO to match, evaluation=%#v err=%v", evaluation, err)
	}
	if err := ValidateExpression(policyRule.Condition.Expression); err != nil {
		t.Fatalf("validate service SLO expression: %v", err)
	}
}

func TestEvaluateSLOGroupExpressions(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	first := model.Resource{ID: "recording-a", Type: model.ResourceTypeRecordingRule, Name: "slo:api:rate5m", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus", Instance: "prod"}, Metadata: map[string]string{model.MetadataSLORule: "true", model.MetadataSLOName: "api-availability", model.MetadataSLOObjective: "99.9", model.MetadataSLOWindow: "5m"}}
	second := model.Resource{ID: "recording-b", Type: model.ResourceTypeRecordingRule, Name: "slo:api:rate30m", Status: model.ResourceStatusActive, Source: first.Source, Metadata: map[string]string{model.MetadataSLORule: "true", model.MetadataSLOName: "api-availability", model.MetadataSLOObjective: "0.999", model.MetadataSLOWindow: "6h"}}
	disabledAlert := model.Resource{ID: "alert-disabled", Type: model.ResourceTypeAlertRule, Name: "APIBurnRate", Status: model.ResourceStatusActive, Source: first.Source, Metadata: map[string]string{model.MetadataSLORule: "true", model.MetadataSLOName: "api-availability", model.MetadataDisabled: "true"}}
	for _, resource := range []model.Resource{second, disabledAlert, first} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	policyRule := Rule{
		ID:        "slo-without-alert",
		Scope:     []model.ResourceType{model.ResourceTypeRecordingRule},
		Condition: Condition{Expression: `metadata["slo_rule"] == "true" AND metadata["slo_name"] != "" AND slo_group_recording_rules == "2" AND slo_group_alert_rules == "0" AND slo_group_primary_recording == "true"`},
	}
	evaluation, err := Evaluate(policyRule, first, resourceGraph)
	if err != nil || !evaluation.Matched {
		t.Fatalf("expected primary recording rule to represent missing-alert group, evaluation=%#v err=%v", evaluation, err)
	}
	evaluation, err = Evaluate(policyRule, second, resourceGraph)
	if err != nil || evaluation.Matched {
		t.Fatalf("expected secondary recording rule not to duplicate group match, evaluation=%#v err=%v", evaluation, err)
	}
	if err := ValidateExpression(policyRule.Condition.Expression); err != nil {
		t.Fatalf("validate SLO group expression: %v", err)
	}
	objectiveRule := Rule{
		ID:        "slo-objective-equivalent",
		Scope:     []model.ResourceType{model.ResourceTypeRecordingRule},
		Condition: Condition{Expression: `slo_group_primary_rule == "true" AND slo_group_objective_values == "2" AND slo_group_invalid_objectives == "0" AND slo_group_objective_variants == "1"`},
	}
	evaluation, err = Evaluate(objectiveRule, first, resourceGraph)
	if err != nil || !evaluation.Matched {
		t.Fatalf("expected equivalent percent and ratio objectives to form one variant, evaluation=%#v err=%v", evaluation, err)
	}
	if err := ValidateExpression(objectiveRule.Condition.Expression); err != nil {
		t.Fatalf("validate SLO objective group expression: %v", err)
	}
	windowRule := Rule{
		ID:        "slo-window-coverage",
		Scope:     []model.ResourceType{model.ResourceTypeRecordingRule},
		Condition: Condition{Expression: `slo_group_primary_rule == "true" AND slo_group_window_values == "2" AND slo_group_invalid_windows == "0" AND slo_group_window_variants == "2" AND slo_group_short_windows == "1" AND slo_group_long_windows == "1"`},
	}
	evaluation, err = Evaluate(windowRule, first, resourceGraph)
	if err != nil || !evaluation.Matched {
		t.Fatalf("expected short and long SLO window coverage, evaluation=%#v err=%v", evaluation, err)
	}
	if err := ValidateExpression(windowRule.Condition.Expression); err != nil {
		t.Fatalf("validate SLO window group expression: %v", err)
	}
}

func TestEvaluateLogLabelPolicyExpressions(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	label := model.Resource{
		ID:     "log-label-user-id",
		Type:   model.ResourceTypeLogLabel,
		Name:   "user_id",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLogLabel:           "user_id",
			model.MetadataLogLabelValueCount: "250",
		},
	}

	riskyRule := Rule{
		ID:        "policy.log.risky_label",
		Scope:     []model.ResourceType{model.ResourceTypeLogLabel},
		Condition: Condition{Expression: `name =~ "(?i).*(user[_-]?id|request[_-]?id|trace[_-]?id|span[_-]?id|session[_-]?id|pod[_-]?uid|container[_-]?id|client[_-]?ip|path|url).*" OR metadata["label"] =~ "(?i).*(user[_-]?id|request[_-]?id|trace[_-]?id|span[_-]?id|session[_-]?id|pod[_-]?uid|container[_-]?id|client[_-]?ip|path|url).*"`},
	}
	evaluation, err := Evaluate(riskyRule, label, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate risky label rule: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected risky log label rule to match")
	}

	cardinalityRule := Rule{
		ID:        "policy.log.high_value_count",
		Scope:     []model.ResourceType{model.ResourceTypeLogLabel},
		Condition: Condition{Expression: `metadata["value_count"] > "100"`},
	}
	evaluation, err = Evaluate(cardinalityRule, label, resourceGraph)
	if err != nil {
		t.Fatalf("evaluate high value count rule: %v", err)
	}
	if !evaluation.Matched {
		t.Fatalf("expected high value count rule to match")
	}
}
