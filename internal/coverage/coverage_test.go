package coverage

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAssessDistinguishesObservedMissingUnknownAndExempt(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
		{ID: "dashboard-other", Type: model.ResourceTypeDashboard, Name: "Other", Status: model.ResourceStatusActive},
		{ID: "alert-other", Type: model.ResourceTypeAlertRule, Name: "OtherDown", Status: model.ResourceStatusActive},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID: "metric-api-service", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo,
	}); err != nil {
		t.Fatal(err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatal(err)
	}
	expectation := model.CoverageExpectation{
		ID: "baseline", Name: "Baseline", Scope: model.CoverageScopeAllServices,
		RequiredSignals: []model.CoverageSignal{
			model.CoverageSignalMetrics,
			model.CoverageSignalDashboards,
			model.CoverageSignalAlerts,
			model.CoverageSignalTraces,
		},
		Owner: "platform", Rationale: "test", Enabled: true,
	}
	exception := model.CoverageException{
		ID: "exception-alerts", ExpectationID: expectation.ID, ServiceID: "service-api",
		Signal: model.CoverageSignalAlerts, Owner: "platform", Reason: "migration", CreatedBy: "alice",
		ExpiresAt: now.Add(time.Hour),
	}

	summary := Assess(resources, resourceGraph, []model.CoverageExpectation{expectation}, []model.CoverageException{exception}, now)
	if len(summary.Assessments) != 1 {
		t.Fatalf("expected one assessment, got %#v", summary.Assessments)
	}
	assessment := summary.Assessments[0]
	states := map[model.CoverageSignal]SignalState{}
	for _, item := range assessment.Signals {
		states[item.Signal] = item.State
	}
	if states[model.CoverageSignalMetrics] != SignalObserved ||
		states[model.CoverageSignalDashboards] != SignalMissing ||
		states[model.CoverageSignalAlerts] != SignalExempt ||
		states[model.CoverageSignalTraces] != SignalUnknown {
		t.Fatalf("unexpected signal states %#v", states)
	}
	if assessment.CoveragePercent == nil || *assessment.CoveragePercent != 50 {
		t.Fatalf("expected 50%% evaluable coverage, got %#v", assessment.CoveragePercent)
	}
	if assessment.EvidenceState != EvidencePartial || assessment.EvidenceCompleteness == nil || *assessment.EvidenceCompleteness < 66 || *assessment.EvidenceCompleteness > 67 {
		t.Fatalf("expected partial evidence around 66.7%%, got %#v", assessment)
	}
	if summary.EvidenceState != EvidencePartial || summary.EvidenceCompleteness == nil || *summary.EvidenceCompleteness < 66 || *summary.EvidenceCompleteness > 67 {
		t.Fatalf("expected partial summary evidence around 66.7%%, got %#v", summary)
	}
	if assessment.State != AssessmentMissing {
		t.Fatalf("expected missing assessment, got %s", assessment.State)
	}
}

func TestAssessExpiredExceptionRevertsToMissing(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	service := model.Resource{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive}
	dashboard := model.Resource{ID: "dashboard-other", Type: model.ResourceTypeDashboard, Name: "Other", Status: model.ResourceStatusActive}
	for _, resource := range []model.Resource{service, dashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatal(err)
	}
	expectation := model.CoverageExpectation{
		ID: "dashboard", Name: "Dashboard", Scope: model.CoverageScopeAllServices,
		RequiredSignals: []model.CoverageSignal{model.CoverageSignalDashboards},
		Owner:           "platform", Rationale: "test", Enabled: true,
	}
	exception := model.CoverageException{
		ID: "expired", ExpectationID: expectation.ID, ServiceID: service.ID,
		Signal: model.CoverageSignalDashboards, Owner: "platform", Reason: "ended", CreatedBy: "alice",
		ExpiresAt: now.Add(-time.Minute),
	}
	summary := Assess([]model.Resource{service, dashboard}, resourceGraph, []model.CoverageExpectation{expectation}, []model.CoverageException{exception}, now)
	if got := summary.Assessments[0].Signals[0].State; got != SignalMissing {
		t.Fatalf("expected expired exception to revert to missing, got %s", got)
	}
}

func TestAssessUnknownSignalsDoNotProduceCoveragePercentage(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	service := model.Resource{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive}
	expectation := model.CoverageExpectation{
		ID: "traces", Name: "Traces", Scope: model.CoverageScopeAllServices,
		RequiredSignals: []model.CoverageSignal{model.CoverageSignalTraces},
		Owner:           "platform", Rationale: "test", Enabled: true,
	}
	summary := Assess([]model.Resource{service}, nil, []model.CoverageExpectation{expectation}, nil, now)
	if summary.MissingSignals != 0 || summary.UnknownSignals != 1 || summary.CoveragePercent != nil {
		t.Fatalf("unknown inventory must not be reported as missing or scored, got %#v", summary)
	}
	if summary.EvidenceState != EvidenceUnavailable || summary.EvidenceCompleteness == nil || *summary.EvidenceCompleteness != 0 {
		t.Fatalf("unknown-only inventory must disclose unavailable evidence, got %#v", summary)
	}
}

func TestCoverageEvidenceStateHandlesCompleteAndNotApplicableScopes(t *testing.T) {
	state, percent := coverageEvidence(3, 0)
	if state != EvidenceComplete || percent == nil || *percent != 100 {
		t.Fatalf("expected complete evidence, got %s %#v", state, percent)
	}
	state, percent = coverageEvidence(0, 0)
	if state != EvidenceNotApplicable || percent != nil {
		t.Fatalf("expected not-applicable evidence, got %s %#v", state, percent)
	}
}

func TestAssessDisclosesInferredServiceIdentity(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	service := model.Resource{
		ID: "service-payments", Type: model.ResourceTypeService, Name: "payments", Status: model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataServiceIdentitySource: "prometheus.job", model.MetadataServiceIdentityConfidence: "INFERRED"},
	}
	expectation := model.CoverageExpectation{
		ID: "metrics", Name: "Metrics", Scope: model.CoverageScopeAllServices,
		RequiredSignals: []model.CoverageSignal{model.CoverageSignalMetrics}, Owner: "platform", Rationale: "test", Enabled: true,
	}
	summary := Assess([]model.Resource{service}, nil, []model.CoverageExpectation{expectation}, nil, now)
	if summary.InferredServiceCount != 1 || len(summary.Assessments) != 1 || summary.Assessments[0].ServiceIdentitySource != "prometheus.job" || summary.Assessments[0].ServiceIdentityConfidence != "INFERRED" {
		t.Fatalf("inferred identity provenance was not retained: %#v", summary)
	}
}

func TestAssessSupportsNamespaceAndBoundedLabelScopes(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	services := []model.Resource{
		{ID: "checkout", Type: model.ResourceTypeService, Name: "checkout", Status: model.ResourceStatusActive, Labels: map[string]string{"namespace": "payments", "environment": "production"}},
		{ID: "catalog", Type: model.ResourceTypeService, Name: "catalog", Status: model.ResourceStatusActive, Labels: map[string]string{"namespace": "store", "environment": "staging"}},
	}
	expectations := []model.CoverageExpectation{
		{ID: "namespace", Name: "Payments", Scope: model.CoverageScopeNamespace, ScopeValue: "payments", RequiredSignals: []model.CoverageSignal{model.CoverageSignalMetrics}, Owner: "sre", Rationale: "test", Enabled: true},
		{ID: "label", Name: "Production", Scope: model.CoverageScopeLabel, ScopeValue: "environment=production", RequiredSignals: []model.CoverageSignal{model.CoverageSignalAlerts}, Owner: "sre", Rationale: "test", Enabled: true},
	}
	for _, expectation := range expectations {
		if err := ValidateExpectation(expectation); err != nil {
			t.Fatalf("valid scope rejected: %v", err)
		}
	}
	summary := Assess(services, nil, expectations, nil, now)
	if len(summary.Assessments) != 2 || summary.Assessments[0].ServiceID != "checkout" || summary.Assessments[1].ServiceID != "checkout" {
		t.Fatalf("scoped expectations leaked to unrelated services: %#v", summary.Assessments)
	}
	invalid := expectations[1]
	invalid.ScopeValue = "environment in (production)"
	if err := ValidateExpectation(invalid); err == nil {
		t.Fatal("unbounded label selector was accepted")
	}
}

func TestRelatedServiceIDsScopesAResourceToItsCoverageGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Status: model.ResourceStatusActive},
		{ID: "service-worker", Type: model.ResourceTypeService, Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Status: model.ResourceStatusActive},
		{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Status: model.ResourceStatusActive},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "metric-service", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "dashboard-metric", FromID: "dashboard-api", ToID: "metric-api", Type: model.RelationshipUses},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatal(err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatal(err)
	}
	for _, resourceID := range []string{"metric-api", "dashboard-api"} {
		if got := RelatedServiceIDs(resourceID, resourceGraph); len(got) != 1 || got[0] != "service-api" {
			t.Fatalf("unexpected service scope for %s: %#v", resourceID, got)
		}
	}
	if got := RelatedServiceIDs("missing", resourceGraph); len(got) != 0 {
		t.Fatalf("expected no service scope for missing resource, got %#v", got)
	}
}

func TestRelatedResourcesForServiceStopsAtSharedConsumer(t *testing.T) {
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Status: model.ResourceStatusActive},
		{ID: "service-worker", Type: model.ResourceTypeService, Status: model.ResourceStatusActive},
		{ID: "job-api", Type: model.ResourceTypeJob, Status: model.ResourceStatusActive},
		{ID: "target-api", Type: model.ResourceTypeTarget, Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Status: model.ResourceStatusActive},
		{ID: "metric-worker", Type: model.ResourceTypeMetric, Status: model.ResourceStatusActive},
		{ID: "dashboard-shared", Type: model.ResourceTypeDashboard, Status: model.ResourceStatusActive},
	}
	relationships := []model.Relationship{
		{ID: "job-api-service", FromID: "job-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "target-api-job", FromID: "target-api", ToID: "job-api", Type: model.RelationshipBelongsTo},
		{ID: "target-api-metric", FromID: "target-api", ToID: "metric-api", Type: model.RelationshipProduces},
		{ID: "metric-worker-service", FromID: "metric-worker", ToID: "service-worker", Type: model.RelationshipBelongsTo},
		{ID: "dashboard-api", FromID: "dashboard-shared", ToID: "metric-api", Type: model.RelationshipUses},
		{ID: "dashboard-worker", FromID: "dashboard-shared", ToID: "metric-worker", Type: model.RelationshipUses},
	}

	related := RelatedResourcesForService("service-api", graph.NewBounded(resources, relationships))
	ids := map[string]bool{}
	for _, resource := range related {
		ids[resource.ID] = true
	}
	for _, required := range []string{"job-api", "target-api", "metric-api", "dashboard-shared"} {
		if !ids[required] {
			t.Fatalf("service scope missing %s: %#v", required, ids)
		}
	}
	if ids["metric-worker"] || ids["service-worker"] {
		t.Fatalf("shared dashboard fanned into another service: %#v", ids)
	}
}
