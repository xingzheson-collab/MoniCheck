package agentkit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestNeedToKnowQueriesAnswerOneServiceWithoutRawEvidence(t *testing.T) {
	ctx := context.Background()
	path, service, target := seedQueryState(t, ctx)

	result, err := QueryFindings(ctx, path, FindingQueryInput{
		Service: "Redis", Purpose: "Answer the user's question about Redis monitoring health", Limit: 10,
	})
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	if result.ContractVersion != "agent-findings-query.v1" || result.MatchedCount != 1 || len(result.Findings) != 1 {
		t.Fatalf("unexpected finding query: %#v", result)
	}
	if len(result.ActionGroups) != 1 || result.ActionGroups[0].Family != "target-telemetry-loss" || result.ActionGroups[0].ResourceCount != 1 {
		t.Fatalf("scoped action grouping missing: %#v", result.ActionGroups)
	}
	item := result.Findings[0]
	if item.Resource.ID != target.ID || item.Resource.Name != target.Name || item.Type != "BrokenTarget" {
		t.Fatalf("query did not return the scoped target: %#v", item)
	}
	if item.EvidenceCount != 1 || strings.Contains(strings.Join(result.Disclosure.ExcludedFields, " "), "resource names") {
		t.Fatalf("need-to-know disclosure is inconsistent: %#v", result.Disclosure)
	}
	if !strings.Contains(item.Recommendation, "[REDACTED_ENDPOINT]") || strings.Contains(item.Recommendation, "https://") {
		t.Fatalf("recommendation endpoint was not redacted: %q", item.Recommendation)
	}
	if result.Disclosure.Mode != "NEED_TO_KNOW" || result.Disclosure.AuditEventRef == "" {
		t.Fatalf("missing disclosure audit: %#v", result.Disclosure)
	}

	coverageResult, err := CoverageByService(ctx, path, CoverageByServiceInput{
		Service: service.Name, Purpose: "Explain whether Redis has metric, dashboard, and alert coverage",
	})
	if err != nil {
		t.Fatalf("query coverage: %v", err)
	}
	if coverageResult.Service.ID != service.ID || len(coverageResult.Assessments) != 2 {
		t.Fatalf("unexpected service coverage: %#v", coverageResult)
	}
	expectationIDs := map[string]bool{}
	for _, assessment := range coverageResult.Assessments {
		expectationIDs[assessment.ExpectationID] = true
	}
	if !expectationIDs[model.BuiltinServiceCoverageExpectationID] || !expectationIDs["redis-team-baseline"] {
		t.Fatalf("coverage query omitted a custom expectation: %#v", coverageResult.Assessments)
	}
	if coverageResult.Visibility.State != "NOT_PROVEN_COMPLETE" {
		t.Fatalf("service query hid inventory uncertainty: %#v", coverageResult.Visibility)
	}
	states := map[model.CoverageSignal]string{}
	for _, signal := range coverageResult.Assessments[0].Signals {
		states[signal.Signal] = string(signal.State)
	}
	if states[model.CoverageSignalMetrics] != "OBSERVED" || states[model.CoverageSignalDashboards] != "UNKNOWN" || states[model.CoverageSignalAlerts] != "UNKNOWN" {
		t.Fatalf("coverage lost missing/unknown semantics: %#v", states)
	}

	entityResult, err := GetEntity(ctx, path, EntityGetInput{
		ID: target.ID, Purpose: "Inspect the broken Redis target selected from the finding query", Limit: 10,
	})
	if err != nil {
		t.Fatalf("get entity: %v", err)
	}
	if entityResult.Entity.Name != target.Name || entityResult.RelationshipCount != 1 || entityResult.FindingCount != 1 {
		t.Fatalf("unexpected entity drill-down: %#v", entityResult)
	}
	if entityResult.Relationships[0].Entity.ID != service.ID || entityResult.Relationships[0].Type != model.RelationshipBelongsTo {
		t.Fatalf("entity relationship missing: %#v", entityResult.Relationships)
	}

	auditPath := path + ".agent-query-audit.jsonl"
	info, err := os.Stat(auditPath)
	if err != nil {
		t.Fatalf("stat query audit: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("query audit mode = %o, want 600", info.Mode().Perm())
	}
	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read query audit: %v", err)
	}
	text := string(body)
	for _, required := range []string{"agent-query-audit.v1", "monicheck.findings.query", "monicheck.coverage.by_service", "monicheck.entity.get", "Redis"} {
		if !strings.Contains(text, required) {
			t.Fatalf("query audit missing %q: %s", required, text)
		}
	}
	for _, forbidden := range []string{"http://", "https://", "raw evidence should stay local"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("query audit leaked %q: %s", forbidden, text)
		}
	}
}

func TestNeedToKnowQueriesRequirePurposeAndBoundResults(t *testing.T) {
	ctx := context.Background()
	path, service, _ := seedQueryState(t, ctx)
	if _, err := QueryFindings(ctx, path, FindingQueryInput{Service: "Redis"}); err == nil || !strings.Contains(err.Error(), "purpose is required") {
		t.Fatalf("query without purpose was accepted: %v", err)
	}
	if _, err := QueryFindings(ctx, path, FindingQueryInput{Service: "Redis", Purpose: "Investigate Redis", Limit: 51}); err == nil || !strings.Contains(err.Error(), "between 1 and 50") {
		t.Fatalf("unbounded query was accepted: %v", err)
	}
	if _, err := QueryFindings(ctx, path, FindingQueryInput{Purpose: "Dump everything"}); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("unscoped query was accepted: %v", err)
	}
	store, err := storage.NewFileStore(path)
	if err != nil {
		t.Fatalf("open seeded store: %v", err)
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "coverage-test", []model.Finding{{
		ID: "finding-redis-coverage", Type: "MissingMonitoringCoverage", Severity: model.SeverityWarning,
		Category: model.FindingCategoryReliability, Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
		Metadata: map[string]string{"analyzer_id": "coverage-test"}, Status: model.FindingStatusOpen,
	}}); err != nil {
		t.Fatalf("save second action family: %v", err)
	}
	grouped, err := QueryFindings(ctx, path, FindingQueryInput{Service: "Redis", Purpose: "Verify bounded full-result grouping", Limit: 1})
	if err != nil {
		t.Fatalf("query grouped findings: %v", err)
	}
	if len(grouped.Findings) != 1 || grouped.MatchedCount != 2 || len(grouped.ActionGroups) != 2 {
		t.Fatalf("truncated items lost full-result action groups: %#v", grouped)
	}

	diff, err := BaselineDiff(ctx, path, BaselineDiffInput{Purpose: "Explain what changed since the previous scan"})
	if err != nil {
		t.Fatalf("baseline diff: %v", err)
	}
	if diff.ContractVersion != "agent-baseline-diff.v1" || diff.State != "NO_BASELINE" || diff.Disclosure.AuditEventRef == "" {
		t.Fatalf("unexpected no-baseline result: %#v", diff)
	}
}

func seedQueryState(t *testing.T, ctx context.Context) (string, model.Resource, model.Resource) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := storage.NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	now := time.Now().UTC()
	service := model.Resource{
		ID: "service-redis", UID: "redis", Type: model.ResourceTypeService, Name: "Redis",
		Source: model.SourceInfo{System: "kubernetes", Cluster: "production", Instance: "cluster-a"}, Status: model.ResourceStatusActive,
	}
	target := model.Resource{
		ID: "target-redis-exporter", UID: "redis-exporter", Type: model.ResourceTypeTarget, Name: "redis-exporter",
		Source: model.SourceInfo{System: "prometheus", Cluster: "production", Instance: "prom-main"}, Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{service, target} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("save resource: %v", err)
		}
	}
	if err := store.CoverageExpectations.Save(ctx, model.CoverageExpectation{
		ID: "redis-team-baseline", Name: "Redis team baseline", Scope: model.CoverageScopeService,
		ScopeValue: service.ID, RequiredSignals: []model.CoverageSignal{model.CoverageSignalMetrics},
		Owner: "redis-team", Rationale: "Redis requires explicit metrics coverage", Enabled: true,
		CreatedBy: "test", CreatedAt: now, UpdatedBy: "test", UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save custom coverage expectation: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID: "target-belongs-service", FromID: target.ID, ToID: service.ID, Type: model.RelationshipBelongsTo, CreatedAt: now,
	}); err != nil {
		t.Fatalf("save relationship: %v", err)
	}
	score := &model.FindingRiskScore{Version: "risk.v1", Score: 92, Level: "CRITICAL", Confidence: 90, ConfidenceLevel: "HIGH"}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test", []model.Finding{{
		ID: "finding-broken-redis", Type: "BrokenTarget", Severity: model.SeverityCritical,
		Category: model.FindingCategoryReliability, RiskScore: score,
		Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
		Evidence: []string{"raw evidence should stay local"}, Recommendation: "Check https://prometheus.internal/targets before changing alerting.",
		Metadata: map[string]string{"analyzer_id": "test"}, Status: model.FindingStatusOpen,
	}}); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	return path, service, target
}
