package report

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/coverage"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildGovernanceExportIncludesBoundedPriorityFindingEvidence(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	findings := []model.Finding{
		{
			ID: "critical", Type: "MissingServiceAlert", Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability, Status: model.FindingStatusOpen,
			Resource:       model.ResourceRef{ID: "service-checkout", Type: model.ResourceTypeService, Name: "checkout"},
			Evidence:       []string{"checkout has metrics but no evaluable alert coverage"},
			Recommendation: "Add an owned symptom alert and verify notification delivery.",
			Metadata:       map[string]string{"connector.private_token": "must-not-export"},
		},
		{
			ID: "warning", Type: "HighCardinalityMetric", Severity: model.SeverityWarning,
			Category: model.FindingCategoryCost, Status: model.FindingStatusOpen,
			RiskScore: &model.FindingRiskScore{Score: 91, Level: "HIGH", Confidence: 88},
			Resource:  model.ResourceRef{ID: "metric-requests", Type: model.ResourceTypeMetric, Name: "requests_total"},
			Evidence:  []string{"requests_total has 24,000 active series"}, Recommendation: "Remove unbounded labels after consumer review.",
		},
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test.priority", findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	export, err := BuildExport(ctx, store, "governance", "json")
	if err != nil {
		t.Fatalf("build governance export: %v", err)
	}
	var payload struct {
		ContractVersion  string `json:"contract_version"`
		CriticalCount    int    `json:"critical_count"`
		WarningCount     int    `json:"warning_count"`
		PriorityFindings []struct {
			ID             string   `json:"id"`
			RiskScore      int      `json:"risk_score"`
			Evidence       []string `json:"evidence"`
			Recommendation string   `json:"recommendation"`
		} `json:"priority_findings"`
	}
	if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
		t.Fatalf("decode governance export: %v", err)
	}
	if payload.ContractVersion != "governance-report.v2" || len(payload.PriorityFindings) != 2 || payload.PriorityFindings[0].ID != "critical" || payload.PriorityFindings[1].RiskScore != 91 {
		t.Fatalf("unexpected priority finding projection: %#v", payload)
	}
	if payload.CriticalCount != 1 || payload.WarningCount != 1 {
		t.Fatalf("unexpected severity summary: %#v", payload)
	}
	if len(payload.PriorityFindings[0].Evidence) != 1 || payload.PriorityFindings[0].Recommendation == "" || strings.Contains(export.Content, "must-not-export") {
		t.Fatalf("priority evidence is incomplete or leaked metadata: %s", export.Content)
	}
}

func TestGovernancePriorityDeprioritizesDatasourceHealthWithinSeverity(t *testing.T) {
	findings := []model.Finding{
		{ID: "health", Type: "InvalidDatasource", Severity: model.SeverityWarning, Status: model.FindingStatusOpen, RiskScore: &model.FindingRiskScore{Score: 99}},
		{ID: "coverage", Type: "ServiceObservabilityGap", Severity: model.SeverityWarning, Status: model.FindingStatusOpen, RiskScore: &model.FindingRiskScore{Score: 50}},
	}
	got := governancePriorityFindings(findings, 2)
	if len(got) != 2 || got[0].ID != "coverage" || got[1].ID != "health" {
		t.Fatalf("datasource health still crowded out other priority work: %#v", got)
	}
}

func TestGovernanceExportLocalizesOnlyBuiltInFindingPresentation(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	builtIn := model.Finding{
		ID: "builtin", Type: "KubernetesUnknownOperatorCondition", Severity: model.SeverityWarning,
		Category: model.FindingCategoryConfiguration, Status: model.FindingStatusOpen,
		Resource: model.ResourceRef{ID: "prometheus-main", Type: model.ResourceTypeTSDB, Name: "main"},
		Evidence: []string{"内置证据。"}, Recommendation: "修复 Kubernetes 配置。",
		Metadata: map[string]string{"analyzer_id": "builtin.legacy"},
	}
	custom := model.Finding{
		ID: "custom", Type: "CustomPolicy", Severity: model.SeverityWarning,
		Category: model.FindingCategoryQuality, Status: model.FindingStatusOpen,
		Resource: model.ResourceRef{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api"},
		Evidence: []string{"保留自定义证据。"}, Recommendation: "保留自定义建议。",
		Metadata: map[string]string{"analyzer_id": "builtin.rule_engine"},
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "builtin.legacy", []model.Finding{builtIn}); err != nil {
		t.Fatal(err)
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "builtin.rule_engine", []model.Finding{custom}); err != nil {
		t.Fatal(err)
	}
	export, err := BuildExport(ctx, store, "governance", "json")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		PriorityFindings []struct {
			ID             string   `json:"id"`
			Evidence       []string `json:"evidence"`
			Recommendation string   `json:"recommendation"`
		} `json:"priority_findings"`
	}
	if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
		t.Fatal(err)
	}
	byID := map[string]struct {
		Evidence       []string
		Recommendation string
	}{}
	for _, item := range payload.PriorityFindings {
		byID[item.ID] = struct {
			Evidence       []string
			Recommendation string
		}{item.Evidence, item.Recommendation}
	}
	if item := byID["builtin"]; len(item.Evidence) != 1 || strings.Contains(item.Evidence[0], "内置") || !strings.Contains(item.Recommendation, "Kubernetes manifest") {
		t.Fatalf("legacy built-in presentation was not localized: %#v", item)
	}
	if item := byID["custom"]; len(item.Evidence) != 1 || item.Evidence[0] != "保留自定义证据。" || item.Recommendation != "保留自定义建议。" {
		t.Fatalf("user-authored presentation was changed: %#v", item)
	}
}

func TestBuildGovernanceExportIncludesEvaluableCoverageEvidence(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive},
		{ID: "dashboard-other", Type: model.ResourceTypeDashboard, Name: "Other service", Status: model.ResourceStatusActive},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID: "metric-api-service", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	export, err := BuildExport(ctx, store, "governance", "json")
	if err != nil {
		t.Fatalf("build governance export: %v", err)
	}
	var payload struct {
		CoverageServiceCount         int              `json:"coverage_service_count"`
		CoveragePercent              int              `json:"coverage_percent"`
		CoverageMissingSignals       int              `json:"coverage_missing_signals"`
		CoverageUnknownSignals       int              `json:"coverage_unknown_signals"`
		CoverageEvaluableSignals     int              `json:"coverage_evaluable_signals"`
		CoverageEvidenceState        string           `json:"coverage_evidence_state"`
		CoverageEvidenceCompleteness int              `json:"coverage_evidence_completeness_percent"`
		Coverage                     coverage.Summary `json:"coverage"`
	}
	if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
		t.Fatalf("decode governance export: %v", err)
	}
	if payload.CoverageServiceCount != 1 || payload.CoveragePercent != 50 || payload.CoverageMissingSignals != 1 || payload.CoverageUnknownSignals != 1 || payload.CoverageEvaluableSignals != 2 || payload.CoverageEvidenceState != "PARTIAL" || payload.CoverageEvidenceCompleteness != 67 {
		t.Fatalf("unexpected coverage evidence: %#v", payload)
	}
	if len(payload.Coverage.Assessments) != 1 || payload.Coverage.Assessments[0].State != coverage.AssessmentMissing {
		t.Fatalf("expected a detailed missing assessment: %#v", payload.Coverage)
	}
	if payload.Coverage.EvidenceState != coverage.EvidencePartial || payload.Coverage.EvidenceCompleteness == nil {
		t.Fatalf("expected detailed partial evidence completeness: %#v", payload.Coverage)
	}
}

func TestBuildServicesExportIncludesDerivedMetricImpact(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Source: model.SourceInfo{System: "catalog"}, Status: model.ResourceStatusActive},
		{ID: "metric-raw", Type: model.ResourceTypeMetric, Name: "http_requests_total", Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive},
		{ID: "metric-derived", Type: model.ResourceTypeMetric, Name: "job:http_requests:rate5m", Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive},
		{ID: "record-api", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Source: model.SourceInfo{System: "n9e"}, Status: model.ResourceStatusActive},
		{ID: "panel-api", Type: model.ResourceTypePanel, Name: "API throughput", Source: model.SourceInfo{System: "grafana"}, Status: model.ResourceStatusActive},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "metric-belongs-service", FromID: "metric-raw", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "record-uses-raw", FromID: "record-api", ToID: "metric-raw", Type: model.RelationshipUses},
		{ID: "record-produces-derived", FromID: "record-api", ToID: "metric-derived", Type: model.RelationshipProduces},
		{ID: "raw-produces-derived", FromID: "metric-raw", ToID: "metric-derived", Type: model.RelationshipProduces},
		{ID: "panel-uses-derived", FromID: "panel-api", ToID: "metric-derived", Type: model.RelationshipUses},
	}
	for _, relationship := range relationships {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test.service_export", []model.Finding{
		{
			ID:       "finding-panel",
			Type:     "PanelFinding",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryQuality,
			Resource: model.ResourceRef{ID: "panel-api", Type: model.ResourceTypePanel, Name: "API throughput"},
			Status:   model.FindingStatusOpen,
			Metadata: map[string]string{"analyzer_id": "test.service_export"},
		},
	}); err != nil {
		t.Fatalf("save finding: %v", err)
	}

	export, err := BuildExport(ctx, store, "services", "json")
	if err != nil {
		t.Fatalf("build export: %v", err)
	}
	var payload struct {
		Services []struct {
			ResourceCount          int            `json:"resource_count"`
			FindingCount           int            `json:"finding_count"`
			ImpactResourceCount    int            `json:"impact_resource_count"`
			ImpactFindingCount     int            `json:"impact_finding_count"`
			ImpactResourcesByType  map[string]int `json:"impact_resources_by_type"`
			ImpactFindingsBySource map[string]int `json:"impact_findings_by_source"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if len(payload.Services) != 1 {
		t.Fatalf("expected one service export item, got %#v", payload.Services)
	}
	service := payload.Services[0]
	if service.ResourceCount != 1 || service.FindingCount != 0 {
		t.Fatalf("expected direct attribution to remain unchanged, got %#v", service)
	}
	if service.ImpactResourceCount != 4 || service.ImpactFindingCount != 1 {
		t.Fatalf("expected derived metric impact in export, got %#v", service)
	}
	if service.ImpactResourcesByType[string(model.ResourceTypeRecordingRule)] != 1 || service.ImpactResourcesByType[string(model.ResourceTypePanel)] != 1 {
		t.Fatalf("expected recording rule and panel impact resource summary, got %#v", service.ImpactResourcesByType)
	}
	if service.ImpactFindingsBySource["grafana"] != 1 {
		t.Fatalf("expected panel finding impact source to be grafana, got %#v", service.ImpactFindingsBySource)
	}
}

func TestBuildCostExportIncludesTSDBSummary(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "tsdb-prometheus", Type: model.ResourceTypeTSDB, Name: "prometheus TSDB", Source: model.SourceInfo{System: "prometheus", Instance: "http://prometheus:9090"}, Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "3000", model.MetadataTSDBHeadChunks: "4500", model.MetadataTSDBHeadRangeSeconds: "7200", model.MetadataTSDBLabelValueCount: "5002", model.MetadataTSDBLabelMemoryBytes: "2000100"}},
		{ID: "tsdb-thanos", Type: model.ResourceTypeTSDB, Name: "thanos TSDB", Source: model.SourceInfo{System: "thanos", Instance: "http://thanos:10902"}, Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "7000", model.MetadataTSDBHeadChunks: "8000", model.MetadataTSDBLabelValueCount: "9000", model.MetadataTSDBLabelMemoryBytes: "3000000"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB: %v", err)
		}
	}
	export, err := BuildExport(ctx, store, "cost", "json")
	if err != nil {
		t.Fatalf("build cost export: %v", err)
	}
	var payload TSDBCostSummary
	if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
		t.Fatalf("decode cost export: %v", err)
	}
	if payload.TSDBCount != 2 || payload.HeadSeries != 10000 || payload.HeadChunks != 12500 || payload.LabelValueCount != 14002 || payload.LabelMemoryBytes != 5000100 || len(payload.Instances) != 2 {
		t.Fatalf("unexpected TSDB cost summary: %#v", payload)
	}
}
