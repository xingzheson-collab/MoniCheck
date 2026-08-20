package contract

import (
	"strings"
	"testing"
	"time"

	"monicheck/internal/connector"
	"monicheck/internal/model"
)

func TestValidateSnapshot(t *testing.T) {
	now := time.Now().UTC()
	resource := model.Resource{
		ID:        "metric-1",
		Type:      model.ResourceTypeMetric,
		Name:      "http_requests_total",
		UID:       "metric-1",
		Source:    model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "metric:http_requests_total"},
		Status:    model.ResourceStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	snapshot := connector.Snapshot{
		Resources: []model.Resource{resource},
		Relationships: []model.Relationship{
			{
				ID:        "rel-1",
				FromID:    resource.ID,
				ToID:      resource.ID,
				Type:      model.RelationshipUses,
				CreatedAt: now,
			},
		},
	}

	result := ValidateSnapshot(snapshot)
	if !result.Valid {
		t.Fatalf("expected valid snapshot, got %#v", result.Violations)
	}
}

func TestValidateSnapshotAcceptsRelationshipToReadOnlyReference(t *testing.T) {
	now := time.Now().UTC()
	panel := model.Resource{
		ID: "panel-1", Type: model.ResourceTypePanel, Name: "Requests", UID: "panel-1",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:1"},
		Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	metric := model.Resource{
		ID: "metric-1", Type: model.ResourceTypeMetric, Name: "http_requests_total", UID: "metric-1",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "metric:http_requests_total"},
		Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	result := ValidateSnapshot(connector.Snapshot{
		Resources:  []model.Resource{panel},
		References: []model.Resource{metric},
		Relationships: []model.Relationship{{
			ID: "uses", FromID: panel.ID, ToID: metric.ID, Type: model.RelationshipUses,
		}},
	})
	if !result.Valid {
		t.Fatalf("expected reference-complete snapshot, got %#v", result.Violations)
	}
}

func TestValidateSnapshotRejectsMissingFieldsAndInvalidReferences(t *testing.T) {
	result := ValidateSnapshot(connector.Snapshot{
		Resources: []model.Resource{
			{ID: "metric-1", Type: model.ResourceTypeMetric},
			{ID: "metric-1", Type: model.ResourceTypeMetric},
		},
		Relationships: []model.Relationship{
			{ID: "rel-1", FromID: "metric-1", ToID: "missing", Type: model.RelationshipUses},
		},
	})

	if result.Valid {
		t.Fatalf("expected invalid snapshot")
	}
	assertViolation(t, result, "DuplicateID", "id")
	assertViolation(t, result, "MissingField", "name")
	assertViolation(t, result, "MissingField", "uid")
	assertViolation(t, result, "MissingField", "source.system")
	assertViolation(t, result, "InvalidReference", "to_id")
}

func TestNormalizeAndValidateFindings(t *testing.T) {
	findings := NormalizeFindings("builtin.test", []model.Finding{
		{
			ID:       "finding-1",
			Type:     "UnusedMetric",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: "metric-1", Type: model.ResourceTypeMetric, Name: "http_requests_total"},
			Evidence: []string{"metric has no consumers"},
		},
	})

	if findings[0].Status != model.FindingStatusOpen {
		t.Fatalf("expected default open status, got %s", findings[0].Status)
	}
	if findings[0].Category == "" {
		t.Fatalf("expected default category")
	}
	if findings[0].Metadata["analyzer_id"] != "builtin.test" {
		t.Fatalf("expected analyzer id metadata, got %#v", findings[0].Metadata)
	}
	if result := ValidateFindings(findings); !result.Valid {
		t.Fatalf("expected valid findings, got %#v", result.Violations)
	}
}

func TestNormalizeFindingsLocalizesBuiltInRecommendationsOnly(t *testing.T) {
	builtIn := NormalizeFindings("builtin.missing_owner", []model.Finding{{
		ID: "missing-owner", Type: "MissingOwner", Severity: model.SeverityWarning,
		Category: model.FindingCategoryLifecycle,
		Resource: model.ResourceRef{ID: "service-api", Type: model.ResourceTypeService, Name: "api"},
		Evidence: []string{"服务缺少 owner 标签。"}, Recommendation: "为资源补充 owner 标签。",
	}})
	if containsHan(builtIn[0].Recommendation) || builtIn[0].Metadata["recommendation.localized"] != "en" || !strings.Contains(builtIn[0].Recommendation, "owner") {
		t.Fatalf("built-in recommendation was not localized: %#v", builtIn[0])
	}
	if evidenceContainsHan(builtIn[0].Evidence) || builtIn[0].Metadata["evidence.localized"] != "en" || !strings.Contains(builtIn[0].Evidence[0], "MissingOwner") {
		t.Fatalf("built-in evidence was not localized: %#v", builtIn[0])
	}

	custom := NormalizeFindings("builtin.rule_engine", []model.Finding{{
		ID: "custom", Type: "CustomPolicy", Severity: model.SeverityWarning,
		Category: model.FindingCategoryQuality,
		Resource: model.ResourceRef{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api"},
		Evidence: []string{"保留用户自定义证据。"}, Recommendation: "保留用户自定义建议。",
	}})
	if !containsHan(custom[0].Recommendation) || !evidenceContainsHan(custom[0].Evidence) || custom[0].Metadata["recommendation.localized"] != "" || custom[0].Metadata["evidence.localized"] != "" {
		t.Fatalf("user-authored recommendation was changed: %#v", custom[0])
	}

	english := NormalizeFindings("builtin.test", []model.Finding{{
		ID: "english", Type: "BrokenTarget", Severity: model.SeverityWarning,
		Category: model.FindingCategoryReliability,
		Resource: model.ResourceRef{ID: "target-api", Type: model.ResourceTypeTarget, Name: "api"},
		Evidence: []string{"target is down"}, Recommendation: "Check exporter health.",
	}})
	if english[0].Recommendation != "Check exporter health." || english[0].Metadata["recommendation.localized"] != "" {
		t.Fatalf("English recommendation was changed: %#v", english[0])
	}
	if english[0].Evidence[0] != "target is down" || english[0].Metadata["evidence.localized"] != "" {
		t.Fatalf("English evidence was changed: %#v", english[0])
	}
}

func TestNormalizeFindingsUsesDomainAwareEnglishFallback(t *testing.T) {
	findings := NormalizeFindings("builtin.kubernetes_test", []model.Finding{{
		ID: "kubernetes", Type: "KubernetesUnknownOperatorCondition", Severity: model.SeverityWarning,
		Category: model.FindingCategoryConfiguration,
		Resource: model.ResourceRef{ID: "prometheus-main", Type: model.ResourceTypeTSDB, Name: "main"},
		Evidence: []string{"Kubernetes Prometheus main has an invalid operator condition"},
	}})
	if len(findings) != 1 || !strings.Contains(findings[0].Recommendation, "Kubernetes manifest") || findings[0].Metadata["recommendation.localized"] != "en" {
		t.Fatalf("expected domain-aware Kubernetes fallback for empty recommendation: %#v", findings)
	}

	otel := EnglishRecommendation(model.Finding{Type: "OTelUnknownPipelineCondition", Category: model.FindingCategoryReliability, Resource: model.ResourceRef{Type: model.ResourceTypePipeline}})
	if !strings.Contains(otel, "OpenTelemetry Collector") || containsHan(otel) {
		t.Fatalf("expected domain-aware OTel fallback, got %q", otel)
	}
	runbook := EnglishRecommendation(model.Finding{Type: "MissingRunbook", Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{Type: model.ResourceTypeAlertRule}})
	if !strings.Contains(runbook, "diagnosis, impact, mitigation, and escalation") {
		t.Fatalf("expected actionable first-report runbook recommendation, got %q", runbook)
	}
}

func assertViolation(t *testing.T, result ValidationResult, code string, field string) {
	t.Helper()
	for _, violation := range result.Violations {
		if violation.Code == code && violation.Field == field {
			return
		}
	}
	t.Fatalf("expected violation %s %s in %#v", code, field, result.Violations)
}
