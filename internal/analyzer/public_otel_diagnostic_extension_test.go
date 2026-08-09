package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPublicOTelDiagnosticExtensionAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		otelDiagnosticExtension("public-pprof", "pprof", "true", "true", "true"),
		otelDiagnosticExtension("public-zpages", "zpages", "true", "true", "true"),
		otelDiagnosticExtension("loopback", "pprof", "true", "true", "false"),
		otelDiagnosticExtension("environment", "zpages", "true", "false", "false"),
		otelDiagnosticExtension("disabled", "pprof", "false", "true", "true"),
		otelDiagnosticExtension("health", "health_check", "true", "true", "true"),
	}
	deprecated := otelDiagnosticExtension("deprecated", "pprof", "true", "true", "true")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert extension: %v", err)
		}
	}

	findings, err := NewPublicOTelDiagnosticExtensionAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 ||
		findings[0].Resource.ID != "public-pprof" ||
		findings[1].Resource.ID != "public-zpages" {
		t.Fatalf("unexpected public diagnostic findings: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Type != "PublicOTelDiagnosticExtension" ||
			finding.Severity != model.SeverityWarning ||
			finding.Category != model.FindingCategorySecurity ||
			model.DefaultFindingCategory(finding.Type, finding.Resource.Type) != model.FindingCategorySecurity ||
			strings.Contains(strings.Join(finding.Evidence, " "), "1777") {
			t.Fatalf("unexpected public diagnostic finding contract: %#v", finding)
		}
	}
}

func otelDiagnosticExtension(id, extensionType, enabled, evaluable, public string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeExtension,
		Name:   id,
		Source: model.SourceInfo{System: "otelcol", Instance: "/etc/otelcol.yaml"},
		Metadata: map[string]string{
			model.MetadataComponentType:                 extensionType,
			model.MetadataOTelExtensionEnabled:          enabled,
			model.MetadataOTelEndpointExposureEvaluable: evaluable,
			model.MetadataOTelEndpointPublic:            public,
		},
		Status: model.ResourceStatusActive,
	}
}
