package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelExporterQueueNearSaturationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	atThreshold := otelcolQueueRuntimeResource("at-threshold", "true", "3", "0", "80")
	nearFull := otelcolQueueRuntimeResource("near-full", "true", "2", "0", "99.5")
	belowThreshold := otelcolQueueRuntimeResource("below-threshold", "true", "2", "0", "79.9")
	full := otelcolQueueRuntimeResource("full", "true", "2", "1", "100")
	inconsistentFull := otelcolQueueRuntimeResource("inconsistent-full", "true", "2", "0", "100")
	unobserved := otelcolQueueRuntimeResource("unobserved", "true", "0", "0", "95")
	unavailable := otelcolQueueRuntimeResource("unavailable", "false", "2", "0", "95")
	wrongSource := otelcolQueueRuntimeResource("wrong-source", "true", "2", "0", "95")
	wrongSource.Source.System = "plugin"
	inactive := otelcolQueueRuntimeResource("inactive", "true", "2", "0", "95")
	inactive.Status = model.ResourceStatusOrphan
	for _, resource := range []model.Resource{
		atThreshold,
		nearFull,
		belowThreshold,
		full,
		inconsistentFull,
		unobserved,
		unavailable,
		wrongSource,
		inactive,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	item := NewOTelExporterQueueNearSaturationAnalyzer()
	findings, err := item.Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected threshold and near-full findings, got %#v", findings)
	}
	byResource := map[string]model.Finding{}
	for _, finding := range findings {
		byResource[finding.Resource.ID] = finding
		if finding.Type != "OTelExporterQueueNearSaturation" ||
			finding.Severity != model.SeverityWarning ||
			finding.Category != model.FindingCategoryReliability ||
			finding.Metadata["threshold_percent"] != "80" ||
			model.DefaultFindingCategory(finding.Type, finding.Resource.Type) != model.FindingCategoryReliability {
			t.Fatalf("unexpected finding: %#v", finding)
		}
		encoded, marshalErr := json.Marshal(finding)
		if marshalErr != nil {
			t.Fatalf("marshal finding: %v", marshalErr)
		}
		for _, privateValue := range []string{"private-exporter", "private-instance", "private-label", "queue-capacity"} {
			if strings.Contains(string(encoded), privateValue) {
				t.Fatalf("finding leaked %q: %s", privateValue, encoded)
			}
		}
	}
	if !strings.Contains(byResource[atThreshold.ID].Evidence[0], "80% maximum utilization") ||
		!strings.Contains(byResource[nearFull.ID].Evidence[0], "99.5% maximum utilization") {
		t.Fatalf("unexpected evidence: %#v", byResource)
	}
}
