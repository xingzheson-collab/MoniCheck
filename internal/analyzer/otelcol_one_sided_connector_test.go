package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelColOneSidedConnectorAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	balanced := otelConnectorResource("balanced", "2", "1")
	missingReceiver := otelConnectorResource("missing-receiver", "0", "1")
	missingExporter := otelConnectorResource("missing-exporter", "3", "0")
	unused := otelConnectorResource("unused", "0", "0")
	malformed := otelConnectorResource("malformed", "unknown", "1")
	deprecated := otelConnectorResource("deprecated", "0", "1")
	deprecated.Status = model.ResourceStatusDeprecated
	otherSystem := otelConnectorResource("other-system", "0", "1")
	otherSystem.Source.System = "other"

	for _, resource := range []model.Resource{balanced, missingReceiver, missingExporter, unused, malformed, deprecated, otherSystem} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewOTelColOneSidedConnectorAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected two one-sided connector findings, got %#v", findings)
	}
	if findings[0].Resource.ID != missingExporter.ID ||
		findings[0].Metadata["missing_role"] != "exporter" ||
		findings[1].Resource.ID != missingReceiver.ID ||
		findings[1].Metadata["missing_role"] != "receiver" {
		t.Fatalf("unexpected one-sided connector findings: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Type != "OTelConnectorOneSided" ||
			finding.Severity != model.SeverityCritical ||
			finding.Category != model.FindingCategoryReliability {
			t.Fatalf("unexpected finding contract: %#v", finding)
		}
	}
}

func otelConnectorResource(name string, receiverUsage string, exporterUsage string) model.Resource {
	resource := otelResource(model.ResourceTypeTelemetryConnector, name, "connector:"+name)
	resource.Metadata[model.MetadataOTelConnectorReceiverUsage] = receiverUsage
	resource.Metadata[model.MetadataOTelConnectorExporterUsage] = exporterUsage
	return resource
}
