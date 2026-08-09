package connector

import (
	"fmt"
	"testing"

	"monicheck/internal/model"
)

func TestPrivacySafeDiscoveredValuesNormalizesAndDeduplicates(t *testing.T) {
	values := privacySafeDiscoveredValues("loki", "tenant", []string{
		" alpha ",
		"alpha",
		"",
		"  ",
		"beta",
	})
	if len(values) != 2 {
		t.Fatalf("expected two unique non-empty values, got %#v", values)
	}
	if values[0].raw != "alpha" || values[1].raw != "beta" {
		t.Fatalf("unexpected normalized values: %#v", values)
	}
	if values[0].fingerprint == "" || values[1].fingerprint == "" || values[0].fingerprint == values[1].fingerprint {
		t.Fatalf("unexpected value fingerprints: %#v", values)
	}
	again := privacySafeDiscoveredValues("loki", "tenant", []string{"alpha"})
	if len(again) != 1 || again[0].fingerprint != values[0].fingerprint {
		t.Fatalf("expected deterministic fingerprint, got %#v and %#v", values[0], again)
	}
}

func TestRedactedDiscoveredValueNameDoesNotContainRawValue(t *testing.T) {
	name := redactedDiscoveredValueName("tenant", "1234567890abcdef")
	if name != "tenant=<redacted:1234567890ab>" {
		t.Fatalf("unexpected redacted value name %q", name)
	}
}

func assertPrivacyResourceCount(t *testing.T, snapshot Snapshot, resourceType model.ResourceType, expected int) {
	t.Helper()
	count := 0
	for _, resource := range snapshot.Resources {
		if resource.Type == resourceType {
			count++
		}
	}
	if count != expected {
		t.Fatalf("expected %d %s resources, got %d", expected, resourceType, count)
	}
}

func assertDetailDiscoveryDiagnostic(t *testing.T, snapshot Snapshot, id string, total int, failed int) {
	t.Helper()
	if snapshot.Partial != (failed > 0) {
		t.Fatalf("unexpected partial state %t for failed count %d", snapshot.Partial, failed)
	}
	var diagnostic model.Diagnostic
	found := false
	for _, item := range snapshot.Diagnostics {
		if item.ID == id {
			diagnostic = item
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %s detail diagnostic, got %#v", id, snapshot.Diagnostics)
	}
	expectedStatus := model.ExecutionStatusSucceeded
	if failed > 0 {
		expectedStatus = model.ExecutionStatusWarning
	}
	if diagnostic.Status != expectedStatus ||
		diagnostic.Metadata["item_count"] != fmt.Sprintf("%d", total) ||
		diagnostic.Metadata["failed_count"] != fmt.Sprintf("%d", failed) {
		t.Fatalf("unexpected detail diagnostic: %#v", diagnostic)
	}
	expectedWorkers := total
	if expectedWorkers > defaultConnectorDetailWorkers {
		expectedWorkers = defaultConnectorDetailWorkers
	}
	if diagnostic.Metadata["worker_count"] != fmt.Sprintf("%d", expectedWorkers) {
		t.Fatalf("expected worker_count=%d, got %#v", expectedWorkers, diagnostic.Metadata)
	}
}
