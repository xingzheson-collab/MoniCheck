package localruntime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

func TestOpenExistingDoesNotRequireOrRunConnectors(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent-state.json")
	store, err := storage.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "report", Type: "governance", Format: "json", Origin: report.LocalPostureSnapshotOrigin,
		ContentType: "application/json", Content: `{"resource_count":1}`, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Executions.Save(ctx, model.ExecutionResult{ID: "run", Status: model.ExecutionStatusSucceeded, FinishedAt: now}); err != nil {
		t.Fatal(err)
	}

	runtime, err := OpenExisting(ctx, path)
	if err != nil {
		t.Fatalf("open existing state: %v", err)
	}
	if runtime.StateSource != "PERSISTED_AGENT_AUDIT" || runtime.Execution.ID != "run" {
		t.Fatalf("unexpected persisted runtime: %#v", runtime)
	}
	if statuses := runtime.Engine.ConnectorStatuses(); len(statuses) != 0 {
		t.Fatalf("opening existing state ran connectors: %#v", statuses)
	}
}
