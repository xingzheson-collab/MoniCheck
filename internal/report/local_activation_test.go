package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestLocalActivationTimingIsImmutableAndPrivacyBounded(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	started := time.Date(2026, 8, 9, 4, 30, 0, 0, time.UTC)
	first, err := SaveLocalActivationTiming(ctx, store, started, started.Add(42*time.Second), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SaveLocalActivationTiming(ctx, store, started.Add(time.Hour), started.Add(time.Hour+20*time.Minute), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.ContractVersion != LocalActivationTimingContract || first.ElapsedMilliseconds != 42000 || !first.WithinTarget {
		t.Fatalf("activation timing must retain the first successful report: first=%#v second=%#v", first, second)
	}
	exports, err := store.ReportExports.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 1 || exports[0].Origin != LocalActivationTimingOrigin || exports[0].ExecutionID != "" {
		t.Fatalf("unexpected activation timing storage boundary: %#v", exports)
	}
}

func TestLocalActivationTimingRejectsInvalidWindow(t *testing.T) {
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	if _, err := SaveLocalActivationTiming(context.Background(), store, now, now.Add(-time.Second), 15*time.Minute); err == nil {
		t.Fatal("accepted an activation completion before its start")
	}
}

func TestLocalActivationTimingDoesNotSubstituteLegacyAnalyzerWindow(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	legacyStart := time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC)
	legacyExecution := model.ExecutionResult{ID: "legacy-first", StartedAt: legacyStart, FinishedAt: legacyStart.Add(70 * time.Second)}
	if err := store.Executions.Save(ctx, legacyExecution); err != nil {
		t.Fatal(err)
	}
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "legacy-snapshot", Type: "governance", Format: "json", Origin: LocalPostureSnapshotOrigin,
		ExecutionID: legacyExecution.ID, CreatedAt: legacyExecution.FinishedAt,
	}); err != nil {
		t.Fatal(err)
	}
	now := legacyStart.Add(8 * 24 * time.Hour)
	timing, err := SaveLocalActivationTiming(ctx, store, now, now.Add(20*time.Minute), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !timing.StartedAt.Equal(now) || !timing.CompletedAt.Equal(now.Add(20*time.Minute)) || timing.ElapsedMilliseconds != int64((20*time.Minute)/time.Millisecond) || timing.WithinTarget {
		t.Fatalf("legacy analyzer timing replaced the real activation window: %#v", timing)
	}
}
