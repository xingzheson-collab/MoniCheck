package execution

import "context"

const (
	ProgressStageSourceCollection        = "SOURCE_COLLECTION"
	ProgressStageSnapshotPersistence     = "SNAPSHOT_PERSISTENCE"
	ProgressStageInventoryReconciliation = "INVENTORY_RECONCILIATION"
	ProgressStageAnalysis                = "ANALYSIS"
	ProgressStageFindingPersistence      = "FINDING_PERSISTENCE"
)

// ProgressEvent contains only aggregate, credential-safe Local scan state.
type ProgressEvent struct {
	Stage             string
	Total             int
	ResourceCount     int
	RelationshipCount int
}

type progressReporterKey struct{}

// WithProgressReporter attaches an in-process observer without changing scan output contracts.
func WithProgressReporter(ctx context.Context, reporter func(ProgressEvent)) context.Context {
	if reporter == nil {
		return ctx
	}
	return context.WithValue(ctx, progressReporterKey{}, reporter)
}

func emitProgress(ctx context.Context, event ProgressEvent) {
	reporter, _ := ctx.Value(progressReporterKey{}).(func(ProgressEvent))
	if reporter != nil {
		reporter(event)
	}
}
