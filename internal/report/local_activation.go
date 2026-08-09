package report

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	LocalActivationTimingContract = "local-activation-timing.v1"
	LocalActivationTimingOrigin   = "LOCAL_ACTIVATION"
	localActivationTimingID       = "local-activation-timing-v1"
)

type LocalActivationTiming struct {
	ContractVersion     string    `json:"contract_version"`
	StartedAt           time.Time `json:"started_at"`
	CompletedAt         time.Time `json:"completed_at"`
	ElapsedMilliseconds int64     `json:"elapsed_milliseconds"`
	TargetSeconds       int64     `json:"target_seconds"`
	WithinTarget        bool      `json:"within_target"`
}

func SaveLocalActivationTiming(ctx context.Context, store *storage.Store, startedAt time.Time, completedAt time.Time, target time.Duration) (LocalActivationTiming, error) {
	if store == nil || store.ReportExports == nil {
		return LocalActivationTiming{}, errors.New("report export storage is unavailable")
	}
	if existing, found, err := LoadLocalActivationTiming(ctx, store); err != nil || found {
		return existing, err
	}
	exports, err := store.ReportExports.List(ctx)
	if err != nil {
		return LocalActivationTiming{}, err
	}
	var earliest *model.ReportExport
	for i := range exports {
		export := &exports[i]
		if export.Origin != LocalPostureSnapshotOrigin || export.ExecutionID == "" || export.CreatedAt.IsZero() {
			continue
		}
		if earliest == nil || export.CreatedAt.Before(earliest.CreatedAt) {
			earliest = export
		}
	}
	if earliest != nil && store.Executions != nil {
		executions, listErr := store.Executions.List(ctx)
		if listErr != nil {
			return LocalActivationTiming{}, listErr
		}
		for _, execution := range executions {
			if execution.ID != earliest.ExecutionID || execution.StartedAt.IsZero() {
				continue
			}
			legacyCompletedAt := execution.FinishedAt
			if legacyCompletedAt.IsZero() {
				legacyCompletedAt = earliest.CreatedAt
			}
			if !legacyCompletedAt.Before(execution.StartedAt) {
				startedAt = execution.StartedAt
				completedAt = legacyCompletedAt
			}
			break
		}
	}
	startedAt = startedAt.UTC()
	completedAt = completedAt.UTC()
	if startedAt.IsZero() || completedAt.IsZero() || completedAt.Before(startedAt) {
		return LocalActivationTiming{}, errors.New("valid activation start and completion times are required")
	}
	if target <= 0 {
		return LocalActivationTiming{}, errors.New("activation target must be positive")
	}
	elapsed := completedAt.Sub(startedAt)
	timing := LocalActivationTiming{
		ContractVersion:     LocalActivationTimingContract,
		StartedAt:           startedAt,
		CompletedAt:         completedAt,
		ElapsedMilliseconds: elapsed.Milliseconds(),
		TargetSeconds:       int64(target.Seconds()),
		WithinTarget:        elapsed <= target,
	}
	body, err := json.Marshal(timing)
	if err != nil {
		return LocalActivationTiming{}, err
	}
	export := model.ReportExport{
		ID: localActivationTimingID, Type: "activation-timing", Format: "json",
		Origin: LocalActivationTimingOrigin, Filename: "local-activation-timing.json",
		ContentType: "application/json", Content: string(body), CreatedAt: completedAt,
	}
	if err := store.ReportExports.Save(ctx, export); err != nil {
		return LocalActivationTiming{}, err
	}
	return timing, nil
}

func LoadLocalActivationTiming(ctx context.Context, store *storage.Store) (LocalActivationTiming, bool, error) {
	if store == nil || store.ReportExports == nil {
		return LocalActivationTiming{}, false, errors.New("report export storage is unavailable")
	}
	export, found, err := store.ReportExports.Get(ctx, localActivationTimingID)
	if err != nil || !found {
		return LocalActivationTiming{}, found, err
	}
	if export.Origin != LocalActivationTimingOrigin || export.Type != "activation-timing" || export.Format != "json" {
		return LocalActivationTiming{}, false, errors.New("local activation timing has an invalid storage boundary")
	}
	var timing LocalActivationTiming
	if err := json.Unmarshal([]byte(export.Content), &timing); err != nil {
		return LocalActivationTiming{}, false, err
	}
	if timing.ContractVersion != LocalActivationTimingContract || timing.StartedAt.IsZero() || timing.CompletedAt.IsZero() || timing.CompletedAt.Before(timing.StartedAt) || timing.TargetSeconds <= 0 || timing.ElapsedMilliseconds < 0 {
		return LocalActivationTiming{}, false, errors.New("local activation timing contract is invalid")
	}
	return timing, true, nil
}
