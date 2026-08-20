package connector

import (
	"context"
	"fmt"
	"strconv"

	"monicheck/internal/model"
)

type Snapshot struct {
	Resources     []model.Resource
	References    []model.Resource
	Relationships []model.Relationship
	Diagnostics   []model.Diagnostic
	Partial       bool
}

type Connector interface {
	ID() string
	Name() string
	Sync(ctx context.Context) (Snapshot, error)
}

func detailDiscoveryDiagnostic(id string, name string, system string, endpoint string, total int, failed int) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := fmt.Sprintf("%s discovery completed for %d items", name, total)
	if failed > 0 {
		status = model.ExecutionStatusWarning
		message = fmt.Sprintf("%s discovery failed for %d of %d items; remaining discovery continued", name, failed, total)
	}
	return model.Diagnostic{
		ID:            id,
		Name:          name,
		Status:        status,
		Message:       message,
		ResourceCount: total - failed,
		Metadata: map[string]string{
			"endpoint":        endpoint,
			"optional":        "true",
			"system":          system,
			"item_count":      strconv.Itoa(total),
			"succeeded_count": strconv.Itoa(total - failed),
			"failed_count":    strconv.Itoa(failed),
		},
	}
}

func addDetailDiscoveryWorkerCount(diagnostic *model.Diagnostic, workerCount int) {
	if diagnostic == nil {
		return
	}
	if diagnostic.Metadata == nil {
		diagnostic.Metadata = map[string]string{}
	}
	diagnostic.Metadata["worker_count"] = strconv.Itoa(workerCount)
}
