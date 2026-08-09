package analyzer

import (
	"context"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

type Context struct {
	Resources            storage.ResourceRepository
	Findings             storage.FindingRepository
	ReportExports        storage.ReportExportRepository
	FindingWorkflow      storage.FindingWorkflowRepository
	CoverageExpectations storage.CoverageExpectationRepository
	CoverageExceptions   storage.CoverageExceptionRepository
	Graph                *graph.Graph
	Config               map[string]any
}

type Analyzer interface {
	ID() string
	Name() string
	Version() string
	InputTypes() []model.ResourceType
	Execute(ctx context.Context, analysis Context) ([]model.Finding, error)
}
