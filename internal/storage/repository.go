package storage

import (
	"context"
	"time"

	"monicheck/internal/model"
)

type ResourceRepository interface {
	Upsert(ctx context.Context, resource model.Resource) error
	Get(ctx context.Context, id string) (model.Resource, bool, error)
	List(ctx context.Context, filter ResourceFilter) ([]model.Resource, error)
}

type RelationshipRepository interface {
	Upsert(ctx context.Context, relationship model.Relationship) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]model.Relationship, error)
	ListByResource(ctx context.Context, resourceID string) ([]model.Relationship, error)
}

type FindingRepository interface {
	ReplaceOpenByAnalyzer(ctx context.Context, analyzerID string, findings []model.Finding) error
	Get(ctx context.Context, id string) (model.Finding, bool, error)
	List(ctx context.Context, filter FindingFilter) ([]model.Finding, error)
	UpdateStatus(ctx context.Context, id string, status model.FindingStatus) (model.Finding, bool, error)
	Update(ctx context.Context, finding model.Finding) (model.Finding, bool, error)
}

type ExecutionRepository interface {
	Save(ctx context.Context, result model.ExecutionResult) error
	Get(ctx context.Context, id string) (model.ExecutionResult, bool, error)
	List(ctx context.Context) ([]model.ExecutionResult, error)
}

type RuleAuditRepository interface {
	Save(ctx context.Context, event model.RuleAuditEvent) error
	List(ctx context.Context) ([]model.RuleAuditEvent, error)
}

type APIAccessAuditRepository interface {
	Save(ctx context.Context, event model.APIAccessAuditEvent) error
	List(ctx context.Context, filter APIAccessAuditFilter) ([]model.APIAccessAuditEvent, error)
}

type ConnectorAuditRepository interface {
	Save(ctx context.Context, event model.ConnectorAuditEvent) error
	List(ctx context.Context) ([]model.ConnectorAuditEvent, error)
}

type PluginAuditRepository interface {
	Save(ctx context.Context, event model.PluginAuditEvent) error
	List(ctx context.Context) ([]model.PluginAuditEvent, error)
}

type ReportExportRepository interface {
	Save(ctx context.Context, export model.ReportExport) error
	Get(ctx context.Context, id string) (model.ReportExport, bool, error)
	List(ctx context.Context) ([]model.ReportExport, error)
}

type FindingWorkflowRepository interface {
	Save(ctx context.Context, event model.FindingWorkflowEvent) error
	List(ctx context.Context, findingID string) ([]model.FindingWorkflowEvent, error)
}

type WaiverRepository interface {
	Save(ctx context.Context, waiver model.Waiver) error
	Get(ctx context.Context, id string) (model.Waiver, bool, error)
	List(ctx context.Context) ([]model.Waiver, error)
	Revoke(ctx context.Context, id string, revokedAt time.Time, revokedBy string, reason string) (model.Waiver, bool, error)
}

type FindingOccurrenceRepository interface {
	ReplaceByAnalyzer(ctx context.Context, analyzerID string, records []model.FindingOccurrence) error
	Get(ctx context.Context, findingID string) (model.FindingOccurrence, bool, error)
	List(ctx context.Context, analyzerID string) ([]model.FindingOccurrence, error)
}

type CoverageExpectationRepository interface {
	Save(ctx context.Context, expectation model.CoverageExpectation) error
	Get(ctx context.Context, id string) (model.CoverageExpectation, bool, error)
	List(ctx context.Context) ([]model.CoverageExpectation, error)
}

type CoverageExceptionRepository interface {
	Save(ctx context.Context, exception model.CoverageException) error
	Get(ctx context.Context, id string) (model.CoverageException, bool, error)
	List(ctx context.Context) ([]model.CoverageException, error)
	Revoke(ctx context.Context, id string, revokedAt time.Time, revokedBy string, reason string) (model.CoverageException, bool, error)
}

type ResourceFilter struct {
	Type      model.ResourceType
	Team      string
	Project   string
	Namespace string
	Cluster   string
}

type FindingFilter struct {
	Severity   model.Severity
	Category   model.FindingCategory
	Status     model.FindingStatus
	AnalyzerID string
	RuleID     string
}

type APIAccessAuditFilter struct {
	Method        string
	PathContains  string
	StatusCode    int
	Authenticated *bool
}

type Store struct {
	Resources            ResourceRepository
	Relationships        RelationshipRepository
	Findings             FindingRepository
	Executions           ExecutionRepository
	RuleAudit            RuleAuditRepository
	APIAudit             APIAccessAuditRepository
	ConnectorAudit       ConnectorAuditRepository
	PluginAudit          PluginAuditRepository
	ReportExports        ReportExportRepository
	FindingWorkflow      FindingWorkflowRepository
	Waivers              WaiverRepository
	FindingOccurrences   FindingOccurrenceRepository
	CoverageExpectations CoverageExpectationRepository
	CoverageExceptions   CoverageExceptionRepository
	runBatch             func(context.Context, func() error) error
}

// WithinBatch coalesces durable writes when the backing store supports it.
// Memory stores execute the operation directly.
func (s *Store) WithinBatch(ctx context.Context, operation func() error) error {
	if operation == nil {
		return nil
	}
	if s == nil || s.runBatch == nil {
		return operation()
	}
	return s.runBatch(ctx, operation)
}
