package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"monicheck/internal/model"
)

type fileStore struct {
	path                 string
	mu                   sync.Mutex
	batchMu              sync.Mutex
	batchActive          bool
	batchDirty           bool
	resources            *MemoryResourceRepository
	relationships        *MemoryRelationshipRepository
	findings             *MemoryFindingRepository
	executions           *MemoryExecutionRepository
	ruleAudit            *MemoryRuleAuditRepository
	apiAudit             *MemoryAPIAccessAuditRepository
	connectorAudit       *MemoryConnectorAuditRepository
	pluginAudit          *MemoryPluginAuditRepository
	reportExports        *MemoryReportExportRepository
	findingWorkflow      *MemoryFindingWorkflowRepository
	waivers              *MemoryWaiverRepository
	findingOccurrences   *MemoryFindingOccurrenceRepository
	coverageExpectations *MemoryCoverageExpectationRepository
	coverageExceptions   *MemoryCoverageExceptionRepository
}

type fileStoreSnapshot struct {
	Resources            []model.Resource             `json:"resources"`
	Relationships        []model.Relationship         `json:"relationships"`
	Findings             []model.Finding              `json:"findings"`
	Executions           []model.ExecutionResult      `json:"executions"`
	RuleAudit            []model.RuleAuditEvent       `json:"rule_audit,omitempty"`
	FindingWorkflow      []model.FindingWorkflowEvent `json:"finding_workflow,omitempty"`
	Waivers              []model.Waiver               `json:"waivers,omitempty"`
	FindingOccurrences   []model.FindingOccurrence    `json:"finding_occurrences,omitempty"`
	CoverageExpectations []model.CoverageExpectation  `json:"coverage_expectations,omitempty"`
	CoverageExceptions   []model.CoverageException    `json:"coverage_exceptions,omitempty"`
	APIAudit             []model.APIAccessAuditEvent  `json:"api_audit,omitempty"`
	ConnectorAudit       []model.ConnectorAuditEvent  `json:"connector_audit,omitempty"`
	PluginAudit          []model.PluginAuditEvent     `json:"plugin_audit,omitempty"`
	ReportExports        []model.ReportExport         `json:"report_exports,omitempty"`
}

func NewFileStore(path string) (*Store, error) {
	return NewFileStoreWithAPIAuditRetention(path, 1000)
}

func NewFileStoreWithAPIAuditRetention(path string, apiAuditRetention int) (*Store, error) {
	coverageExpectations := NewMemoryCoverageExpectationRepository()
	_ = coverageExpectations.Save(context.Background(), initializedBuiltinCoverageExpectation())
	fs := &fileStore{
		path:                 path,
		resources:            NewMemoryResourceRepository(),
		relationships:        NewMemoryRelationshipRepository(),
		findings:             NewMemoryFindingRepository(),
		executions:           NewMemoryExecutionRepository(),
		ruleAudit:            NewMemoryRuleAuditRepository(),
		apiAudit:             NewMemoryAPIAccessAuditRepositoryWithLimit(apiAuditRetention),
		connectorAudit:       NewMemoryConnectorAuditRepository(),
		pluginAudit:          NewMemoryPluginAuditRepository(),
		reportExports:        NewMemoryReportExportRepository(),
		findingWorkflow:      NewMemoryFindingWorkflowRepository(),
		waivers:              NewMemoryWaiverRepository(),
		findingOccurrences:   NewMemoryFindingOccurrenceRepository(),
		coverageExpectations: coverageExpectations,
		coverageExceptions:   NewMemoryCoverageExceptionRepository(),
	}
	if err := fs.load(context.Background()); err != nil {
		return nil, err
	}
	return &Store{
		Resources:            &fileResourceRepository{inner: fs.resources, persist: fs.persist},
		Relationships:        &fileRelationshipRepository{inner: fs.relationships, persist: fs.persist},
		Findings:             &fileFindingRepository{inner: fs.findings, persist: fs.persist},
		Executions:           &fileExecutionRepository{inner: fs.executions, persist: fs.persist},
		RuleAudit:            &fileRuleAuditRepository{inner: fs.ruleAudit, persist: fs.persist},
		APIAudit:             &fileAPIAccessAuditRepository{inner: fs.apiAudit, persist: fs.persist},
		ConnectorAudit:       &fileConnectorAuditRepository{inner: fs.connectorAudit, persist: fs.persist},
		PluginAudit:          &filePluginAuditRepository{inner: fs.pluginAudit, persist: fs.persist},
		ReportExports:        &fileReportExportRepository{inner: fs.reportExports, persist: fs.persist},
		FindingWorkflow:      &fileFindingWorkflowRepository{inner: fs.findingWorkflow, persist: fs.persist},
		Waivers:              &fileWaiverRepository{inner: fs.waivers, persist: fs.persist},
		FindingOccurrences:   &fileFindingOccurrenceRepository{inner: fs.findingOccurrences, persist: fs.persist},
		CoverageExpectations: &fileCoverageExpectationRepository{inner: fs.coverageExpectations, persist: fs.persist},
		CoverageExceptions:   &fileCoverageExceptionRepository{inner: fs.coverageExceptions, persist: fs.persist},
		runBatch:             fs.withinBatch,
	}, nil
}

func (s *fileStore) load(ctx context.Context) error {
	content, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(content) == 0 {
		return nil
	}

	var snapshot fileStoreSnapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return err
	}
	for _, resource := range snapshot.Resources {
		s.resources.resources[resource.ID] = resource
	}
	for _, relationship := range snapshot.Relationships {
		if err := s.relationships.Upsert(ctx, relationship); err != nil {
			return err
		}
	}
	for _, finding := range snapshot.Findings {
		if finding.Category == "" {
			finding.Category = model.DefaultFindingCategory(finding.Type, finding.Resource.Type)
		}
		s.findings.findings[finding.ID] = finding
	}
	for _, execution := range snapshot.Executions {
		if err := s.executions.Save(ctx, execution); err != nil {
			return err
		}
	}
	for _, event := range snapshot.RuleAudit {
		if err := s.ruleAudit.Save(ctx, event); err != nil {
			return err
		}
	}
	for _, event := range snapshot.FindingWorkflow {
		if err := s.findingWorkflow.Save(ctx, event); err != nil {
			return err
		}
	}
	for _, waiver := range snapshot.Waivers {
		if err := s.waivers.Save(ctx, waiver); err != nil {
			return err
		}
	}
	for _, record := range snapshot.FindingOccurrences {
		s.findingOccurrences.records[record.FindingID] = record
	}
	for _, expectation := range snapshot.CoverageExpectations {
		s.coverageExpectations.expectations[expectation.ID] = expectation
	}
	for _, exception := range snapshot.CoverageExceptions {
		s.coverageExceptions.exceptions[exception.ID] = exception
	}
	for _, event := range snapshot.APIAudit {
		if err := s.apiAudit.Save(ctx, event); err != nil {
			return err
		}
	}
	for _, event := range snapshot.ConnectorAudit {
		if err := s.connectorAudit.Save(ctx, event); err != nil {
			return err
		}
	}
	for _, event := range snapshot.PluginAudit {
		if err := s.pluginAudit.Save(ctx, event); err != nil {
			return err
		}
	}
	for _, export := range snapshot.ReportExports {
		if err := s.reportExports.Save(ctx, export); err != nil {
			return err
		}
	}
	return nil
}

func (s *fileStore) persist() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batchActive {
		s.batchDirty = true
		return nil
	}
	return s.persistLocked()
}

func (s *fileStore) withinBatch(ctx context.Context, operation func() error) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	s.mu.Lock()
	s.batchActive = true
	s.batchDirty = false
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		dirty := s.batchDirty
		s.batchActive = false
		s.batchDirty = false
		var persistErr error
		if dirty {
			persistErr = s.persistLocked()
		}
		s.mu.Unlock()
		returnErr = errors.Join(returnErr, persistErr)
	}()

	return operation()
}

func (s *fileStore) persistLocked() error {

	ctx := context.Background()
	resources, err := s.resources.List(ctx, ResourceFilter{})
	if err != nil {
		return err
	}
	relationships, err := s.relationships.List(ctx)
	if err != nil {
		return err
	}
	findings, err := s.findings.List(ctx, FindingFilter{})
	if err != nil {
		return err
	}
	executions, err := s.executions.List(ctx)
	if err != nil {
		return err
	}
	ruleAudit, err := s.ruleAudit.List(ctx)
	if err != nil {
		return err
	}
	findingWorkflow, err := s.findingWorkflow.List(ctx, "")
	if err != nil {
		return err
	}
	waivers, err := s.waivers.List(ctx)
	if err != nil {
		return err
	}
	findingOccurrences, err := s.findingOccurrences.List(ctx, "")
	if err != nil {
		return err
	}
	coverageExpectations, err := s.coverageExpectations.List(ctx)
	if err != nil {
		return err
	}
	coverageExceptions, err := s.coverageExceptions.List(ctx)
	if err != nil {
		return err
	}
	apiAudit, err := s.apiAudit.List(ctx, APIAccessAuditFilter{})
	if err != nil {
		return err
	}
	connectorAudit, err := s.connectorAudit.List(ctx)
	if err != nil {
		return err
	}
	pluginAudit, err := s.pluginAudit.List(ctx)
	if err != nil {
		return err
	}
	reportExports, err := s.reportExports.List(ctx)
	if err != nil {
		return err
	}

	snapshot := fileStoreSnapshot{
		Resources:            resources,
		Relationships:        relationships,
		Findings:             findings,
		Executions:           executions,
		RuleAudit:            ruleAudit,
		FindingWorkflow:      findingWorkflow,
		Waivers:              waivers,
		FindingOccurrences:   findingOccurrences,
		CoverageExpectations: coverageExpectations,
		CoverageExceptions:   coverageExceptions,
		APIAudit:             apiAudit,
		ConnectorAudit:       connectorAudit,
		PluginAudit:          pluginAudit,
		ReportExports:        reportExports,
	}
	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}

type fileFindingOccurrenceRepository struct {
	inner   *MemoryFindingOccurrenceRepository
	persist func() error
}

type fileCoverageExpectationRepository struct {
	inner   *MemoryCoverageExpectationRepository
	persist func() error
}

func (r *fileCoverageExpectationRepository) Save(ctx context.Context, expectation model.CoverageExpectation) error {
	if err := r.inner.Save(ctx, expectation); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileCoverageExpectationRepository) Get(ctx context.Context, id string) (model.CoverageExpectation, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileCoverageExpectationRepository) List(ctx context.Context) ([]model.CoverageExpectation, error) {
	return r.inner.List(ctx)
}

type fileCoverageExceptionRepository struct {
	inner   *MemoryCoverageExceptionRepository
	persist func() error
}

func (r *fileCoverageExceptionRepository) Save(ctx context.Context, exception model.CoverageException) error {
	if err := r.inner.Save(ctx, exception); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileCoverageExceptionRepository) Get(ctx context.Context, id string) (model.CoverageException, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileCoverageExceptionRepository) List(ctx context.Context) ([]model.CoverageException, error) {
	return r.inner.List(ctx)
}

func (r *fileCoverageExceptionRepository) Revoke(ctx context.Context, id string, revokedAt time.Time, revokedBy string, reason string) (model.CoverageException, bool, error) {
	exception, found, err := r.inner.Revoke(ctx, id, revokedAt, revokedBy, reason)
	if err != nil || !found {
		return exception, found, err
	}
	if err := r.persist(); err != nil {
		return model.CoverageException{}, false, err
	}
	return exception, true, nil
}

func (r *fileFindingOccurrenceRepository) ReplaceByAnalyzer(ctx context.Context, analyzerID string, records []model.FindingOccurrence) error {
	if err := r.inner.ReplaceByAnalyzer(ctx, analyzerID, records); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileFindingOccurrenceRepository) Get(ctx context.Context, findingID string) (model.FindingOccurrence, bool, error) {
	return r.inner.Get(ctx, findingID)
}

func (r *fileFindingOccurrenceRepository) List(ctx context.Context, analyzerID string) ([]model.FindingOccurrence, error) {
	return r.inner.List(ctx, analyzerID)
}

type fileWaiverRepository struct {
	inner   *MemoryWaiverRepository
	persist func() error
}

func (r *fileWaiverRepository) Save(ctx context.Context, waiver model.Waiver) error {
	if err := r.inner.Save(ctx, waiver); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileWaiverRepository) Get(ctx context.Context, id string) (model.Waiver, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileWaiverRepository) List(ctx context.Context) ([]model.Waiver, error) {
	return r.inner.List(ctx)
}

func (r *fileWaiverRepository) Revoke(ctx context.Context, id string, revokedAt time.Time, revokedBy string, reason string) (model.Waiver, bool, error) {
	waiver, ok, err := r.inner.Revoke(ctx, id, revokedAt, revokedBy, reason)
	if err != nil || !ok {
		return waiver, ok, err
	}
	if err := r.persist(); err != nil {
		return model.Waiver{}, false, err
	}
	return waiver, true, nil
}

type fileResourceRepository struct {
	inner   *MemoryResourceRepository
	persist func() error
}

func (r *fileResourceRepository) Upsert(ctx context.Context, resource model.Resource) error {
	if err := r.inner.Upsert(ctx, resource); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileResourceRepository) Get(ctx context.Context, id string) (model.Resource, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileResourceRepository) List(ctx context.Context, filter ResourceFilter) ([]model.Resource, error) {
	return r.inner.List(ctx, filter)
}

type fileRelationshipRepository struct {
	inner   *MemoryRelationshipRepository
	persist func() error
}

func (r *fileRelationshipRepository) Upsert(ctx context.Context, relationship model.Relationship) error {
	if err := r.inner.Upsert(ctx, relationship); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileRelationshipRepository) Delete(ctx context.Context, id string) error {
	if err := r.inner.Delete(ctx, id); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileRelationshipRepository) List(ctx context.Context) ([]model.Relationship, error) {
	return r.inner.List(ctx)
}

func (r *fileRelationshipRepository) ListByResource(ctx context.Context, resourceID string) ([]model.Relationship, error) {
	return r.inner.ListByResource(ctx, resourceID)
}

type fileFindingRepository struct {
	inner   *MemoryFindingRepository
	persist func() error
}

func (r *fileFindingRepository) ReplaceOpenByAnalyzer(ctx context.Context, analyzerID string, findings []model.Finding) error {
	if err := r.inner.ReplaceOpenByAnalyzer(ctx, analyzerID, findings); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileFindingRepository) Get(ctx context.Context, id string) (model.Finding, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileFindingRepository) List(ctx context.Context, filter FindingFilter) ([]model.Finding, error) {
	return r.inner.List(ctx, filter)
}

func (r *fileFindingRepository) UpdateStatus(ctx context.Context, id string, status model.FindingStatus) (model.Finding, bool, error) {
	finding, ok, err := r.inner.UpdateStatus(ctx, id, status)
	if err != nil || !ok {
		return finding, ok, err
	}
	return finding, ok, r.persist()
}

func (r *fileFindingRepository) Update(ctx context.Context, finding model.Finding) (model.Finding, bool, error) {
	updated, ok, err := r.inner.Update(ctx, finding)
	if err != nil || !ok {
		return updated, ok, err
	}
	return updated, ok, r.persist()
}

type fileExecutionRepository struct {
	inner   *MemoryExecutionRepository
	persist func() error
}

func (r *fileExecutionRepository) Save(ctx context.Context, result model.ExecutionResult) error {
	if err := r.inner.Save(ctx, result); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileExecutionRepository) Get(ctx context.Context, id string) (model.ExecutionResult, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileExecutionRepository) List(ctx context.Context) ([]model.ExecutionResult, error) {
	return r.inner.List(ctx)
}

type fileRuleAuditRepository struct {
	inner   *MemoryRuleAuditRepository
	persist func() error
}

func (r *fileRuleAuditRepository) Save(ctx context.Context, event model.RuleAuditEvent) error {
	if err := r.inner.Save(ctx, event); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileRuleAuditRepository) List(ctx context.Context) ([]model.RuleAuditEvent, error) {
	return r.inner.List(ctx)
}

type fileFindingWorkflowRepository struct {
	inner   *MemoryFindingWorkflowRepository
	persist func() error
}

func (r *fileFindingWorkflowRepository) Save(ctx context.Context, event model.FindingWorkflowEvent) error {
	if err := r.inner.Save(ctx, event); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileFindingWorkflowRepository) List(ctx context.Context, findingID string) ([]model.FindingWorkflowEvent, error) {
	return r.inner.List(ctx, findingID)
}

type fileAPIAccessAuditRepository struct {
	inner   *MemoryAPIAccessAuditRepository
	persist func() error
}

func (r *fileAPIAccessAuditRepository) Save(ctx context.Context, event model.APIAccessAuditEvent) error {
	if err := r.inner.Save(ctx, event); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileAPIAccessAuditRepository) List(ctx context.Context, filter APIAccessAuditFilter) ([]model.APIAccessAuditEvent, error) {
	return r.inner.List(ctx, filter)
}

type fileConnectorAuditRepository struct {
	inner   *MemoryConnectorAuditRepository
	persist func() error
}

func (r *fileConnectorAuditRepository) Save(ctx context.Context, event model.ConnectorAuditEvent) error {
	if err := r.inner.Save(ctx, event); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileConnectorAuditRepository) List(ctx context.Context) ([]model.ConnectorAuditEvent, error) {
	return r.inner.List(ctx)
}

type filePluginAuditRepository struct {
	inner   *MemoryPluginAuditRepository
	persist func() error
}

func (r *filePluginAuditRepository) Save(ctx context.Context, event model.PluginAuditEvent) error {
	if err := r.inner.Save(ctx, event); err != nil {
		return err
	}
	return r.persist()
}

func (r *filePluginAuditRepository) List(ctx context.Context) ([]model.PluginAuditEvent, error) {
	return r.inner.List(ctx)
}

type fileReportExportRepository struct {
	inner   *MemoryReportExportRepository
	persist func() error
}

func (r *fileReportExportRepository) Save(ctx context.Context, export model.ReportExport) error {
	if err := r.inner.Save(ctx, export); err != nil {
		return err
	}
	return r.persist()
}

func (r *fileReportExportRepository) Get(ctx context.Context, id string) (model.ReportExport, bool, error) {
	return r.inner.Get(ctx, id)
}

func (r *fileReportExportRepository) List(ctx context.Context) ([]model.ReportExport, error) {
	return r.inner.List(ctx)
}
