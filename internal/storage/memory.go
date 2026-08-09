package storage

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"monicheck/internal/model"
)

func NewMemoryStore() *Store {
	return NewMemoryStoreWithAPIAuditRetention(1000)
}

func NewMemoryStoreWithAPIAuditRetention(apiAuditRetention int) *Store {
	expectations := NewMemoryCoverageExpectationRepository()
	_ = expectations.Save(context.Background(), initializedBuiltinCoverageExpectation())
	return &Store{
		Resources:            NewMemoryResourceRepository(),
		Relationships:        NewMemoryRelationshipRepository(),
		Findings:             NewMemoryFindingRepository(),
		Executions:           NewMemoryExecutionRepository(),
		RuleAudit:            NewMemoryRuleAuditRepository(),
		APIAudit:             NewMemoryAPIAccessAuditRepositoryWithLimit(apiAuditRetention),
		ConnectorAudit:       NewMemoryConnectorAuditRepository(),
		PluginAudit:          NewMemoryPluginAuditRepository(),
		ReportExports:        NewMemoryReportExportRepository(),
		FindingWorkflow:      NewMemoryFindingWorkflowRepository(),
		Waivers:              NewMemoryWaiverRepository(),
		FindingOccurrences:   NewMemoryFindingOccurrenceRepository(),
		CoverageExpectations: expectations,
		CoverageExceptions:   NewMemoryCoverageExceptionRepository(),
	}
}

func initializedBuiltinCoverageExpectation() model.CoverageExpectation {
	expectation := model.BuiltinServiceCoverageExpectation()
	now := time.Now().UTC()
	expectation.CreatedAt = now
	expectation.UpdatedAt = now
	return expectation
}

type MemoryResourceRepository struct {
	mu        sync.RWMutex
	resources map[string]model.Resource
}

func NewMemoryResourceRepository() *MemoryResourceRepository {
	return &MemoryResourceRepository{resources: make(map[string]model.Resource)}
}

func (r *MemoryResourceRepository) Upsert(ctx context.Context, resource model.Resource) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	resource = cloneResource(resource)
	now := time.Now().UTC()
	if existing, ok := r.resources[resource.ID]; ok && resource.CreatedAt.IsZero() {
		resource.CreatedAt = existing.CreatedAt
	}
	if resource.CreatedAt.IsZero() {
		resource.CreatedAt = now
	}
	resource.UpdatedAt = now
	r.resources[resource.ID] = resource
	return nil
}

func (r *MemoryResourceRepository) Get(ctx context.Context, id string) (model.Resource, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resource, ok := r.resources[id]
	return cloneResource(resource), ok, nil
}

func (r *MemoryResourceRepository) List(ctx context.Context, filter ResourceFilter) ([]model.Resource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resources := make([]model.Resource, 0, len(r.resources))
	for _, resource := range r.resources {
		if filter.Type != "" && resource.Type != filter.Type {
			continue
		}
		if !resourceMatchesTenantFilter(resource, filter) {
			continue
		}
		resources = append(resources, cloneResource(resource))
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ID < resources[j].ID
	})
	return resources, nil
}

func resourceMatchesTenantFilter(resource model.Resource, filter ResourceFilter) bool {
	if filter.Team != "" && !resourceTenantValueMatches(resource, "team", filter.Team) {
		return false
	}
	if filter.Project != "" && !resourceTenantValueMatches(resource, "project", filter.Project) {
		return false
	}
	if filter.Namespace != "" && !resourceTenantValueMatches(resource, "namespace", filter.Namespace) {
		return false
	}
	if filter.Cluster != "" && !resourceTenantValueMatches(resource, "cluster", filter.Cluster) {
		return false
	}
	return true
}

func resourceTenantValueMatches(resource model.Resource, dimension string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	for _, value := range resourceTenantValues(resource, dimension) {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func resourceTenantValues(resource model.Resource, dimension string) []string {
	keys := tenantDimensionKeys(dimension)
	values := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		if value := strings.TrimSpace(resource.Labels[key]); value != "" {
			values = append(values, value)
		}
		if value := strings.TrimSpace(resource.Metadata[key]); value != "" {
			values = append(values, value)
		}
	}
	if dimension == "cluster" && strings.TrimSpace(resource.Source.Cluster) != "" {
		values = append(values, resource.Source.Cluster)
	}
	return values
}

func tenantDimensionKeys(dimension string) []string {
	switch dimension {
	case "team":
		return []string{"team", "owner_team", "responsible_team"}
	case "project":
		return []string{"project", "project_id", "project_name"}
	case "namespace":
		return []string{"namespace", "kubernetes_namespace", "k8s_namespace"}
	case "cluster":
		return []string{"cluster", "cluster_name"}
	default:
		return []string{dimension}
	}
}

type MemoryRelationshipRepository struct {
	mu            sync.RWMutex
	relationships map[string]model.Relationship
}

func NewMemoryRelationshipRepository() *MemoryRelationshipRepository {
	return &MemoryRelationshipRepository{relationships: make(map[string]model.Relationship)}
}

func (r *MemoryRelationshipRepository) Upsert(ctx context.Context, relationship model.Relationship) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if relationship.CreatedAt.IsZero() {
		relationship.CreatedAt = time.Now().UTC()
	}
	r.relationships[relationship.ID] = cloneRelationship(relationship)
	return nil
}

func (r *MemoryRelationshipRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.relationships, id)
	return nil
}

func (r *MemoryRelationshipRepository) List(ctx context.Context) ([]model.Relationship, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	relationships := make([]model.Relationship, 0, len(r.relationships))
	for _, relationship := range r.relationships {
		relationships = append(relationships, cloneRelationship(relationship))
	}
	sort.Slice(relationships, func(i, j int) bool {
		return relationships[i].ID < relationships[j].ID
	})
	return relationships, nil
}

func (r *MemoryRelationshipRepository) ListByResource(ctx context.Context, resourceID string) ([]model.Relationship, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	relationships := make([]model.Relationship, 0)
	for _, relationship := range r.relationships {
		if relationship.FromID == resourceID || relationship.ToID == resourceID {
			relationships = append(relationships, cloneRelationship(relationship))
		}
	}
	sort.Slice(relationships, func(i, j int) bool {
		return relationships[i].ID < relationships[j].ID
	})
	return relationships, nil
}

type MemoryFindingRepository struct {
	mu       sync.RWMutex
	findings map[string]model.Finding
}

type MemoryFindingOccurrenceRepository struct {
	mu      sync.RWMutex
	records map[string]model.FindingOccurrence
}

type MemoryCoverageExpectationRepository struct {
	mu           sync.RWMutex
	expectations map[string]model.CoverageExpectation
}

func NewMemoryCoverageExpectationRepository() *MemoryCoverageExpectationRepository {
	return &MemoryCoverageExpectationRepository{expectations: make(map[string]model.CoverageExpectation)}
}

func (r *MemoryCoverageExpectationRepository) Save(_ context.Context, expectation model.CoverageExpectation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expectations[expectation.ID] = expectation
	return nil
}

func (r *MemoryCoverageExpectationRepository) Get(_ context.Context, id string) (model.CoverageExpectation, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	expectation, ok := r.expectations[id]
	return expectation, ok, nil
}

func (r *MemoryCoverageExpectationRepository) List(_ context.Context) ([]model.CoverageExpectation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]model.CoverageExpectation, 0, len(r.expectations))
	for _, expectation := range r.expectations {
		result = append(result, expectation)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

type MemoryCoverageExceptionRepository struct {
	mu         sync.RWMutex
	exceptions map[string]model.CoverageException
}

func NewMemoryCoverageExceptionRepository() *MemoryCoverageExceptionRepository {
	return &MemoryCoverageExceptionRepository{exceptions: make(map[string]model.CoverageException)}
}

func (r *MemoryCoverageExceptionRepository) Save(_ context.Context, exception model.CoverageException) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exceptions[exception.ID] = exception
	return nil
}

func (r *MemoryCoverageExceptionRepository) Get(_ context.Context, id string) (model.CoverageException, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	exception, ok := r.exceptions[id]
	return exception, ok, nil
}

func (r *MemoryCoverageExceptionRepository) List(_ context.Context) ([]model.CoverageException, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]model.CoverageException, 0, len(r.exceptions))
	for _, exception := range r.exceptions {
		result = append(result, exception)
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.After(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}

func (r *MemoryCoverageExceptionRepository) Revoke(_ context.Context, id string, revokedAt time.Time, revokedBy string, reason string) (model.CoverageException, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	exception, ok := r.exceptions[id]
	if !ok {
		return model.CoverageException{}, false, nil
	}
	revokedAt = revokedAt.UTC()
	exception.RevokedAt = &revokedAt
	exception.RevokedBy = revokedBy
	exception.RevocationReason = reason
	r.exceptions[id] = exception
	return exception, true, nil
}

func NewMemoryFindingOccurrenceRepository() *MemoryFindingOccurrenceRepository {
	return &MemoryFindingOccurrenceRepository{records: make(map[string]model.FindingOccurrence)}
}

func (r *MemoryFindingOccurrenceRepository) ReplaceByAnalyzer(_ context.Context, analyzerID string, records []model.FindingOccurrence) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, record := range r.records {
		if record.AnalyzerID == analyzerID {
			delete(r.records, id)
		}
	}
	for _, record := range records {
		r.records[record.FindingID] = record
	}
	return nil
}

func (r *MemoryFindingOccurrenceRepository) Get(_ context.Context, findingID string) (model.FindingOccurrence, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[findingID]
	return record, ok, nil
}

func (r *MemoryFindingOccurrenceRepository) List(_ context.Context, analyzerID string) ([]model.FindingOccurrence, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]model.FindingOccurrence, 0, len(r.records))
	for _, record := range r.records {
		if analyzerID == "" || record.AnalyzerID == analyzerID {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FindingID < result[j].FindingID })
	return result, nil
}

func NewMemoryFindingRepository() *MemoryFindingRepository {
	return &MemoryFindingRepository{findings: make(map[string]model.Finding)}
}

func (r *MemoryFindingRepository) ReplaceOpenByAnalyzer(ctx context.Context, analyzerID string, findings []model.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, finding := range r.findings {
		if finding.Metadata["analyzer_id"] == analyzerID && (finding.Status == model.FindingStatusOpen || finding.Status == model.FindingStatusWaived) {
			delete(r.findings, id)
		}
	}
	now := time.Now().UTC()
	for _, finding := range findings {
		finding = cloneFinding(finding)
		if finding.CreatedAt.IsZero() {
			finding.CreatedAt = now
		}
		finding.UpdatedAt = now
		if finding.Status == "" {
			finding.Status = model.FindingStatusOpen
		}
		if finding.Category == "" {
			finding.Category = model.DefaultFindingCategory(finding.Type, finding.Resource.Type)
		}
		r.findings[finding.ID] = finding
	}
	return nil
}

func (r *MemoryFindingRepository) Get(ctx context.Context, id string) (model.Finding, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	finding, ok := r.findings[id]
	return cloneFinding(finding), ok, nil
}

func (r *MemoryFindingRepository) List(ctx context.Context, filter FindingFilter) ([]model.Finding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	findings := make([]model.Finding, 0, len(r.findings))
	for _, finding := range r.findings {
		if filter.Severity != "" && finding.Severity != filter.Severity {
			continue
		}
		if filter.Category != "" && finding.Category != filter.Category {
			continue
		}
		if filter.Status != "" && finding.Status != filter.Status {
			continue
		}
		if filter.AnalyzerID != "" && finding.Metadata["analyzer_id"] != filter.AnalyzerID {
			continue
		}
		if filter.RuleID != "" && finding.Metadata["rule_id"] != filter.RuleID {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings, nil
}

func (r *MemoryFindingRepository) UpdateStatus(ctx context.Context, id string, status model.FindingStatus) (model.Finding, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	finding, ok := r.findings[id]
	if !ok {
		return model.Finding{}, false, nil
	}
	finding.Status = status
	finding.UpdatedAt = time.Now().UTC()
	r.findings[id] = finding
	return cloneFinding(finding), true, nil
}

func (r *MemoryFindingRepository) Update(ctx context.Context, finding model.Finding) (model.Finding, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.findings[finding.ID]; !ok {
		return model.Finding{}, false, nil
	}
	finding = cloneFinding(finding)
	finding.UpdatedAt = time.Now().UTC()
	r.findings[finding.ID] = finding
	return cloneFinding(finding), true, nil
}

func cloneResource(resource model.Resource) model.Resource {
	resource.Metadata = cloneStringMap(resource.Metadata)
	resource.Labels = cloneStringMap(resource.Labels)
	return resource
}

func cloneRelationship(relationship model.Relationship) model.Relationship {
	relationship.Metadata = cloneStringMap(relationship.Metadata)
	return relationship
}

func cloneFinding(finding model.Finding) model.Finding {
	finding.Evidence = append([]string(nil), finding.Evidence...)
	finding.Metadata = cloneStringMap(finding.Metadata)
	if finding.RiskScore != nil {
		score := *finding.RiskScore
		score.Components = append([]model.FindingRiskComponent(nil), score.Components...)
		score.ConfidenceComponents = append([]model.FindingRiskComponent(nil), score.ConfidenceComponents...)
		finding.RiskScore = &score
	}
	if finding.Occurrence != nil {
		occurrence := *finding.Occurrence
		finding.Occurrence = &occurrence
	}
	return finding
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

type MemoryWaiverRepository struct {
	mu      sync.RWMutex
	waivers map[string]model.Waiver
}

func NewMemoryWaiverRepository() *MemoryWaiverRepository {
	return &MemoryWaiverRepository{waivers: make(map[string]model.Waiver)}
}

func (r *MemoryWaiverRepository) Save(ctx context.Context, waiver model.Waiver) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waivers[waiver.ID] = waiver
	return nil
}

func (r *MemoryWaiverRepository) Get(ctx context.Context, id string) (model.Waiver, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	waiver, ok := r.waivers[id]
	return waiver, ok, nil
}

func (r *MemoryWaiverRepository) List(ctx context.Context) ([]model.Waiver, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]model.Waiver, 0, len(r.waivers))
	for _, waiver := range r.waivers {
		result = append(result, waiver)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (r *MemoryWaiverRepository) Revoke(ctx context.Context, id string, revokedAt time.Time, revokedBy string, reason string) (model.Waiver, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	waiver, ok := r.waivers[id]
	if !ok {
		return model.Waiver{}, false, nil
	}
	waiver.RevokedAt = &revokedAt
	waiver.RevokedBy = revokedBy
	waiver.RevocationReason = reason
	r.waivers[id] = waiver
	return waiver, true, nil
}

type MemoryExecutionRepository struct {
	mu         sync.RWMutex
	executions map[string]model.ExecutionResult
}

func NewMemoryExecutionRepository() *MemoryExecutionRepository {
	return &MemoryExecutionRepository{executions: make(map[string]model.ExecutionResult)}
}

func (r *MemoryExecutionRepository) Save(ctx context.Context, result model.ExecutionResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.executions[result.ID] = result
	return nil
}

func (r *MemoryExecutionRepository) Get(ctx context.Context, id string) (model.ExecutionResult, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result, ok := r.executions[id]
	return result, ok, nil
}

func (r *MemoryExecutionRepository) List(ctx context.Context) ([]model.ExecutionResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	executions := make([]model.ExecutionResult, 0, len(r.executions))
	for _, result := range r.executions {
		executions = append(executions, result)
	}
	sort.Slice(executions, func(i, j int) bool {
		return executions[i].StartedAt.After(executions[j].StartedAt)
	})
	return executions, nil
}

type MemoryRuleAuditRepository struct {
	mu     sync.RWMutex
	events map[string]model.RuleAuditEvent
}

func NewMemoryRuleAuditRepository() *MemoryRuleAuditRepository {
	return &MemoryRuleAuditRepository{events: make(map[string]model.RuleAuditEvent)}
}

func (r *MemoryRuleAuditRepository) Save(ctx context.Context, event model.RuleAuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events[event.ID] = event
	return nil
}

func (r *MemoryRuleAuditRepository) List(ctx context.Context) ([]model.RuleAuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	events := make([]model.RuleAuditEvent, 0, len(r.events))
	for _, event := range r.events {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	return events, nil
}

type MemoryFindingWorkflowRepository struct {
	mu     sync.RWMutex
	events map[string]model.FindingWorkflowEvent
}

func NewMemoryFindingWorkflowRepository() *MemoryFindingWorkflowRepository {
	return &MemoryFindingWorkflowRepository{events: make(map[string]model.FindingWorkflowEvent)}
}

func (r *MemoryFindingWorkflowRepository) Save(ctx context.Context, event model.FindingWorkflowEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	event.Metadata = cloneStringMap(event.Metadata)
	r.events[event.ID] = event
	return nil
}

func (r *MemoryFindingWorkflowRepository) List(ctx context.Context, findingID string) ([]model.FindingWorkflowEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	events := make([]model.FindingWorkflowEvent, 0, len(r.events))
	for _, event := range r.events {
		if findingID != "" && event.FindingID != findingID {
			continue
		}
		event.Metadata = cloneStringMap(event.Metadata)
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	return events, nil
}

type MemoryAPIAccessAuditRepository struct {
	mu     sync.RWMutex
	events map[string]model.APIAccessAuditEvent
	limit  int
}

func NewMemoryAPIAccessAuditRepository() *MemoryAPIAccessAuditRepository {
	return NewMemoryAPIAccessAuditRepositoryWithLimit(1000)
}

func NewMemoryAPIAccessAuditRepositoryWithLimit(limit int) *MemoryAPIAccessAuditRepository {
	return &MemoryAPIAccessAuditRepository{events: make(map[string]model.APIAccessAuditEvent), limit: limit}
}

func (r *MemoryAPIAccessAuditRepository) Save(ctx context.Context, event model.APIAccessAuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events[event.ID] = event
	r.pruneLocked()
	return nil
}

func (r *MemoryAPIAccessAuditRepository) List(ctx context.Context, filter APIAccessAuditFilter) ([]model.APIAccessAuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	events := make([]model.APIAccessAuditEvent, 0, len(r.events))
	for _, event := range r.events {
		if filter.Method != "" && event.Method != filter.Method {
			continue
		}
		if filter.PathContains != "" && !strings.Contains(event.Path, filter.PathContains) {
			continue
		}
		if filter.StatusCode > 0 && event.StatusCode != filter.StatusCode {
			continue
		}
		if filter.Authenticated != nil && event.Authenticated != *filter.Authenticated {
			continue
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	return events, nil
}

func (r *MemoryAPIAccessAuditRepository) pruneLocked() {
	if r.limit <= 0 || len(r.events) <= r.limit {
		return
	}
	events := make([]model.APIAccessAuditEvent, 0, len(r.events))
	for _, event := range r.events {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	for _, event := range events[r.limit:] {
		delete(r.events, event.ID)
	}
}

type MemoryConnectorAuditRepository struct {
	mu     sync.RWMutex
	events map[string]model.ConnectorAuditEvent
}

func NewMemoryConnectorAuditRepository() *MemoryConnectorAuditRepository {
	return &MemoryConnectorAuditRepository{events: make(map[string]model.ConnectorAuditEvent)}
}

func (r *MemoryConnectorAuditRepository) Save(ctx context.Context, event model.ConnectorAuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events[event.ID] = event
	return nil
}

func (r *MemoryConnectorAuditRepository) List(ctx context.Context) ([]model.ConnectorAuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	events := make([]model.ConnectorAuditEvent, 0, len(r.events))
	for _, event := range r.events {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	return events, nil
}

type MemoryPluginAuditRepository struct {
	mu     sync.RWMutex
	events map[string]model.PluginAuditEvent
}

func NewMemoryPluginAuditRepository() *MemoryPluginAuditRepository {
	return &MemoryPluginAuditRepository{events: make(map[string]model.PluginAuditEvent)}
}

func (r *MemoryPluginAuditRepository) Save(ctx context.Context, event model.PluginAuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events[event.ID] = event
	return nil
}

func (r *MemoryPluginAuditRepository) List(ctx context.Context) ([]model.PluginAuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	events := make([]model.PluginAuditEvent, 0, len(r.events))
	for _, event := range r.events {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	return events, nil
}

type MemoryReportExportRepository struct {
	mu      sync.RWMutex
	exports map[string]model.ReportExport
}

func NewMemoryReportExportRepository() *MemoryReportExportRepository {
	return &MemoryReportExportRepository{exports: make(map[string]model.ReportExport)}
}

func (r *MemoryReportExportRepository) Save(ctx context.Context, export model.ReportExport) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.exports[export.ID] = export
	return nil
}

func (r *MemoryReportExportRepository) Get(ctx context.Context, id string) (model.ReportExport, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	export, ok := r.exports[id]
	return export, ok, nil
}

func (r *MemoryReportExportRepository) List(ctx context.Context) ([]model.ReportExport, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exports := make([]model.ReportExport, 0, len(r.exports))
	for _, export := range r.exports {
		exports = append(exports, export)
	}
	sort.Slice(exports, func(i, j int) bool {
		return exports[i].CreatedAt.After(exports[j].CreatedAt)
	})
	return exports, nil
}
