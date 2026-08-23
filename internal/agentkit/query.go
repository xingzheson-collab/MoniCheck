package agentkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	coveragepkg "monicheck/internal/coverage"
	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

const (
	defaultQueryLimit  = 20
	maximumQueryLimit  = 50
	maximumPurposeSize = 240
)

type Disclosure struct {
	Mode                      string            `json:"mode"`
	Purpose                   string            `json:"purpose"`
	Scope                     map[string]string `json:"scope"`
	ResultLimit               int               `json:"result_limit"`
	ResultCount               int               `json:"result_count"`
	Truncated                 bool              `json:"truncated"`
	DisclosedIdentifierFields []string          `json:"disclosed_identifier_fields"`
	ExcludedFields            []string          `json:"excluded_fields"`
	AuditEventRef             string            `json:"audit_event_ref"`
}

type EntityRef struct {
	ID     string               `json:"id"`
	Type   model.ResourceType   `json:"type"`
	Name   string               `json:"name"`
	Status model.ResourceStatus `json:"status"`
}

type FindingQueryInput struct {
	Service  string `json:"service"`
	Entity   string `json:"entity"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Limit    int    `json:"limit"`
	Purpose  string `json:"purpose"`
}

type FindingQueryItem struct {
	FindingID      string                `json:"finding_id"`
	Type           string                `json:"type"`
	Category       model.FindingCategory `json:"category"`
	Severity       model.Severity        `json:"severity"`
	Status         model.FindingStatus   `json:"status"`
	RiskScore      *int                  `json:"risk_score,omitempty"`
	Resource       EntityRef             `json:"resource"`
	Recommendation string                `json:"recommendation"`
	EvidenceCount  int                   `json:"evidence_count"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

type FindingQueryResult struct {
	ContractVersion string             `json:"contract_version"`
	MatchedCount    int                `json:"matched_count"`
	Findings        []FindingQueryItem `json:"findings"`
	ActionGroups    []ActionGroup      `json:"action_groups"`
	Disclosure      Disclosure         `json:"disclosure"`
}

type CoverageByServiceInput struct {
	Service string `json:"service"`
	Purpose string `json:"purpose"`
}

type CoverageByServiceResult struct {
	ContractVersion string                   `json:"contract_version"`
	Service         EntityRef                `json:"service"`
	Assessments     []coveragepkg.Assessment `json:"assessments"`
	Visibility      InventoryVisibility      `json:"inventory_visibility"`
	Disclosure      Disclosure               `json:"disclosure"`
}

type EntityGetInput struct {
	ID      string `json:"id"`
	Limit   int    `json:"limit"`
	Purpose string `json:"purpose"`
}

type EntityRelation struct {
	Direction string                 `json:"direction"`
	Type      model.RelationshipType `json:"type"`
	Entity    EntityRef              `json:"entity"`
}

type EntityResult struct {
	ContractVersion   string             `json:"contract_version"`
	Entity            EntityRef          `json:"entity"`
	SourceSystem      string             `json:"source_system"`
	SourceCluster     string             `json:"source_cluster,omitempty"`
	UpdatedAt         time.Time          `json:"updated_at"`
	RelationshipCount int                `json:"relationship_count"`
	Relationships     []EntityRelation   `json:"relationships"`
	FindingCount      int                `json:"finding_count"`
	Findings          []FindingQueryItem `json:"findings"`
	Disclosure        Disclosure         `json:"disclosure"`
}

type BaselineDiffInput struct {
	Limit   int    `json:"limit"`
	Purpose string `json:"purpose"`
}

type BaselineChange struct {
	FindingID string              `json:"finding_id,omitempty"`
	Type      string              `json:"type"`
	Severity  model.Severity      `json:"severity"`
	From      model.FindingStatus `json:"from,omitempty"`
	To        model.FindingStatus `json:"to,omitempty"`
	Change    string              `json:"change"`
	Resource  *EntityRef          `json:"resource,omitempty"`
}

type BaselineDiffResult struct {
	ContractVersion  string                      `json:"contract_version"`
	State            string                      `json:"state"`
	SnapshotCount    int                         `json:"snapshot_count"`
	Delta            map[string]int              `json:"delta"`
	RegressedMetrics []string                    `json:"regressed_metrics"`
	ImprovedMetrics  []string                    `json:"improved_metrics"`
	FindingDiff      *BaselineFindingDiffSummary `json:"finding_diff,omitempty"`
	Changes          []BaselineChange            `json:"changes"`
	Disclosure       Disclosure                  `json:"disclosure"`
}

type BaselineFindingDiffSummary struct {
	Comparable       bool   `json:"comparable"`
	Reason           string `json:"reason,omitempty"`
	PreviousCount    int    `json:"previous_count"`
	CurrentCount     int    `json:"current_count"`
	NewOpen          int    `json:"new_open"`
	PersistentOpen   int    `json:"persistent_open"`
	Triaged          int    `json:"triaged"`
	Reopened         int    `json:"reopened"`
	Cleared          int    `json:"cleared"`
	ChangesTruncated bool   `json:"changes_truncated"`
}

type queryAuditEvent struct {
	ContractVersion           string            `json:"contract_version"`
	EventID                   string            `json:"event_id"`
	CreatedAt                 time.Time         `json:"created_at"`
	Tool                      string            `json:"tool"`
	Purpose                   string            `json:"purpose"`
	Scope                     map[string]string `json:"scope"`
	ResultLimit               int               `json:"result_limit"`
	ResultCount               int               `json:"result_count"`
	Truncated                 bool              `json:"truncated"`
	DisclosedIdentifierFields []string          `json:"disclosed_identifier_fields"`
}

func QueryFindings(ctx context.Context, storagePath string, input FindingQueryInput) (FindingQueryResult, error) {
	purpose, err := validatePurpose(input.Purpose)
	if err != nil {
		return FindingQueryResult{}, err
	}
	limit, err := boundedLimit(input.Limit)
	if err != nil {
		return FindingQueryResult{}, err
	}
	scope := compactScope(map[string]string{"service": input.Service, "entity": input.Entity, "type": input.Type, "severity": input.Severity})
	if len(scope) == 0 {
		return FindingQueryResult{}, errors.New("at least one of service, entity, type, or severity is required")
	}
	store, err := openQueryStore(storagePath)
	if err != nil {
		return FindingQueryResult{}, err
	}
	resources, relationships, resourcesByID, err := loadResourceGraph(ctx, store)
	if err != nil {
		return FindingQueryResult{}, err
	}
	resourceGraph := graph.NewBounded(resources, relationships)
	var scopedIDs map[string]bool
	if strings.TrimSpace(input.Service) != "" {
		service, resolveErr := resolveOneResource(resources, input.Service, model.ResourceTypeService)
		if resolveErr != nil {
			return FindingQueryResult{}, resolveErr
		}
		scopedIDs = map[string]bool{service.ID: true}
		for _, related := range coveragepkg.RelatedResourcesForService(service.ID, resourceGraph) {
			scopedIDs[related.ID] = true
		}
	}
	if strings.TrimSpace(input.Entity) != "" {
		entity, resolveErr := resolveOneResource(resources, input.Entity, "")
		if resolveErr != nil {
			return FindingQueryResult{}, resolveErr
		}
		entityScope := map[string]bool{entity.ID: true}
		if scopedIDs == nil {
			scopedIDs = entityScope
		} else {
			scopedIDs = intersectIDs(scopedIDs, entityScope)
		}
	}
	severity, err := normalizeSeverity(input.Severity)
	if err != nil {
		return FindingQueryResult{}, err
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return FindingQueryResult{}, err
	}
	items := make([]FindingQueryItem, 0)
	for _, finding := range findings {
		if scopedIDs != nil && !scopedIDs[finding.Resource.ID] {
			continue
		}
		if input.Type != "" && !strings.EqualFold(strings.TrimSpace(input.Type), finding.Type) {
			continue
		}
		if severity != "" && finding.Severity != severity {
			continue
		}
		if finding.Status == model.FindingStatusResolved || finding.Status == model.FindingStatusClosed {
			continue
		}
		resource, ok := resourcesByID[finding.Resource.ID]
		if !ok {
			continue
		}
		items = append(items, findingQueryItem(finding, resource))
	}
	sortFindingItems(items)
	matched := len(items)
	allItems := items
	if len(items) > limit {
		items = items[:limit]
	}
	actionGroups := actionGroupsFromQuery(allItems, items)
	disclosure, err := recordDisclosure(storagePath, "monicheck.findings.query", purpose, scope, limit, matched, matched > len(items), []string{"finding_id", "resource.id", "resource.name"})
	if err != nil {
		return FindingQueryResult{}, err
	}
	return FindingQueryResult{ContractVersion: "agent-findings-query.v1", MatchedCount: matched, Findings: items, ActionGroups: actionGroups, Disclosure: disclosure}, nil
}

func CoverageByService(ctx context.Context, storagePath string, input CoverageByServiceInput) (CoverageByServiceResult, error) {
	purpose, err := validatePurpose(input.Purpose)
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	if strings.TrimSpace(input.Service) == "" {
		return CoverageByServiceResult{}, errors.New("service is required")
	}
	store, err := openQueryStore(storagePath)
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	resources, relationships, _, err := loadResourceGraph(ctx, store)
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	service, err := resolveOneResource(resources, input.Service, model.ResourceTypeService)
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	expectations, err := store.CoverageExpectations.List(ctx)
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	exceptions, err := store.CoverageExceptions.List(ctx)
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	summary := coveragepkg.Assess(resources, graph.NewBounded(resources, relationships), expectations, exceptions, time.Now().UTC())
	assessments := make([]coveragepkg.Assessment, 0)
	for _, assessment := range summary.Assessments {
		if assessment.ServiceID == service.ID {
			assessments = append(assessments, assessment)
		}
	}
	matchedAssessments := len(assessments)
	scope := map[string]string{"service": input.Service}
	disclosure, err := recordDisclosure(storagePath, "monicheck.coverage.by_service", purpose, scope, matchedAssessments, matchedAssessments, false, []string{"service.id", "service.name"})
	if err != nil {
		return CoverageByServiceResult{}, err
	}
	return CoverageByServiceResult{
		ContractVersion: "agent-service-coverage.v1", Service: entityRef(service), Assessments: assessments,
		Visibility: inventoryVisibility(nil, len(resources)), Disclosure: disclosure,
	}, nil
}

func GetEntity(ctx context.Context, storagePath string, input EntityGetInput) (EntityResult, error) {
	purpose, err := validatePurpose(input.Purpose)
	if err != nil {
		return EntityResult{}, err
	}
	if strings.TrimSpace(input.ID) == "" {
		return EntityResult{}, errors.New("id is required")
	}
	limit, err := boundedLimit(input.Limit)
	if err != nil {
		return EntityResult{}, err
	}
	store, err := openQueryStore(storagePath)
	if err != nil {
		return EntityResult{}, err
	}
	resource, found, err := store.Resources.Get(ctx, strings.TrimSpace(input.ID))
	if err != nil {
		return EntityResult{}, err
	}
	if !found {
		return EntityResult{}, errors.New("entity not found")
	}
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return EntityResult{}, err
	}
	resourcesByID := indexResources(resources)
	relationships, err := store.Relationships.ListByResource(ctx, resource.ID)
	if err != nil {
		return EntityResult{}, err
	}
	relations := make([]EntityRelation, 0, len(relationships))
	for _, relationship := range relationships {
		otherID, direction := relationship.ToID, "OUTGOING"
		if relationship.ToID == resource.ID {
			otherID, direction = relationship.FromID, "INCOMING"
		}
		other, ok := resourcesByID[otherID]
		if !ok {
			continue
		}
		relations = append(relations, EntityRelation{Direction: direction, Type: relationship.Type, Entity: entityRef(other)})
	}
	sort.Slice(relations, func(i, j int) bool {
		if relations[i].Direction != relations[j].Direction {
			return relations[i].Direction < relations[j].Direction
		}
		if relations[i].Type != relations[j].Type {
			return relations[i].Type < relations[j].Type
		}
		return relations[i].Entity.ID < relations[j].Entity.ID
	})
	relationCount := len(relations)
	if len(relations) > limit {
		relations = relations[:limit]
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return EntityResult{}, err
	}
	findingItems := make([]FindingQueryItem, 0)
	for _, finding := range findings {
		if finding.Resource.ID == resource.ID && finding.Status != model.FindingStatusResolved && finding.Status != model.FindingStatusClosed {
			findingItems = append(findingItems, findingQueryItem(finding, resource))
		}
	}
	sortFindingItems(findingItems)
	findingCount := len(findingItems)
	if len(findingItems) > limit {
		findingItems = findingItems[:limit]
	}
	truncated := relationCount > len(relations) || findingCount > len(findingItems)
	scope := map[string]string{"id": input.ID}
	disclosure, err := recordDisclosure(storagePath, "monicheck.entity.get", purpose, scope, limit, 1, truncated, []string{"entity.id", "entity.name", "relationships.entity.id", "relationships.entity.name", "findings.finding_id"})
	if err != nil {
		return EntityResult{}, err
	}
	return EntityResult{
		ContractVersion: "agent-entity.v1", Entity: entityRef(resource), SourceSystem: resource.Source.System,
		SourceCluster: resource.Source.Cluster, UpdatedAt: resource.UpdatedAt, RelationshipCount: relationCount,
		Relationships: relations, FindingCount: findingCount, Findings: findingItems, Disclosure: disclosure,
	}, nil
}

func BaselineDiff(ctx context.Context, storagePath string, input BaselineDiffInput) (BaselineDiffResult, error) {
	purpose, err := validatePurpose(input.Purpose)
	if err != nil {
		return BaselineDiffResult{}, err
	}
	limit, err := boundedLimit(input.Limit)
	if err != nil {
		return BaselineDiffResult{}, err
	}
	store, err := openQueryStore(storagePath)
	if err != nil {
		return BaselineDiffResult{}, err
	}
	regression, err := report.BuildLocalRegression(ctx, store)
	if err != nil {
		return BaselineDiffResult{}, err
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return BaselineDiffResult{}, err
	}
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return BaselineDiffResult{}, err
	}
	findingsByID := make(map[string]model.Finding, len(findings))
	for _, finding := range findings {
		findingsByID[finding.ID] = finding
	}
	resourcesByID := indexResources(resources)
	changes := []BaselineChange{}
	changeCount := 0
	if regression.FindingDiff != nil {
		changeCount = len(regression.FindingDiff.Changes)
		for _, change := range regression.FindingDiff.Changes {
			item := BaselineChange{FindingID: change.ID, Type: change.Type, Severity: change.Severity, From: change.From, To: change.To, Change: change.Change}
			if finding, ok := findingsByID[change.ID]; ok {
				if resource, exists := resourcesByID[finding.Resource.ID]; exists {
					ref := entityRef(resource)
					item.Resource = &ref
				}
			}
			changes = append(changes, item)
			if len(changes) == limit {
				break
			}
		}
	}
	truncated := changeCount > len(changes) || (regression.FindingDiff != nil && regression.FindingDiff.ChangesTruncated)
	disclosure, err := recordDisclosure(storagePath, "monicheck.baseline.diff", purpose, map[string]string{"scope": "latest_two_snapshots"}, limit, changeCount, truncated, []string{"changes.finding_id", "changes.resource.id", "changes.resource.name"})
	if err != nil {
		return BaselineDiffResult{}, err
	}
	var findingDiff *BaselineFindingDiffSummary
	if regression.FindingDiff != nil {
		findingDiff = &BaselineFindingDiffSummary{
			Comparable: regression.FindingDiff.Comparable, Reason: regression.FindingDiff.Reason,
			PreviousCount: regression.FindingDiff.PreviousCount, CurrentCount: regression.FindingDiff.CurrentCount,
			NewOpen: regression.FindingDiff.NewOpen, PersistentOpen: regression.FindingDiff.PersistentOpen,
			Triaged: regression.FindingDiff.Triaged, Reopened: regression.FindingDiff.Reopened,
			Cleared: regression.FindingDiff.Cleared, ChangesTruncated: regression.FindingDiff.ChangesTruncated,
		}
	}
	return BaselineDiffResult{
		ContractVersion: "agent-baseline-diff.v1", State: regression.State, SnapshotCount: regression.SnapshotCount,
		Delta: regression.Delta, RegressedMetrics: regression.RegressedMetrics, ImprovedMetrics: regression.ImprovedMetrics,
		FindingDiff: findingDiff, Changes: changes, Disclosure: disclosure,
	}, nil
}

func openQueryStore(path string) (*storage.Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("storage_path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("local state unavailable; run monicheck.audit.run first")
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("storage_path must be a regular file")
	}
	return storage.NewFileStore(path)
}

func loadResourceGraph(ctx context.Context, store *storage.Store) ([]model.Resource, []model.Relationship, map[string]model.Resource, error) {
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, nil, nil, err
	}
	relationships, err := store.Relationships.List(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return resources, relationships, indexResources(resources), nil
}

func indexResources(resources []model.Resource) map[string]model.Resource {
	result := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		result[resource.ID] = resource
	}
	return result
}

func resolveOneResource(resources []model.Resource, selector string, resourceType model.ResourceType) (model.Resource, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return model.Resource{}, errors.New("resource selector is required")
	}
	exact := []model.Resource{}
	partial := []model.Resource{}
	needle := strings.ToLower(selector)
	for _, resource := range resources {
		if resourceType != "" && resource.Type != resourceType {
			continue
		}
		if strings.EqualFold(resource.ID, selector) || strings.EqualFold(resource.Name, selector) || strings.EqualFold(resource.UID, selector) {
			exact = append(exact, resource)
			continue
		}
		if strings.Contains(strings.ToLower(resource.Name), needle) || strings.Contains(strings.ToLower(resource.UID), needle) {
			partial = append(partial, resource)
		}
	}
	candidates := exact
	if len(candidates) == 0 {
		candidates = partial
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return model.Resource{}, fmt.Errorf("resource %q not found", selector)
	}
	return model.Resource{}, fmt.Errorf("resource %q is ambiguous; use an exact MoniCheck entity ID", selector)
}

func entityRef(resource model.Resource) EntityRef {
	return EntityRef{ID: resource.ID, Type: resource.Type, Name: resource.Name, Status: resource.Status}
}

func findingQueryItem(finding model.Finding, resource model.Resource) FindingQueryItem {
	var score *int
	if finding.RiskScore != nil {
		value := finding.RiskScore.Score
		score = &value
	}
	return FindingQueryItem{
		FindingID: finding.ID, Type: finding.Type, Category: finding.Category, Severity: finding.Severity,
		Status: finding.Status, RiskScore: score, Resource: entityRef(resource),
		Recommendation: sanitizeRecommendation(finding.Recommendation), EvidenceCount: len(finding.Evidence), UpdatedAt: finding.UpdatedAt,
	}
}

func sortFindingItems(items []FindingQueryItem) {
	sort.Slice(items, func(i, j int) bool {
		left, right := querySeverityRank(items[i].Severity), querySeverityRank(items[j].Severity)
		if left != right {
			return left > right
		}
		leftRisk, rightRisk := -1, -1
		if items[i].RiskScore != nil {
			leftRisk = *items[i].RiskScore
		}
		if items[j].RiskScore != nil {
			rightRisk = *items[j].RiskScore
		}
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}
		if !items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].FindingID < items[j].FindingID
	})
}

func intersectIDs(left, right map[string]bool) map[string]bool {
	result := map[string]bool{}
	for id := range left {
		if right[id] {
			result[id] = true
		}
	}
	return result
}

func normalizeSeverity(value string) (model.Severity, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	severity := model.Severity(value)
	if severity != model.SeverityCritical && severity != model.SeverityWarning && severity != model.SeverityInfo {
		return "", errors.New("severity must be CRITICAL, WARNING, or INFO")
	}
	return severity, nil
}

func querySeverityRank(value model.Severity) int {
	switch value {
	case model.SeverityCritical:
		return 3
	case model.SeverityWarning:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func boundedLimit(value int) (int, error) {
	if value == 0 {
		return defaultQueryLimit, nil
	}
	if value < 1 || value > maximumQueryLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", maximumQueryLimit)
	}
	return value, nil
}

func validatePurpose(value string) (string, error) {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "", errors.New("purpose is required for need-to-know disclosure")
	}
	if len(value) > maximumPurposeSize {
		return "", fmt.Errorf("purpose must be at most %d bytes", maximumPurposeSize)
	}
	return value, nil
}

func compactScope(values map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result[key] = value
		}
	}
	return result
}

func boundedText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum]) + "..."
}

var endpointPattern = regexp.MustCompile(`(?i)https?://[^\s]+`)

func sanitizeRecommendation(value string) string {
	return boundedText(endpointPattern.ReplaceAllString(value, "[REDACTED_ENDPOINT]"), 1000)
}

func recordDisclosure(storagePath, tool, purpose string, scope map[string]string, limit, resultCount int, truncated bool, fields []string) (Disclosure, error) {
	now := time.Now().UTC()
	scopeBody, _ := json.Marshal(scope)
	event := queryAuditEvent{
		ContractVersion: "agent-query-audit.v1", CreatedAt: now, Tool: tool, Purpose: purpose,
		Scope: scope, ResultLimit: limit, ResultCount: resultCount, Truncated: truncated,
		DisclosedIdentifierFields: append([]string{}, fields...),
	}
	event.EventID = model.StableID("agent_query", tool, purpose, string(scopeBody), now.Format(time.RFC3339Nano))
	if err := appendQueryAudit(storagePath, event); err != nil {
		return Disclosure{}, fmt.Errorf("write need-to-know audit: %w", err)
	}
	return Disclosure{
		Mode: "NEED_TO_KNOW", Purpose: purpose, Scope: scope, ResultLimit: limit, ResultCount: resultCount,
		Truncated: truncated, DisclosedIdentifierFields: append([]string{}, fields...),
		ExcludedFields: []string{"credentials", "endpoint URLs", "labels", "raw queries", "raw evidence", "dashboard JSON", "source configuration", "user identity"},
		AuditEventRef:  event.EventID,
	}, nil
}

func appendQueryAudit(storagePath string, event queryAuditEvent) (returnErr error) {
	path := storagePath + ".agent-query-audit.jsonl"
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("query audit path must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	return json.NewEncoder(file).Encode(event)
}
