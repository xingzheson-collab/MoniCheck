package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestFileStoreBatchesRealScaleSnapshotIntoOneAtomicCommit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "monicheck.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	const resourceCount = 3316
	const relationshipCount = 38847
	startedAt := time.Now()
	err = store.WithinBatch(ctx, func() error {
		for index := 0; index < resourceCount; index++ {
			id := fmt.Sprintf("metric-%05d", index)
			if err := store.Resources.Upsert(ctx, model.Resource{ID: id, Type: model.ResourceTypeMetric, Name: id, Status: model.ResourceStatusActive}); err != nil {
				return err
			}
		}
		for index := 0; index < relationshipCount; index++ {
			if err := store.Relationships.Upsert(ctx, model.Relationship{
				ID:     fmt.Sprintf("relationship-%05d", index),
				FromID: fmt.Sprintf("metric-%05d", index%resourceCount),
				ToID:   fmt.Sprintf("metric-%05d", (index+1)%resourceCount),
				Type:   model.RelationshipUses,
			}); err != nil {
				return err
			}
		}
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("state file was written before the snapshot batch completed: %v", statErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed > 15*time.Second {
		t.Fatalf("real-scale snapshot persistence took %s, want <=15s", elapsed)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%#o, want 0600", info.Mode().Perm())
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := reloaded.Resources.List(ctx, ResourceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	relationships, err := reloaded.Relationships.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != resourceCount || len(relationships) != relationshipCount {
		t.Fatalf("reloaded resources=%d relationships=%d", len(resources), len(relationships))
	}
}

func TestFileStoreBatchFlushesPartialMutationWhenOperationFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "monicheck.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("stop snapshot")
	err = store.WithinBatch(ctx, func() error {
		if err := store.Resources.Upsert(ctx, model.Resource{ID: "retained", Type: model.ResourceTypeMetric}); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("batch error=%v, want %v", err, wantErr)
	}
	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := reloaded.Resources.Get(ctx, "retained"); err != nil || !found {
		t.Fatalf("partial mutation was not durably flushed: found=%v err=%v", found, err)
	}
}

func TestFileStoreProtectsDetailedLocalEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monicheck.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Resources.Upsert(context.Background(), model.Resource{ID: "metric-private", Type: model.ResourceTypeMetric, Name: "private_metric"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("local evidence mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestFileStorePersistsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "monicheck.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	resource := model.Resource{
		ID:     "metric-1",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "rel-1",
		FromID: "panel-1",
		ToID:   resource.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	finding := model.Finding{
		ID:       "finding-1",
		Type:     "UnusedMetric",
		Severity: model.SeverityWarning,
		Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Metadata: map[string]string{"analyzer_id": "test"},
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test", []model.Finding{finding}); err != nil {
		t.Fatalf("replace findings: %v", err)
	}
	if _, _, err := store.Findings.UpdateStatus(ctx, finding.ID, model.FindingStatusAcked); err != nil {
		t.Fatalf("ack finding: %v", err)
	}
	workflowEvent := model.FindingWorkflowEvent{
		ID:        "workflow-1",
		FindingID: finding.ID,
		Action:    "ack",
		Actor:     "alice",
		From:      string(model.FindingStatusOpen),
		To:        string(model.FindingStatusAcked),
		Note:      "accepted for cleanup",
		CreatedAt: time.Unix(7, 0).UTC(),
	}
	if err := store.FindingWorkflow.Save(ctx, workflowEvent); err != nil {
		t.Fatalf("save finding workflow: %v", err)
	}
	waiver := model.Waiver{
		ID:         "waiver-1",
		Scope:      model.WaiverScopeFinding,
		ScopeValue: finding.ID,
		Owner:      "platform",
		Reason:     "planned migration",
		CreatedBy:  "alice",
		CreatedAt:  time.Unix(8, 0).UTC(),
		ExpiresAt:  time.Unix(3608, 0).UTC(),
	}
	if err := store.Waivers.Save(ctx, waiver); err != nil {
		t.Fatalf("save waiver: %v", err)
	}
	occurrence := model.FindingOccurrence{
		FindingID: finding.ID, GroupKey: "group-1", AnalyzerID: "test",
		FindingType: finding.Type, Severity: finding.Severity, Category: model.FindingCategoryLifecycle,
		ResourceType: finding.Resource.Type, FirstSeenAt: time.Unix(8, 0).UTC(),
		LastSeenAt: time.Unix(9, 0).UTC(), ObservationCount: 2, Active: true,
	}
	if err := store.FindingOccurrences.ReplaceByAnalyzer(ctx, "test", []model.FindingOccurrence{occurrence}); err != nil {
		t.Fatalf("save finding occurrence: %v", err)
	}
	execution := model.ExecutionResult{
		ID:         "execution-1",
		Status:     model.ExecutionStatusSucceeded,
		StartedAt:  time.Unix(0, 0).UTC(),
		FinishedAt: time.Unix(1, 0).UTC(),
	}
	if err := store.Executions.Save(ctx, execution); err != nil {
		t.Fatalf("save execution: %v", err)
	}
	auditEvent := model.RuleAuditEvent{
		ID:        "audit-1",
		Action:    "reload",
		Status:    "SUCCEEDED",
		RuleCount: 1,
		CreatedAt: time.Unix(2, 0).UTC(),
	}
	if err := store.RuleAudit.Save(ctx, auditEvent); err != nil {
		t.Fatalf("save rule audit: %v", err)
	}
	apiAuditEvent := model.APIAccessAuditEvent{
		ID:             "api-audit-1",
		RequestID:      "request-1",
		Method:         "GET",
		Path:           "/api/v1/resources",
		StatusCode:     200,
		DurationMillis: 12,
		Authenticated:  true,
		CreatedAt:      time.Unix(3, 0).UTC(),
	}
	if err := store.APIAudit.Save(ctx, apiAuditEvent); err != nil {
		t.Fatalf("save api audit: %v", err)
	}
	connectorAuditEvent := model.ConnectorAuditEvent{
		ID:          "connector-audit-1",
		ConnectorID: "prometheus",
		Action:      "secret_rotated",
		Field:       "prometheus_bearer_token",
		Status:      "SUCCEEDED",
		RequestID:   "request-2",
		CreatedAt:   time.Unix(4, 0).UTC(),
	}
	if err := store.ConnectorAudit.Save(ctx, connectorAuditEvent); err != nil {
		t.Fatalf("save connector audit: %v", err)
	}
	pluginAuditEvent := model.PluginAuditEvent{
		ID:             "plugin-audit-1",
		PluginID:       "plugin.rule_pack",
		PluginType:     "rule",
		Action:         "load_rules",
		Status:         "SUCCEEDED",
		DurationMillis: 3,
		CreatedAt:      time.Unix(5, 0).UTC(),
	}
	if err := store.PluginAudit.Save(ctx, pluginAuditEvent); err != nil {
		t.Fatalf("save plugin audit: %v", err)
	}
	reportExport := model.ReportExport{
		ID:          "report-export-1",
		Type:        "governance",
		Format:      "csv",
		Filename:    "monicheck-governance-report.csv",
		ContentType: "text/csv",
		Content:     "section,key,value\nsummary,resource_count,1\n",
		CreatedAt:   time.Unix(6, 0).UTC(),
	}
	if err := store.ReportExports.Save(ctx, reportExport); err != nil {
		t.Fatalf("save report export: %v", err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	if _, ok, err := reloaded.Resources.Get(ctx, resource.ID); err != nil || !ok {
		t.Fatalf("expected persisted resource, ok=%v err=%v", ok, err)
	}
	relationships, err := reloaded.Relationships.ListByResource(ctx, resource.ID)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(relationships))
	}
	reloadedFinding, ok, err := reloaded.Findings.Get(ctx, finding.ID)
	if err != nil || !ok {
		t.Fatalf("expected persisted finding, ok=%v err=%v", ok, err)
	}
	if reloadedFinding.Status != model.FindingStatusAcked {
		t.Fatalf("expected finding status %s, got %s", model.FindingStatusAcked, reloadedFinding.Status)
	}
	if reloadedFinding.Category != model.FindingCategoryLifecycle {
		t.Fatalf("expected lifecycle category, got %s", reloadedFinding.Category)
	}
	workflowEvents, err := reloaded.FindingWorkflow.List(ctx, finding.ID)
	if err != nil {
		t.Fatalf("list finding workflow: %v", err)
	}
	if len(workflowEvents) != 1 || workflowEvents[0].ID != workflowEvent.ID || workflowEvents[0].Note != workflowEvent.Note {
		t.Fatalf("expected persisted finding workflow event, got %#v", workflowEvents)
	}
	reloadedWaiver, ok, err := reloaded.Waivers.Get(ctx, waiver.ID)
	if err != nil || !ok || reloadedWaiver.Reason != waiver.Reason {
		t.Fatalf("expected persisted waiver, got %#v ok=%v err=%v", reloadedWaiver, ok, err)
	}
	reloadedOccurrence, ok, err := reloaded.FindingOccurrences.Get(ctx, finding.ID)
	if err != nil || !ok || reloadedOccurrence.ObservationCount != 2 || reloadedOccurrence.GroupKey != occurrence.GroupKey {
		t.Fatalf("expected persisted finding occurrence, got %#v ok=%v err=%v", reloadedOccurrence, ok, err)
	}
	if _, ok, err := reloaded.Executions.Get(ctx, execution.ID); err != nil || !ok {
		t.Fatalf("expected persisted execution, ok=%v err=%v", ok, err)
	}
	auditEvents, err := reloaded.RuleAudit.List(ctx)
	if err != nil {
		t.Fatalf("list rule audit: %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].ID != auditEvent.ID {
		t.Fatalf("expected persisted rule audit event, got %#v", auditEvents)
	}
	apiAuditEvents, err := reloaded.APIAudit.List(ctx, APIAccessAuditFilter{})
	if err != nil {
		t.Fatalf("list api audit: %v", err)
	}
	if len(apiAuditEvents) != 1 || apiAuditEvents[0].ID != apiAuditEvent.ID {
		t.Fatalf("expected persisted api audit event, got %#v", apiAuditEvents)
	}
	connectorAuditEvents, err := reloaded.ConnectorAudit.List(ctx)
	if err != nil {
		t.Fatalf("list connector audit: %v", err)
	}
	if len(connectorAuditEvents) != 1 || connectorAuditEvents[0].ID != connectorAuditEvent.ID {
		t.Fatalf("expected persisted connector audit event, got %#v", connectorAuditEvents)
	}
	pluginAuditEvents, err := reloaded.PluginAudit.List(ctx)
	if err != nil {
		t.Fatalf("list plugin audit: %v", err)
	}
	if len(pluginAuditEvents) != 1 || pluginAuditEvents[0].ID != pluginAuditEvent.ID {
		t.Fatalf("expected persisted plugin audit event, got %#v", pluginAuditEvents)
	}
	reloadedExport, ok, err := reloaded.ReportExports.Get(ctx, reportExport.ID)
	if err != nil || !ok {
		t.Fatalf("expected persisted report export, ok=%v err=%v", ok, err)
	}
	if reloadedExport.Content != reportExport.Content {
		t.Fatalf("expected persisted report export content, got %q", reloadedExport.Content)
	}
}

func TestFileStorePersistsRelationshipDeletion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "monicheck.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	relationship := model.Relationship{ID: "stale-relationship", FromID: "from", ToID: "to", Type: model.RelationshipUses}
	if err := store.Relationships.Upsert(ctx, relationship); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	if err := store.Relationships.Delete(ctx, relationship.ID); err != nil {
		t.Fatalf("delete relationship: %v", err)
	}
	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	relationships, err := reloaded.Relationships.List(ctx)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 0 {
		t.Fatalf("expected relationship deletion to persist, got %#v", relationships)
	}
}

func TestFileStorePersistsCoverageGovernance(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "monicheck.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	builtin, found, err := store.CoverageExpectations.Get(ctx, model.BuiltinServiceCoverageExpectationID)
	if err != nil || !found || len(builtin.RequiredSignals) != 3 {
		t.Fatalf("expected built-in coverage baseline, found=%v err=%v item=%#v", found, err, builtin)
	}
	builtin.Owner = "sre"
	builtin.UpdatedAt = time.Now().UTC()
	if err := store.CoverageExpectations.Save(ctx, builtin); err != nil {
		t.Fatalf("save coverage expectation: %v", err)
	}
	exception := model.CoverageException{
		ID: "coverage-exception-1", ExpectationID: builtin.ID, ServiceID: "service-api",
		Signal: model.CoverageSignalDashboards, Owner: "sre", Reason: "migration", CreatedBy: "alice",
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := store.CoverageExceptions.Save(ctx, exception); err != nil {
		t.Fatalf("save coverage exception: %v", err)
	}
	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	gotExpectation, found, err := reloaded.CoverageExpectations.Get(ctx, builtin.ID)
	if err != nil || !found || gotExpectation.Owner != "sre" {
		t.Fatalf("expected persisted coverage expectation, found=%v err=%v item=%#v", found, err, gotExpectation)
	}
	gotException, found, err := reloaded.CoverageExceptions.Get(ctx, exception.ID)
	if err != nil || !found || gotException.Reason != "migration" {
		t.Fatalf("expected persisted coverage exception, found=%v err=%v item=%#v", found, err, gotException)
	}
}

func TestFileStoreConcurrentAuditWritesAreIsolatedFromFindingReaders(t *testing.T) {
	ctx := context.Background()
	store, err := NewFileStore(filepath.Join(t.TempDir(), "monicheck.json"))
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	finding := model.Finding{
		ID: "finding-1", Type: "UnusedMetric", Severity: model.SeverityWarning,
		Resource: model.ResourceRef{ID: "metric-1", Type: model.ResourceTypeMetric},
		Metadata: map[string]string{"analyzer_id": "builtin.unused_metric"},
		Status:   model.FindingStatusOpen,
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "builtin.unused_metric", []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		workers.Add(2)
		go func() {
			defer workers.Done()
			for index := 0; index < 40; index++ {
				items, listErr := store.Findings.List(ctx, FindingFilter{})
				if listErr != nil {
					t.Errorf("list findings: %v", listErr)
					return
				}
				items[0].Metadata["reader"] = strconv.Itoa(worker)
				delete(items[0].Metadata, "analyzer_id")
			}
		}()
		go func() {
			defer workers.Done()
			for index := 0; index < 40; index++ {
				id := strconv.Itoa(worker) + "-" + strconv.Itoa(index)
				if saveErr := store.APIAudit.Save(ctx, model.APIAccessAuditEvent{ID: id, CreatedAt: time.Now().UTC()}); saveErr != nil {
					t.Errorf("save api audit: %v", saveErr)
					return
				}
			}
		}()
	}
	workers.Wait()
	stored, found, err := store.Findings.Get(ctx, finding.ID)
	if err != nil || !found || stored.Metadata["analyzer_id"] != "builtin.unused_metric" || stored.Metadata["reader"] != "" {
		t.Fatalf("reader mutation escaped repository boundary: found=%v err=%v finding=%#v", found, err, stored)
	}
}

func TestAPIAccessAuditFiltersAndRetention(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryAPIAccessAuditRepositoryWithLimit(2)
	events := []model.APIAccessAuditEvent{
		{ID: "old", Method: "GET", Path: "/api/v1/resources", StatusCode: 200, Authenticated: true, CreatedAt: time.Unix(1, 0).UTC()},
		{ID: "middle", Method: "POST", Path: "/api/v1/execution/run", StatusCode: 202, Authenticated: true, CreatedAt: time.Unix(2, 0).UTC()},
		{ID: "new", Method: "GET", Path: "/api/v1/audit/api", StatusCode: 401, Authenticated: false, CreatedAt: time.Unix(3, 0).UTC()},
	}
	for _, event := range events {
		if err := repo.Save(ctx, event); err != nil {
			t.Fatalf("save api audit event: %v", err)
		}
	}

	all, err := repo.List(ctx, APIAccessAuditFilter{})
	if err != nil {
		t.Fatalf("list api audit events: %v", err)
	}
	if len(all) != 2 || all[0].ID != "new" || all[1].ID != "middle" {
		t.Fatalf("expected retention to keep latest two events, got %#v", all)
	}

	authenticated := false
	filtered, err := repo.List(ctx, APIAccessAuditFilter{Method: "GET", StatusCode: 401, Authenticated: &authenticated})
	if err != nil {
		t.Fatalf("filter api audit events: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != "new" {
		t.Fatalf("expected filtered unauthenticated GET 401 event, got %#v", filtered)
	}
}
