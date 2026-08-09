package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"monicheck/internal/analyzer"
	"monicheck/internal/connector"
	"monicheck/internal/logger"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestEngineBootstrap(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	registry := analyzer.NewRegistry()
	registry.Register(analyzer.NewUnusedMetricAnalyzer())
	registry.Register(analyzer.NewBrokenTargetAnalyzer())
	registry.Register(analyzer.NewSlowTargetScrapeAnalyzer())
	registry.Register(analyzer.NewStaleTargetScrapeAnalyzer())
	registry.Register(analyzer.NewTargetScrapeTimeoutRiskAnalyzer())
	registry.Register(analyzer.NewMetricMetadataAnalyzer())
	registry.Register(analyzer.NewHighCardinalityMetricAnalyzer())
	registry.Register(analyzer.NewHighImpactMetricAnalyzer())
	registry.Register(analyzer.NewEmptyDashboardAnalyzer())
	registry.Register(analyzer.NewUnusedDatasourceAnalyzer())
	registry.Register(analyzer.NewBrokenPanelQueryAnalyzer())
	registry.Register(analyzer.NewPanelWithoutDatasourceAnalyzer())
	registry.Register(analyzer.NewPanelWithoutVisualizationTypeAnalyzer())
	registry.Register(analyzer.NewPanelWithoutTitleAnalyzer())
	registry.Register(analyzer.NewPanelWithoutUnitAnalyzer())
	registry.Register(analyzer.NewPanelWithoutThresholdsAnalyzer())
	registry.Register(analyzer.NewTinyPanelAnalyzer())
	registry.Register(analyzer.NewBrokenRuleAnalyzer())
	registry.Register(analyzer.NewBrokenRuleQueryAnalyzer())
	registry.Register(analyzer.NewOrphanAlertAnalyzer())
	registry.Register(analyzer.NewUnusedRecordingRuleAnalyzer())
	registry.Register(analyzer.NewDuplicateRuleAnalyzer())
	registry.Register(analyzer.NewDuplicateRecordingRuleOutputAnalyzer())
	registry.Register(analyzer.NewNoAnnotationAnalyzer())
	registry.Register(analyzer.NewDisabledAlertAnalyzer())
	registry.Register(analyzer.NewMetricNamingAnalyzer())
	registry.Register(analyzer.NewAlertNamingAnalyzer())
	registry.Register(analyzer.NewDuplicateDashboardAnalyzer())
	registry.Register(analyzer.NewBrokenDashboardAnalyzer())
	registry.Register(analyzer.NewDashboardWithoutFolderAnalyzer())
	registry.Register(analyzer.NewDashboardWithoutTagsAnalyzer())
	registry.Register(analyzer.NewEditableDashboardAnalyzer())
	registry.Register(analyzer.NewLargeDashboardAnalyzer())
	registry.Register(analyzer.NewFastDashboardRefreshAnalyzer())
	registry.Register(analyzer.NewLongDashboardTimeRangeAnalyzer())
	registry.Register(analyzer.NewExpensiveQueryAnalyzer())
	registry.Register(analyzer.NewWideRangeQueryAnalyzer())
	registry.Register(analyzer.NewWideLogQueryAnalyzer())
	registry.Register(analyzer.NewHighCardinalityAggregationAnalyzer())
	registry.Register(analyzer.NewUnscopedQueryAnalyzer())
	registry.Register(analyzer.NewUnscopedLogQueryAnalyzer())
	registry.Register(analyzer.NewUnscopedTraceQueryAnalyzer())
	registry.Register(analyzer.NewQueryWithoutRecordingRuleAnalyzer())
	registry.Register(analyzer.NewDuplicateQueryAnalyzer())
	registry.Register(analyzer.NewDuplicateObservabilityQueryAnalyzer())
	registry.Register(analyzer.NewDuplicateMetricAnalyzer())
	registry.Register(analyzer.NewInvalidDatasourceAnalyzer())
	registry.Register(analyzer.NewHighImpactDatasourceAnalyzer())
	registry.Register(analyzer.NewMissingDatasourceTypeAnalyzer())
	registry.Register(analyzer.NewInvalidDatasourceTypeAnalyzer())
	registry.Register(analyzer.NewPublicDatasourceAnalyzer())
	registry.Register(analyzer.NewInsecureDatasourceAnalyzer())
	registry.Register(analyzer.NewDirectDatasourceAccessAnalyzer())
	registry.Register(analyzer.NewMutableDatasourceAnalyzer())
	registry.Register(analyzer.NewBasicAuthHTTPDatasourceAnalyzer())
	registry.Register(analyzer.NewMultipleDefaultDatasourceAnalyzer())
	registry.Register(analyzer.NewSensitiveLabelAnalyzer())
	registry.Register(analyzer.NewMissingOwnerAnalyzer())
	registry.Register(analyzer.NewStaleResourceAnalyzer())
	registry.Register(analyzer.NewOldResourceAnalyzer())
	registry.Register(analyzer.NewStaleUpdateAnalyzer())
	registry.Register(analyzer.NewLongFiringAlertAnalyzer())
	registry.Register(analyzer.NewStaleAlertUpdateAnalyzer())
	registry.Register(analyzer.NewExpiredActiveAlertAnalyzer())
	registry.Register(analyzer.NewSlowRuleEvaluationAnalyzer())
	registry.Register(analyzer.NewStaleRuleEvaluationAnalyzer())
	registry.Register(analyzer.NewSuppressedAlertAnalyzer())
	registry.Register(analyzer.NewAlertWithoutReceiverAnalyzer())
	registry.Register(analyzer.NewBlackholeReceiverAnalyzer())
	registry.Register(analyzer.NewUnusedReceiverAnalyzer())
	registry.Register(analyzer.NewReceiverWithoutIntegrationAnalyzer())
	registry.Register(analyzer.NewUndefinedReceiverAnalyzer())
	registry.Register(analyzer.NewAlertWithoutGeneratorURLAnalyzer())
	registry.Register(analyzer.NewRequiredLabelsAnalyzer())
	registry.Register(analyzer.NewMissingSeverityLabelAnalyzer())
	registry.Register(analyzer.NewInvalidSeverityLabelAnalyzer())
	registry.Register(analyzer.NewMissingRunbookAnalyzer())
	registry.Register(analyzer.NewInvalidRunbookURLAnalyzer())
	registry.Register(analyzer.NewMissingAlertDurationAnalyzer())
	registry.Register(analyzer.NewInvalidAlertDurationAnalyzer())
	registry.Register(analyzer.NewUnsafeAlertStateHandlingAnalyzer())
	registry.Register(analyzer.NewNoActiveAlertInstanceAnalyzer())
	registry.Register(analyzer.NewRuleEngineAnalyzer(nil))

	engine := NewEngine(
		store,
		[]connector.Connector{connector.NewSampleConnector()},
		registry,
		logger.New(io.Discard, "error"),
	)

	result, err := engine.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if result.FindingCount != 16 {
		t.Fatalf("expected 16 findings, got %d", result.FindingCount)
	}
	executions, err := store.Executions.List(ctx)
	if err != nil {
		t.Fatalf("list executions: %v", err)
	}
	if len(executions) != 1 {
		t.Fatalf("expected 1 execution result, got %d", len(executions))
	}

	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 8 {
		t.Fatalf("expected 8 resources, got %d", len(resources))
	}
	serviceID := ""
	for _, resource := range resources {
		if resource.Type == model.ResourceTypeService && resource.Name == "api" {
			serviceID = resource.ID
			break
		}
	}
	if serviceID == "" {
		t.Fatalf("expected derived api service resource")
	}
	relationships, err := store.Relationships.List(ctx)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	var serviceRelationshipCount int
	for _, relationship := range relationships {
		if relationship.Type == model.RelationshipBelongsTo && relationship.ToID == serviceID {
			serviceRelationshipCount++
		}
	}
	if serviceRelationshipCount != 4 {
		t.Fatalf("expected 4 service relationships, got %d", serviceRelationshipCount)
	}
	statuses := engine.ConnectorStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 connector status, got %d", len(statuses))
	}
	if statuses[0].Status != model.ExecutionStatusSucceeded {
		t.Fatalf("expected connector status %s, got %s", model.ExecutionStatusSucceeded, statuses[0].Status)
	}
	if statuses[0].ResourceCount != 8 {
		t.Fatalf("expected connector resource count 8, got %d", statuses[0].ResourceCount)
	}

	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != result.FindingCount {
		t.Fatalf("expected %d findings, got %d", result.FindingCount, len(findings))
	}
	for _, finding := range findings {
		if finding.Category == "" {
			t.Fatalf("expected finding %s to have category", finding.ID)
		}
	}
	configurationFindings, err := store.Findings.List(ctx, storage.FindingFilter{Category: model.FindingCategoryConfiguration})
	if err != nil {
		t.Fatalf("list configuration findings: %v", err)
	}
	if len(configurationFindings) == 0 {
		t.Fatalf("expected at least one configuration finding")
	}

	singleResult, err := engine.RunAnalyzer(ctx, analyzer.UnusedMetricAnalyzerID)
	if err != nil {
		t.Fatalf("run single analyzer: %v", err)
	}
	if len(singleResult.AnalyzerIDs) != 1 || singleResult.AnalyzerIDs[0] != analyzer.UnusedMetricAnalyzerID {
		t.Fatalf("expected single analyzer id %s, got %#v", analyzer.UnusedMetricAnalyzerID, singleResult.AnalyzerIDs)
	}
	if singleResult.FindingCount == 0 {
		t.Fatalf("expected single analyzer to produce findings")
	}
}

func TestEngineRejectsInvalidConnectorSnapshot(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	registry := analyzer.NewRegistry()
	engine := NewEngine(
		store,
		[]connector.Connector{invalidSnapshotConnector{}},
		registry,
		logger.New(io.Discard, "error"),
	)

	err := engine.Sync(ctx)
	if err == nil {
		t.Fatalf("expected invalid connector snapshot to fail")
	}
	resources, listErr := store.Resources.List(ctx, storage.ResourceFilter{})
	if listErr != nil {
		t.Fatalf("list resources: %v", listErr)
	}
	if len(resources) != 0 {
		t.Fatalf("expected invalid snapshot not to persist resources, got %d", len(resources))
	}
	statuses := engine.ConnectorStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected one connector status, got %d", len(statuses))
	}
	if statuses[0].Status != model.ExecutionStatusFailed {
		t.Fatalf("expected failed connector status, got %s", statuses[0].Status)
	}
	if len(statuses[0].Diagnostics) != 1 || statuses[0].Diagnostics[0].ID != "data_flow_contract" {
		t.Fatalf("expected data-flow diagnostic, got %#v", statuses[0].Diagnostics)
	}
}

func TestEngineReconcilesMissingResourcesAndRestoresThem(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	metric := connectorOwnedTestResource("prometheus", "metric:requests", model.ResourceTypeMetric)
	metric.Labels[model.MetadataService] = "payments"
	connectorSequence := &sequenceConnector{
		id: "prometheus",
		snapshots: []connector.Snapshot{
			{Resources: []model.Resource{metric}},
			{},
			{Resources: []model.Resource{metric}},
		},
	}
	engine := NewEngine(store, []connector.Connector{connectorSequence}, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	stored, ok, err := store.Resources.Get(ctx, metric.ID)
	if err != nil || !ok {
		t.Fatalf("get initial metric: found=%v err=%v", ok, err)
	}
	if stored.Metadata[model.MetadataConnectorID] != "prometheus" || stored.Metadata[model.MetadataConnectorLastSeenAt] == "" {
		t.Fatalf("expected connector ownership metadata, got %#v", stored.Metadata)
	}
	if stored.Metadata[model.MetadataConnectorSnapshotID] == "" ||
		stored.Metadata[model.MetadataConnectorSnapshotCompleteness] != "complete" ||
		stored.Metadata[model.MetadataConnectorSnapshotCompletedAt] == "" {
		t.Fatalf("expected complete snapshot evidence, got %#v", stored.Metadata)
	}
	service := derivedService(t, ctx, store, "payments")
	if service.Status != model.ResourceStatusActive {
		t.Fatalf("expected active derived service, got %s", service.Status)
	}

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("empty successful sync: %v", err)
	}
	stored, ok, err = store.Resources.Get(ctx, metric.ID)
	if err != nil || !ok || stored.Status != model.ResourceStatusOrphan {
		t.Fatalf("expected missing metric to become orphan, got %#v found=%v err=%v", stored, ok, err)
	}
	if stored.Metadata[model.MetadataConnectorOrphanedAt] == "" {
		t.Fatalf("expected orphan timestamp metadata, got %#v", stored.Metadata)
	}
	if stored.Metadata[model.MetadataConnectorOrphanedSnapshotID] == "" ||
		stored.Metadata[model.MetadataConnectorOrphanedSnapshotComplete] != "true" {
		t.Fatalf("expected complete tombstone evidence, got %#v", stored.Metadata)
	}
	service = derivedService(t, ctx, store, "payments")
	if service.Status != model.ResourceStatusOrphan {
		t.Fatalf("expected derived service without active resources to become orphan, got %s", service.Status)
	}
	relationships, err := store.Relationships.List(ctx)
	if err != nil {
		t.Fatalf("list reconciled relationships: %v", err)
	}
	if len(relationships) != 0 {
		t.Fatalf("expected stale relationships to be removed, got %#v", relationships)
	}
	status := engine.ConnectorStatuses()[0]
	if status.OrphanedCount != 1 || status.RemovedRelationCount != 1 {
		t.Fatalf("expected reconciliation counts, got %#v", status)
	}

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("recovery sync: %v", err)
	}
	stored, ok, err = store.Resources.Get(ctx, metric.ID)
	if err != nil || !ok || stored.Status != model.ResourceStatusActive {
		t.Fatalf("expected recovered metric to become active, got %#v found=%v err=%v", stored, ok, err)
	}
	if stored.Metadata[model.MetadataConnectorOrphanedAt] != "" {
		t.Fatalf("expected orphan timestamp to be cleared on recovery, got %#v", stored.Metadata)
	}
	if stored.Metadata[model.MetadataConnectorOrphanedSnapshotID] != "" ||
		stored.Metadata[model.MetadataConnectorOrphanedSnapshotComplete] != "" {
		t.Fatalf("expected tombstone evidence to be cleared on recovery, got %#v", stored.Metadata)
	}
	service = derivedService(t, ctx, store, "payments")
	if service.Status != model.ResourceStatusActive {
		t.Fatalf("expected recovered derived service to become active, got %s", service.Status)
	}
}

func TestEnginePreservesPartialConnectorDiagnostics(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	metric := connectorOwnedTestResource("partial", "metric:requests", model.ResourceTypeMetric)
	retainedMetric := connectorOwnedTestResource("partial", "metric:retained", model.ResourceTypeMetric)
	connectorSequence := &sequenceConnector{
		id: "partial",
		snapshots: []connector.Snapshot{{Resources: []model.Resource{metric, retainedMetric}}, {
			Resources: []model.Resource{metric},
			Diagnostics: []model.Diagnostic{{
				ID:      "optional_catalog",
				Name:    "Optional catalog",
				Status:  model.ExecutionStatusWarning,
				Message: "optional catalog unavailable",
			}},
			Partial: true,
		}},
	}
	engine := NewEngine(store, []connector.Connector{connectorSequence}, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("complete connector sync: %v", err)
	}
	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("partial connector sync should persist valid data: %v", err)
	}
	statuses := engine.ConnectorStatuses()
	if len(statuses) != 1 || statuses[0].Status != model.ExecutionStatusWarning {
		t.Fatalf("expected warning connector status, got %#v", statuses)
	}
	if len(statuses[0].Diagnostics) != 2 || statuses[0].Diagnostics[0].ID != "optional_catalog" || statuses[0].Diagnostics[1].ID != "data_flow_contract" {
		t.Fatalf("expected connector and contract diagnostics, got %#v", statuses[0].Diagnostics)
	}
	if _, found, err := store.Resources.Get(ctx, metric.ID); err != nil || !found {
		t.Fatalf("expected partial connector resources to persist, found=%v err=%v", found, err)
	}
	storedRetainedMetric, found, err := store.Resources.Get(ctx, retainedMetric.ID)
	if err != nil || !found {
		t.Fatalf("expected resource missing from partial snapshot to be retained, found=%v err=%v", found, err)
	}
	if storedRetainedMetric.Status == model.ResourceStatusOrphan {
		t.Fatalf("expected partial snapshot to skip orphan reconciliation")
	}
	if storedRetainedMetric.Metadata[model.MetadataConnectorOrphanedSnapshotID] != "" ||
		storedRetainedMetric.Metadata[model.MetadataConnectorOrphanedSnapshotComplete] != "" {
		t.Fatalf("partial snapshot must not create tombstone evidence, got %#v", storedRetainedMetric.Metadata)
	}
	storedMetric, found, err := store.Resources.Get(ctx, metric.ID)
	if err != nil || !found {
		t.Fatalf("expected resource observed in partial snapshot, found=%v err=%v", found, err)
	}
	if storedMetric.Metadata[model.MetadataConnectorSnapshotCompleteness] != "partial" {
		t.Fatalf("expected observed resource to retain partial snapshot provenance, got %#v", storedMetric.Metadata)
	}
}

func TestEngineOrphanedResourceFindingFollowsReconciliationLifecycle(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := connectorOwnedTestResource("prometheus", "metric:temporary", model.ResourceTypeMetric)
	connectorSequence := &sequenceConnector{id: "prometheus", snapshots: []connector.Snapshot{{Resources: []model.Resource{resource}}, {}, {Resources: []model.Resource{resource}}}}
	registry := analyzer.NewRegistry()
	registry.Register(analyzer.NewOrphanedResourceAnalyzer())
	engine := NewEngine(store, []connector.Connector{connectorSequence}, registry, logger.New(io.Discard, "error"))

	result, err := engine.Bootstrap(ctx)
	if err != nil || result.FindingCount != 0 {
		t.Fatalf("expected no finding while resource is present, result=%#v err=%v", result, err)
	}
	result, err = engine.Bootstrap(ctx)
	if err != nil || result.FindingCount != 1 {
		t.Fatalf("expected orphan finding after disappearance, result=%#v err=%v", result, err)
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{AnalyzerID: analyzer.OrphanedResourceAnalyzerID})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != resource.ID {
		t.Fatalf("expected persisted orphan finding, findings=%#v err=%v", findings, err)
	}
	result, err = engine.Bootstrap(ctx)
	if err != nil || result.FindingCount != 0 {
		t.Fatalf("expected finding to resolve after resource recovery, result=%#v err=%v", result, err)
	}
	findings, err = store.Findings.List(ctx, storage.FindingFilter{AnalyzerID: analyzer.OrphanedResourceAnalyzerID, Status: model.FindingStatusOpen})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected no open orphan finding after recovery, findings=%#v err=%v", findings, err)
	}
}

func TestEngineOTelRuntimeCounterFindingFollowsSuccessfulScrapeDelta(t *testing.T) {
	ctx := context.Background()
	var scraperErrors atomic.Int64
	scraperErrors.Store(12)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w,
			"# TYPE otelcol_scraper_errored_metric_points_total counter\notelcol_scraper_errored_metric_points_total %d\n",
			scraperErrors.Load(),
		)
	}))
	defer server.Close()
	configPath := t.TempDir() + "/otelcol.yaml"
	if err := os.WriteFile(configPath, []byte("service:\n  pipelines: {}\n"), 0o600); err != nil {
		t.Fatalf("write Collector config: %v", err)
	}
	otelConnector, err := connector.NewOpenTelemetryCollectorConnectorWithTelemetryOptions(
		configPath, "", server.URL, "", connector.HTTPOptions{},
	)
	if err != nil {
		t.Fatalf("create Collector connector: %v", err)
	}
	registry := analyzer.NewRegistry()
	registry.Register(analyzer.NewOTelScraperErrorsAnalyzer())
	store := storage.NewMemoryStore()
	engine := NewEngine(store, []connector.Connector{otelConnector}, registry, logger.New(io.Discard, "error"))

	first, err := engine.Bootstrap(ctx)
	if err != nil || first.FindingCount != 1 {
		t.Fatalf("expected first cumulative sample to find existing errors, result=%#v err=%v", first, err)
	}
	second, err := engine.Bootstrap(ctx)
	if err != nil || second.FindingCount != 0 {
		t.Fatalf("expected unchanged cumulative counter to resolve finding, result=%#v err=%v", second, err)
	}
	openFindings, err := store.Findings.List(ctx, storage.FindingFilter{
		AnalyzerID: analyzer.OTelScraperErrorsAnalyzerID,
		Status:     model.FindingStatusOpen,
	})
	if err != nil || len(openFindings) != 0 {
		t.Fatalf("expected no open finding after stable scrape, findings=%#v err=%v", openFindings, err)
	}

	scraperErrors.Store(15)
	third, err := engine.Bootstrap(ctx)
	if err != nil || third.FindingCount != 1 {
		t.Fatalf("expected counter growth to reopen finding, result=%#v err=%v", third, err)
	}
	openFindings, err = store.Findings.List(ctx, storage.FindingFilter{
		AnalyzerID: analyzer.OTelScraperErrorsAnalyzerID,
		Status:     model.FindingStatusOpen,
	})
	if err != nil || len(openFindings) != 1 ||
		openFindings[0].Metadata["counter_evidence"] != "delta" ||
		openFindings[0].Metadata["counter_delta"] != "3" ||
		!strings.Contains(openFindings[0].Evidence[0], "increased by 3") {
		t.Fatalf("unexpected reopened delta finding: findings=%#v err=%v", openFindings, err)
	}
}

func TestEngineReconciliationIsIsolatedByConnector(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	alphaResource := connectorOwnedTestResource("alpha", "metric:alpha", model.ResourceTypeMetric)
	betaResource := connectorOwnedTestResource("beta", "metric:beta", model.ResourceTypeMetric)
	alpha := &sequenceConnector{id: "alpha", snapshots: []connector.Snapshot{{Resources: []model.Resource{alphaResource}}, {}}}
	beta := &sequenceConnector{id: "beta", snapshots: []connector.Snapshot{{Resources: []model.Resource{betaResource}}}}
	engine := NewEngine(store, []connector.Connector{alpha, beta}, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("initial multi-connector sync: %v", err)
	}
	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("second multi-connector sync: %v", err)
	}
	alphaStored, _, _ := store.Resources.Get(ctx, alphaResource.ID)
	betaStored, _, _ := store.Resources.Get(ctx, betaResource.ID)
	if alphaStored.Status != model.ResourceStatusOrphan {
		t.Fatalf("expected alpha resource to become orphan, got %s", alphaStored.Status)
	}
	if betaStored.Status != model.ResourceStatusActive {
		t.Fatalf("expected beta resource to remain active, got %s", betaStored.Status)
	}
}

func TestEngineContinuesAfterConnectorFailureWithoutReconcilingFailedConnector(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	flakyResource := connectorOwnedTestResource("flaky", "metric:flaky", model.ResourceTypeMetric)
	healthyResource := connectorOwnedTestResource("healthy", "metric:healthy", model.ResourceTypeMetric)
	flaky := &sequenceConnector{
		id:        "flaky",
		snapshots: []connector.Snapshot{{Resources: []model.Resource{flakyResource}}},
		errors:    []error{nil, errors.New("upstream unavailable")},
	}
	healthy := &sequenceConnector{id: "healthy", snapshots: []connector.Snapshot{{Resources: []model.Resource{healthyResource}}}}
	engine := NewEngine(store, []connector.Connector{flaky, healthy}, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	err := engine.Sync(ctx)
	if err == nil {
		t.Fatalf("expected aggregate sync error from flaky connector")
	}
	var connectorSyncError *ConnectorSyncError
	if !errors.As(err, &connectorSyncError) {
		t.Fatalf("expected typed connector sync error, got %T: %v", err, err)
	}
	flakyStored, _, _ := store.Resources.Get(ctx, flakyResource.ID)
	healthyStored, healthyFound, healthyErr := store.Resources.Get(ctx, healthyResource.ID)
	if flakyStored.Status != model.ResourceStatusActive {
		t.Fatalf("failed connector must preserve previous active state, got %s", flakyStored.Status)
	}
	if healthyErr != nil || !healthyFound || healthyStored.Status != model.ResourceStatusActive || healthy.calls != 2 {
		t.Fatalf("expected healthy connector to continue syncing, resource=%#v found=%v err=%v calls=%d", healthyStored, healthyFound, healthyErr, healthy.calls)
	}
	statuses := engine.ConnectorStatuses()
	if len(statuses) != 2 || statuses[0].ID != "flaky" || statuses[0].Status != model.ExecutionStatusFailed || statuses[1].ID != "healthy" || statuses[1].Status != model.ExecutionStatusSucceeded {
		t.Fatalf("unexpected connector statuses: %#v", statuses)
	}
}

func TestEngineBoundsConcurrentConnectorFetchAndCommitsInConfiguredOrder(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	var active atomic.Int32
	var maximum atomic.Int32

	alphaResource := connectorOwnedTestResource("alpha", "metric:shared", model.ResourceTypeMetric)
	alphaResource.ID = "shared-resource"
	alphaResource.UID = "shared-resource"
	alphaResource.Name = "alpha version"
	betaResource := alphaResource
	betaResource.Name = "beta version"
	betaResource.Source.System = "beta"
	gammaResource := connectorOwnedTestResource("gamma", "metric:gamma", model.ResourceTypeMetric)

	connectors := []connector.Connector{
		&controlledConnector{id: "alpha", delay: 80 * time.Millisecond, active: &active, maximum: &maximum, snapshot: connector.Snapshot{Resources: []model.Resource{alphaResource}}},
		&controlledConnector{id: "beta", delay: 5 * time.Millisecond, active: &active, maximum: &maximum, snapshot: connector.Snapshot{Resources: []model.Resource{betaResource}}},
		&controlledConnector{id: "gamma", delay: 20 * time.Millisecond, active: &active, maximum: &maximum, snapshot: connector.Snapshot{Resources: []model.Resource{gammaResource}}},
	}
	engine := NewEngine(store, connectors, analyzer.NewRegistry(), logger.New(io.Discard, "error"))
	engine.SetWorkerLimits(2, DefaultAnalyzerWorkers)

	if err := engine.Sync(ctx); err != nil {
		t.Fatalf("concurrent connector sync: %v", err)
	}
	if maximum.Load() != 2 {
		t.Fatalf("expected connector concurrency to be bounded at two, got %d", maximum.Load())
	}
	stored, found, err := store.Resources.Get(ctx, alphaResource.ID)
	if err != nil || !found {
		t.Fatalf("get shared resource: found=%v err=%v", found, err)
	}
	if stored.Name != betaResource.Name || stored.Metadata[model.MetadataConnectorID] != "beta" {
		t.Fatalf("expected configured commit order to leave beta version, got %#v", stored)
	}
	statuses := engine.ConnectorStatuses()
	if len(statuses) != 3 || statuses[0].ID != "alpha" || statuses[1].ID != "beta" || statuses[2].ID != "gamma" {
		t.Fatalf("expected stable connector statuses, got %#v", statuses)
	}
}

func TestEngineIsolatesConnectorPanicAndCommitsHealthySnapshot(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	healthyResource := connectorOwnedTestResource("healthy", "metric:healthy", model.ResourceTypeMetric)
	engine := NewEngine(store, []connector.Connector{
		&controlledConnector{id: "panic", panicValue: "broken parser"},
		&controlledConnector{id: "healthy", snapshot: connector.Snapshot{Resources: []model.Resource{healthyResource}}},
	}, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	err := engine.Sync(ctx)
	if err == nil || !strings.Contains(err.Error(), "connector panic: broken parser") {
		t.Fatalf("expected isolated connector panic error, got %v", err)
	}
	if _, found, getErr := store.Resources.Get(ctx, healthyResource.ID); getErr != nil || !found {
		t.Fatalf("expected healthy connector snapshot to persist, found=%v err=%v", found, getErr)
	}
	statuses := engine.ConnectorStatuses()
	if len(statuses) != 2 || statuses[0].ID != "healthy" || statuses[0].Status != model.ExecutionStatusSucceeded ||
		statuses[1].ID != "panic" || statuses[1].Status != model.ExecutionStatusFailed ||
		!strings.Contains(statuses[1].Error, "connector panic") {
		t.Fatalf("unexpected panic isolation statuses: %#v", statuses)
	}
}

func TestEngineSerializesOverlappingSyncRuns(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	var active atomic.Int32
	var maximum atomic.Int32
	controlled := &controlledConnector{
		id:      "serialized",
		delay:   40 * time.Millisecond,
		active:  &active,
		maximum: &maximum,
	}
	engine := NewEngine(store, []connector.Connector{controlled}, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	var runs sync.WaitGroup
	errorsByRun := make(chan error, 2)
	runs.Add(2)
	for run := 0; run < 2; run++ {
		go func() {
			defer runs.Done()
			errorsByRun <- engine.Sync(ctx)
		}()
	}
	runs.Wait()
	close(errorsByRun)
	for err := range errorsByRun {
		if err != nil {
			t.Fatalf("serialized sync: %v", err)
		}
	}
	if maximum.Load() != 1 || controlled.calls.Load() != 2 {
		t.Fatalf("expected two serialized runs, max_active=%d calls=%d", maximum.Load(), controlled.calls.Load())
	}
}

func TestEngineBoundsConcurrentAnalyzersAndIsolatesPanic(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	var active atomic.Int32
	var maximum atomic.Int32
	registry := analyzer.NewRegistry()
	registry.Register(&controlledAnalyzer{id: "alpha", delay: 80 * time.Millisecond, active: &active, maximum: &maximum})
	registry.Register(&controlledAnalyzer{id: "beta", delay: 5 * time.Millisecond, active: &active, maximum: &maximum, panicValue: "broken analyzer"})
	registry.Register(&controlledAnalyzer{id: "gamma", delay: 20 * time.Millisecond, active: &active, maximum: &maximum})

	retained := model.Finding{
		ID:       "beta-retained",
		Type:     "RetainedAnalyzerFinding",
		Severity: model.SeverityWarning,
		Resource: model.ResourceRef{ID: "resource", Type: model.ResourceTypeMetric, Name: "resource"},
		Evidence: []string{"previous successful analyzer result"},
		Metadata: map[string]string{"analyzer_id": "beta"},
		Status:   model.FindingStatusOpen,
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "beta", []model.Finding{retained}); err != nil {
		t.Fatalf("seed retained finding: %v", err)
	}

	engine := NewEngine(store, nil, registry, logger.New(io.Discard, "error"))
	engine.SetWorkerLimits(DefaultConnectorSyncWorkers, 2)
	result, err := engine.RunAnalyzers(ctx)
	if err == nil || !strings.Contains(err.Error(), "run analyzer beta: analyzer panic: broken analyzer") {
		t.Fatalf("expected isolated analyzer panic, got result=%#v err=%v", result, err)
	}
	if maximum.Load() != 2 {
		t.Fatalf("expected analyzer concurrency to be bounded at two, got %d", maximum.Load())
	}
	if result.Status != model.ExecutionStatusFailed ||
		len(result.AnalyzerIDs) != 2 ||
		result.AnalyzerIDs[0] != "alpha" ||
		result.AnalyzerIDs[1] != "gamma" {
		t.Fatalf("expected deterministic successful analyzer IDs, got %#v", result)
	}
	if stored, found, getErr := store.Findings.Get(ctx, retained.ID); getErr != nil || !found || stored.Status != model.FindingStatusOpen {
		t.Fatalf("expected failed analyzer's previous finding to remain, finding=%#v found=%v err=%v", stored, found, getErr)
	}
}

func TestEngineNormalizesBuiltInPresentationAndPreservesRuleEngineLanguage(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	registry := analyzer.NewRegistry()
	registry.Register(&controlledAnalyzer{id: "builtin.localized", findings: []model.Finding{{
		ID: "builtin-finding", Type: "KubernetesUnknownOperatorCondition", Severity: model.SeverityWarning,
		Category: model.FindingCategoryConfiguration,
		Resource: model.ResourceRef{ID: "prometheus-main", Type: model.ResourceTypeTSDB, Name: "main"},
		Evidence: []string{"内置证据。"}, Recommendation: "修复 Kubernetes 配置。",
	}}})
	registry.Register(&controlledAnalyzer{id: "builtin.rule_engine", findings: []model.Finding{{
		ID: "custom-finding", Type: "CustomPolicy", Severity: model.SeverityWarning,
		Category: model.FindingCategoryQuality,
		Resource: model.ResourceRef{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api"},
		Evidence: []string{"保留用户证据。"}, Recommendation: "保留用户建议。",
	}}})
	engine := NewEngine(store, nil, registry, logger.New(io.Discard, "error"))
	if _, err := engine.RunAnalyzers(ctx); err != nil {
		t.Fatal(err)
	}
	builtIn, found, err := store.Findings.Get(ctx, "builtin-finding")
	if err != nil || !found || strings.Contains(strings.Join(builtIn.Evidence, " ")+builtIn.Recommendation, "内置") || !strings.Contains(builtIn.Recommendation, "Kubernetes manifest") {
		t.Fatalf("built-in presentation was not normalized before storage: %#v found=%v err=%v", builtIn, found, err)
	}
	custom, found, err := store.Findings.Get(ctx, "custom-finding")
	if err != nil || !found || custom.Evidence[0] != "保留用户证据。" || custom.Recommendation != "保留用户建议。" {
		t.Fatalf("user-authored Rule Engine presentation changed: %#v found=%v err=%v", custom, found, err)
	}
}

func TestEngineReappliesAndExpiresDurableWaivers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	analyzerID := "controlled.waiver"
	finding := model.Finding{
		ID:             "waived-finding",
		Type:           "ControlledFinding",
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategoryConfiguration,
		Resource:       model.ResourceRef{ID: "resource-1", Type: model.ResourceTypeMetric, Name: "resource"},
		Evidence:       []string{"controlled evidence"},
		Recommendation: "controlled recommendation",
		Metadata:       map[string]string{"analyzer_id": analyzerID},
		Status:         model.FindingStatusOpen,
	}
	registry := analyzer.NewRegistry()
	registry.Register(&controlledAnalyzer{id: analyzerID, findings: []model.Finding{finding}})
	now := time.Now().UTC()
	waiver := model.Waiver{
		ID:         "waiver-1",
		Scope:      model.WaiverScopeAnalyzer,
		ScopeValue: analyzerID,
		Owner:      "platform",
		Reason:     "migration",
		CreatedBy:  "alice",
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := store.Waivers.Save(ctx, waiver); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, nil, registry, logger.New(io.Discard, "error"))
	for run := 0; run < 2; run++ {
		if _, err := engine.RunAnalyzer(ctx, analyzerID); err != nil {
			t.Fatalf("run analyzer %d: %v", run, err)
		}
		stored, found, err := store.Findings.Get(ctx, finding.ID)
		if err != nil || !found || stored.Status != model.FindingStatusWaived || stored.Metadata["waiver.id"] != waiver.ID {
			t.Fatalf("expected waiver after analyzer run %d, finding=%#v found=%v err=%v", run, stored, found, err)
		}
	}
	if _, found, err := store.Waivers.Revoke(ctx, waiver.ID, now.Add(time.Minute), "bob", "migration complete"); err != nil || !found {
		t.Fatalf("revoke waiver: found=%v err=%v", found, err)
	}
	if _, err := engine.RunAnalyzer(ctx, analyzerID); err != nil {
		t.Fatal(err)
	}
	stored, found, err := store.Findings.Get(ctx, finding.ID)
	if err != nil || !found || stored.Status != model.FindingStatusOpen || stored.Metadata["waiver.id"] != "" {
		t.Fatalf("expected revoked waiver to reopen analyzer output, finding=%#v found=%v err=%v", stored, found, err)
	}
}

func TestEngineSerializesOverlappingAnalyzerRuns(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	var active atomic.Int32
	var maximum atomic.Int32
	controlled := &controlledAnalyzer{
		id:      "serialized.analyzer",
		delay:   40 * time.Millisecond,
		active:  &active,
		maximum: &maximum,
	}
	registry := analyzer.NewRegistry()
	registry.Register(controlled)
	engine := NewEngine(store, nil, registry, logger.New(io.Discard, "error"))

	var runs sync.WaitGroup
	errorsByRun := make(chan error, 2)
	runs.Add(2)
	go func() {
		defer runs.Done()
		_, err := engine.RunAnalyzers(ctx)
		errorsByRun <- err
	}()
	go func() {
		defer runs.Done()
		_, err := engine.RunAnalyzer(ctx, controlled.ID())
		errorsByRun <- err
	}()
	runs.Wait()
	close(errorsByRun)
	for err := range errorsByRun {
		if err != nil {
			t.Fatalf("serialized analyzer run: %v", err)
		}
	}
	if maximum.Load() != 1 || controlled.calls.Load() != 2 {
		t.Fatalf("expected two serialized analyzer runs, max_active=%d calls=%d", maximum.Load(), controlled.calls.Load())
	}
}

type sequenceConnector struct {
	id        string
	snapshots []connector.Snapshot
	errors    []error
	calls     int
}

func (c *sequenceConnector) ID() string   { return c.id }
func (c *sequenceConnector) Name() string { return c.id + " connector" }

func (c *sequenceConnector) Sync(context.Context) (connector.Snapshot, error) {
	index := c.calls
	c.calls++
	if index < len(c.errors) && c.errors[index] != nil {
		return connector.Snapshot{}, c.errors[index]
	}
	if len(c.snapshots) == 0 {
		return connector.Snapshot{}, nil
	}
	if index >= len(c.snapshots) {
		index = len(c.snapshots) - 1
	}
	return c.snapshots[index], nil
}

func TestEngineTracksFindingOccurrenceLifecycle(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	analyzerID := "controlled.occurrence"
	finding := model.Finding{
		ID: "recurring-finding", Type: "RecurringFinding", Severity: model.SeverityWarning,
		Category: model.FindingCategoryReliability,
		Resource: model.ResourceRef{ID: "target-1", Type: model.ResourceTypeTarget, Name: "target"},
		Evidence: []string{"controlled evidence"},
		Metadata: map[string]string{"analyzer_id": analyzerID},
	}
	controlled := &controlledAnalyzer{id: analyzerID, findings: []model.Finding{finding}}
	registry := analyzer.NewRegistry()
	registry.Register(controlled)
	engine := NewEngine(store, nil, registry, logger.New(io.Discard, "error"))

	if _, err := engine.RunAnalyzer(ctx, analyzerID); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.RunAnalyzer(ctx, analyzerID); err != nil {
		t.Fatal(err)
	}
	record, found, err := store.FindingOccurrences.Get(ctx, finding.ID)
	if err != nil || !found || !record.Active || record.ObservationCount != 2 || record.ReopenCount != 0 {
		t.Fatalf("unexpected repeated occurrence %#v found=%v err=%v", record, found, err)
	}
	stored, found, err := store.Findings.Get(ctx, finding.ID)
	if err != nil || !found || stored.Occurrence == nil || stored.Occurrence.ObservationCount != 2 {
		t.Fatalf("expected occurrence on current finding, got %#v found=%v err=%v", stored, found, err)
	}

	controlled.findings = nil
	if _, err := engine.RunAnalyzer(ctx, analyzerID); err != nil {
		t.Fatal(err)
	}
	record, found, err = store.FindingOccurrences.Get(ctx, finding.ID)
	if err != nil || !found || record.Active || record.ResolvedAt == nil {
		t.Fatalf("expected resolved occurrence %#v found=%v err=%v", record, found, err)
	}

	controlled.findings = []model.Finding{finding}
	if _, err := engine.RunAnalyzer(ctx, analyzerID); err != nil {
		t.Fatal(err)
	}
	record, found, err = store.FindingOccurrences.Get(ctx, finding.ID)
	if err != nil || !found || !record.Active || record.ObservationCount != 3 || record.ReopenCount != 1 || record.ResolvedAt != nil {
		t.Fatalf("expected reopened occurrence %#v found=%v err=%v", record, found, err)
	}
}

type controlledConnector struct {
	id         string
	delay      time.Duration
	active     *atomic.Int32
	maximum    *atomic.Int32
	calls      atomic.Int32
	snapshot   connector.Snapshot
	err        error
	panicValue any
}

func (c *controlledConnector) ID() string   { return c.id }
func (c *controlledConnector) Name() string { return c.id + " connector" }

func (c *controlledConnector) Sync(context.Context) (connector.Snapshot, error) {
	c.calls.Add(1)
	if c.active != nil {
		current := c.active.Add(1)
		if c.maximum != nil {
			for {
				observed := c.maximum.Load()
				if current <= observed || c.maximum.CompareAndSwap(observed, current) {
					break
				}
			}
		}
		defer c.active.Add(-1)
	}
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	if c.panicValue != nil {
		panic(c.panicValue)
	}
	return c.snapshot, c.err
}

type controlledAnalyzer struct {
	id         string
	delay      time.Duration
	active     *atomic.Int32
	maximum    *atomic.Int32
	calls      atomic.Int32
	findings   []model.Finding
	err        error
	panicValue any
}

func (a *controlledAnalyzer) ID() string                       { return a.id }
func (a *controlledAnalyzer) Name() string                     { return a.id + " analyzer" }
func (a *controlledAnalyzer) Version() string                  { return "0.1.0" }
func (a *controlledAnalyzer) InputTypes() []model.ResourceType { return nil }

func (a *controlledAnalyzer) Execute(context.Context, analyzer.Context) ([]model.Finding, error) {
	a.calls.Add(1)
	if a.active != nil {
		current := a.active.Add(1)
		if a.maximum != nil {
			for {
				observed := a.maximum.Load()
				if current <= observed || a.maximum.CompareAndSwap(observed, current) {
					break
				}
			}
		}
		defer a.active.Add(-1)
	}
	if a.delay > 0 {
		time.Sleep(a.delay)
	}
	if a.panicValue != nil {
		panic(a.panicValue)
	}
	return a.findings, a.err
}

func connectorOwnedTestResource(system string, externalID string, resourceType model.ResourceType) model.Resource {
	id := model.StableID(string(resourceType), system, externalID)
	return model.Resource{
		ID: id, Type: resourceType, Name: externalID, UID: id,
		Source: model.SourceInfo{System: system, Instance: "test", ExternalID: externalID},
		Labels: map[string]string{}, Metadata: map[string]string{}, Status: model.ResourceStatusActive,
	}
}

func derivedService(t *testing.T, ctx context.Context, store *storage.Store, name string) model.Resource {
	t.Helper()
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	for _, resource := range resources {
		if resource.Name == name {
			return resource
		}
	}
	t.Fatalf("derived service %q not found", name)
	return model.Resource{}
}

func TestEnginePassesReportHistoryToTSDBGrowthAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{ID: "tsdb-growth", Type: model.ResourceTypeTSDB, Name: "prometheus TSDB", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "1300000", model.MetadataTSDBLabelMemoryBytes: "130000000"}}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert TSDB: %v", err)
	}
	if err := store.ReportExports.Save(ctx, model.ReportExport{ID: "cost-baseline", Type: "cost", Format: "json", CreatedAt: time.Now().UTC().Add(-time.Hour), Content: `{"tsdb_instances":[{"id":"tsdb-growth","head_series":1000000,"label_memory_bytes":100000000}]}`}); err != nil {
		t.Fatalf("save cost baseline: %v", err)
	}
	registry := analyzer.NewRegistry()
	registry.Register(analyzer.NewTSDBGrowthAnalyzer())
	engine := NewEngine(store, nil, registry, logger.New(io.Discard, "error"))
	result, err := engine.RunAnalyzer(ctx, analyzer.TSDBGrowthAnalyzerID)
	if err != nil {
		t.Fatalf("run TSDB growth analyzer: %v", err)
	}
	if result.FindingCount != 1 {
		t.Fatalf("expected TSDB growth finding through engine context, got %#v", result)
	}
}

type invalidSnapshotConnector struct{}

func TestEngineWorkerLimitsNormalizeAndUpdate(t *testing.T) {
	engine := NewEngine(storage.NewMemoryStore(), nil, analyzer.NewRegistry(), logger.New(io.Discard, "error"))

	engine.SetWorkerLimits(3, 5)
	connectorWorkers, analyzerWorkers := engine.WorkerLimits()
	if connectorWorkers != 3 || analyzerWorkers != 5 {
		t.Fatalf("unexpected worker limits: connector=%d analyzer=%d", connectorWorkers, analyzerWorkers)
	}

	engine.SetWorkerLimits(0, MaxAnalyzerWorkers+1)
	connectorWorkers, analyzerWorkers = engine.WorkerLimits()
	if connectorWorkers != DefaultConnectorSyncWorkers || analyzerWorkers != MaxAnalyzerWorkers {
		t.Fatalf("unexpected normalized worker limits: connector=%d analyzer=%d", connectorWorkers, analyzerWorkers)
	}
}

func (invalidSnapshotConnector) ID() string {
	return "invalid"
}

func (invalidSnapshotConnector) Name() string {
	return "Invalid Snapshot Connector"
}

func (invalidSnapshotConnector) Sync(ctx context.Context) (connector.Snapshot, error) {
	return connector.Snapshot{
		Resources: []model.Resource{
			{
				ID:     "metric-invalid",
				Type:   model.ResourceTypeMetric,
				Name:   "invalid_metric",
				Status: model.ResourceStatusActive,
			},
		},
	}, nil
}
