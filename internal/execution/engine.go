package execution

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"monicheck/internal/analyzer"
	connectorpkg "monicheck/internal/connector"
	"monicheck/internal/contract"
	"monicheck/internal/graph"
	"monicheck/internal/logger"
	"monicheck/internal/model"
	"monicheck/internal/occurrence"
	"monicheck/internal/risk"
	"monicheck/internal/storage"
	waiverpkg "monicheck/internal/waiver"
)

const (
	DefaultConnectorSyncWorkers = 4
	MaxConnectorSyncWorkers     = 16
	DefaultAnalyzerWorkers      = 8
	MaxAnalyzerWorkers          = 32
)

type Engine struct {
	store                *storage.Store
	syncMu               sync.Mutex
	analyzerRunMu        sync.Mutex
	connectorMu          sync.RWMutex
	connectors           []connectorpkg.Connector
	workerMu             sync.RWMutex
	connectorSyncWorkers int
	analyzers            *analyzer.Registry
	logger               logger.Logger
	configMu             sync.RWMutex
	config               map[string]any
	analyzerWorkers      int
	statusMu             sync.RWMutex
	statuses             map[string]model.ConnectorStatus
}

type ConnectorSyncError struct {
	err error
}

func (e *ConnectorSyncError) Error() string {
	return e.err.Error()
}

func (e *ConnectorSyncError) Unwrap() error {
	return e.err
}

func NewEngine(store *storage.Store, connectors []connectorpkg.Connector, analyzers *analyzer.Registry, logger logger.Logger) *Engine {
	return &Engine{
		store:                store,
		connectors:           connectors,
		connectorSyncWorkers: DefaultConnectorSyncWorkers,
		analyzers:            analyzers,
		logger:               logger,
		config:               map[string]any{},
		analyzerWorkers:      DefaultAnalyzerWorkers,
		statuses:             make(map[string]model.ConnectorStatus),
	}
}

func (e *Engine) SetWorkerLimits(connectorSyncWorkers, analyzerWorkers int) {
	e.workerMu.Lock()
	defer e.workerMu.Unlock()
	e.connectorSyncWorkers = normalizeWorkerLimit(connectorSyncWorkers, DefaultConnectorSyncWorkers, MaxConnectorSyncWorkers)
	e.analyzerWorkers = normalizeWorkerLimit(analyzerWorkers, DefaultAnalyzerWorkers, MaxAnalyzerWorkers)
}

func (e *Engine) WorkerLimits() (int, int) {
	e.workerMu.RLock()
	defer e.workerMu.RUnlock()
	return e.connectorSyncWorkers, e.analyzerWorkers
}

func normalizeWorkerLimit(value, fallback, maximum int) int {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func (e *Engine) SetAnalyzerConfig(config map[string]any) {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	e.config = cloneAnalyzerConfig(config)
}

func (e *Engine) UpdateAnalyzerConfig(updates map[string]any) {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	if e.config == nil {
		e.config = map[string]any{}
	}
	for key, value := range updates {
		e.config[key] = cloneAnalyzerConfigValue(value)
	}
}

func (e *Engine) SetConnectors(connectors []connectorpkg.Connector) {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()

	e.connectorMu.Lock()
	defer e.connectorMu.Unlock()
	e.connectors = connectors

	e.statusMu.Lock()
	defer e.statusMu.Unlock()
	e.statuses = make(map[string]model.ConnectorStatus)
}

func (e *Engine) ConnectorStatuses() []model.ConnectorStatus {
	e.statusMu.RLock()
	defer e.statusMu.RUnlock()

	statuses := make([]model.ConnectorStatus, 0, len(e.statuses))
	for _, status := range e.statuses {
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].ID < statuses[j].ID
	})
	return statuses
}

func (e *Engine) Sync(ctx context.Context) error {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()

	e.connectorMu.RLock()
	connectors := append([]connectorpkg.Connector(nil), e.connectors...)
	e.connectorMu.RUnlock()

	var syncErrors []error
	for _, result := range e.fetchConnectorSnapshots(ctx, connectors) {
		connector := result.connector
		startedAt := result.startedAt
		snapshot := result.snapshot
		err := result.err
		if err != nil {
			e.recordConnectorStatus(model.ConnectorStatus{
				ID:             connector.ID(),
				Name:           connector.Name(),
				Status:         model.ExecutionStatusFailed,
				LastStartedAt:  startedAt,
				LastFinishedAt: time.Now().UTC(),
				Error:          err.Error(),
			})
			syncErrors = append(syncErrors, fmt.Errorf("sync connector %s: %w", connector.ID(), err))
			continue
		}
		syncedAt := time.Now().UTC()
		snapshot = connectorpkg.EnrichBusinessServices(snapshot, syncedAt)
		validation := contract.ValidateSnapshot(snapshot)
		if !validation.Valid {
			finishedAt := time.Now().UTC()
			e.recordConnectorStatus(model.ConnectorStatus{
				ID:                connector.ID(),
				Name:              connector.Name(),
				Status:            model.ExecutionStatusFailed,
				ResourceCount:     len(snapshot.Resources),
				RelationshipCount: len(snapshot.Relationships),
				LastStartedAt:     startedAt,
				LastFinishedAt:    finishedAt,
				DurationMillis:    finishedAt.Sub(startedAt).Milliseconds(),
				Error:             fmt.Sprintf("data-flow contract validation failed with %d violations", len(validation.Violations)),
				Diagnostics:       appendSnapshotDiagnostics(snapshot.Diagnostics, contract.SnapshotDiagnostic(validation)),
			})
			syncErrors = append(syncErrors, fmt.Errorf("validate connector %s snapshot: %s", connector.ID(), validation.Violations[0].Message))
			continue
		}
		snapshotID := model.StableID("connector_snapshot", connector.ID(), syncedAt.Format(time.RFC3339Nano))
		snapshotComplete := !snapshot.Partial
		snapshot, resourceIDs, relationshipIDs := stampConnectorSnapshot(snapshot, connector.ID(), snapshotID, syncedAt, snapshotComplete)
		persistFailed := false
		for _, resource := range snapshot.Resources {
			if err := e.store.Resources.Upsert(ctx, resource); err != nil {
				syncErrors = append(syncErrors, fmt.Errorf("sync connector %s: upsert resource %s: %w", connector.ID(), resource.ID, err))
				persistFailed = true
				break
			}
		}
		if !persistFailed {
			for _, relationship := range snapshot.Relationships {
				if err := e.store.Relationships.Upsert(ctx, relationship); err != nil {
					syncErrors = append(syncErrors, fmt.Errorf("sync connector %s: upsert relationship %s: %w", connector.ID(), relationship.ID, err))
					persistFailed = true
					break
				}
			}
		}
		orphanedCount := 0
		removedRelationCount := 0
		if !persistFailed && !snapshot.Partial {
			orphanedCount, removedRelationCount, err = e.reconcileConnectorSnapshot(ctx, connector.ID(), snapshotID, resourceIDs, relationshipIDs, syncedAt)
			if err != nil {
				syncErrors = append(syncErrors, fmt.Errorf("sync connector %s: reconcile snapshot: %w", connector.ID(), err))
				persistFailed = true
			}
		}
		finishedAt := time.Now().UTC()
		if persistFailed {
			e.recordConnectorStatus(model.ConnectorStatus{
				ID: connector.ID(), Name: connector.Name(), Status: model.ExecutionStatusFailed,
				ResourceCount: len(snapshot.Resources), RelationshipCount: len(snapshot.Relationships),
				LastStartedAt: startedAt, LastFinishedAt: finishedAt,
				Error:       "snapshot persistence or reconciliation failed",
				Diagnostics: appendSnapshotDiagnostics(snapshot.Diagnostics, contract.SnapshotDiagnostic(validation)),
			})
			continue
		}
		connectorStatus := model.ExecutionStatusSucceeded
		if snapshot.Partial || diagnosticsHaveWarning(snapshot.Diagnostics) {
			connectorStatus = model.ExecutionStatusWarning
		}
		e.recordConnectorStatus(model.ConnectorStatus{
			ID:                   connector.ID(),
			Name:                 connector.Name(),
			Status:               connectorStatus,
			ResourceCount:        len(snapshot.Resources),
			RelationshipCount:    len(snapshot.Relationships),
			OrphanedCount:        orphanedCount,
			RemovedRelationCount: removedRelationCount,
			LastStartedAt:        startedAt,
			LastFinishedAt:       finishedAt,
			DurationMillis:       finishedAt.Sub(startedAt).Milliseconds(),
			Diagnostics:          appendSnapshotDiagnostics(snapshot.Diagnostics, contract.SnapshotDiagnostic(validation)),
		})
	}
	if err := e.reconcileDerivedServices(ctx); err != nil {
		syncErrors = append(syncErrors, fmt.Errorf("reconcile derived services: %w", err))
	}
	if err := e.reconcileKubernetesRuntimeCoverage(ctx); err != nil {
		syncErrors = append(syncErrors, fmt.Errorf("reconcile kubernetes runtime coverage: %w", err))
	}
	if err := errors.Join(syncErrors...); err != nil {
		return &ConnectorSyncError{err: err}
	}
	return nil
}

type connectorFetchResult struct {
	connector connectorpkg.Connector
	startedAt time.Time
	snapshot  connectorpkg.Snapshot
	err       error
}

func (e *Engine) fetchConnectorSnapshots(ctx context.Context, connectors []connectorpkg.Connector) []connectorFetchResult {
	results := make([]connectorFetchResult, len(connectors))
	if len(connectors) == 0 {
		return results
	}

	workerCount, _ := e.WorkerLimits()
	if workerCount > len(connectors) {
		workerCount = len(connectors)
	}
	e.logger.Info(ctx, "sync connector batch", "connector_count", len(connectors), "worker_count", workerCount)

	jobs := make(chan int, len(connectors))
	for index := range connectors {
		jobs <- index
	}
	close(jobs)

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				connector := connectors[index]
				e.logger.Info(ctx, "sync connector", "connector_id", connector.ID())
				results[index] = connectorFetchResult{
					connector: connector,
					startedAt: time.Now().UTC(),
				}
				results[index].snapshot, results[index].err = syncConnectorSafely(ctx, connector)
			}
		}()
	}
	workers.Wait()
	return results
}

func syncConnectorSafely(ctx context.Context, connector connectorpkg.Connector) (snapshot connectorpkg.Snapshot, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("connector panic: %v", recovered)
		}
	}()
	return connector.Sync(ctx)
}

func (e *Engine) reconcileKubernetesRuntimeCoverage(ctx context.Context) error {
	resources, err := e.store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return err
	}
	runtimeTSDBCount := 0
	runtimeDiscoveryComplete := true
	kubernetesPrometheusCount := 0
	runtimeTargets := map[string]int{}
	runtimeDroppedTargets := map[string]int{}
	runtimeEndpoints := map[string]map[int]bool{}
	runtimeEndpointUnknown := map[string]bool{}
	observedScopes := map[string]bool{}

	for _, resource := range resources {
		active := resource.Status == model.ResourceStatusActive
		if active && resource.Type == model.ResourceTypeTSDB && isPrometheusRuntimeSource(resource.Source.System) {
			runtimeTSDBCount++
			if resource.Metadata[model.MetadataTargetsDiscoveryAvailable] != "true" {
				runtimeDiscoveryComplete = false
			}
		}
		if active && resource.Type == model.ResourceTypeTSDB && resource.Source.System == "kubernetes" && isKubernetesPrometheusWorkloadKind(resource.Metadata["kubernetes_kind"]) {
			if count, parseErr := strconv.Atoi(strings.TrimSpace(resource.Metadata["prometheus_desired_pod_count"])); parseErr == nil && count > 0 {
				kubernetesPrometheusCount++
			}
		}
		if resource.Type != model.ResourceTypeTarget || !isPrometheusRuntimeSource(resource.Source.System) {
			continue
		}
		kind := strings.TrimSpace(resource.Metadata[model.MetadataOperatorMonitorKind])
		namespace := strings.TrimSpace(resource.Metadata[model.MetadataOperatorMonitorNamespace])
		name := strings.TrimSpace(resource.Metadata[model.MetadataOperatorMonitorName])
		if kind == "" || namespace == "" || name == "" {
			continue
		}
		coverageKey := kubernetesRuntimeCoverageKey(kind, namespace, name)
		if resource.Metadata[model.MetadataTargetState] == "dropped" {
			runtimeDroppedTargets[coverageKey]++
			observedScopes[kubernetesRuntimeCoverageScopeKey(kind, namespace)] = true
			continue
		}
		if !active {
			continue
		}
		runtimeTargets[coverageKey]++
		if kind == "ServiceMonitor" || kind == "PodMonitor" {
			endpoint, endpointErr := strconv.Atoi(strings.TrimSpace(resource.Metadata[model.MetadataOperatorMonitorEndpoint]))
			if endpointErr != nil || endpoint < 0 {
				runtimeEndpointUnknown[coverageKey] = true
			} else {
				if runtimeEndpoints[coverageKey] == nil {
					runtimeEndpoints[coverageKey] = map[int]bool{}
				}
				runtimeEndpoints[coverageKey][endpoint] = true
			}
		}
		observedScopes[kubernetesRuntimeCoverageScopeKey(kind, namespace)] = true
	}
	if runtimeTSDBCount == 0 {
		runtimeDiscoveryComplete = false
	}
	singletonScope := runtimeDiscoveryComplete && runtimeTSDBCount == 1 && kubernetesPrometheusCount == 1

	for _, resource := range resources {
		if resource.Type != model.ResourceTypeTarget || resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive {
			continue
		}
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		if !isKubernetesRuntimeCoverageKind(kind) || resource.Metadata["prometheus_selection_candidate"] != "true" {
			continue
		}
		resource.Metadata = copyMetadata(resource.Metadata)
		resource.Metadata[model.MetadataRuntimeCoverageEvaluable] = "false"
		delete(resource.Metadata, model.MetadataRuntimeTargetCount)
		delete(resource.Metadata, model.MetadataRuntimeCoverageScope)
		delete(resource.Metadata, model.MetadataRuntimeDroppedTargetCount)
		delete(resource.Metadata, model.MetadataRuntimeObservedTargetCount)
		delete(resource.Metadata, model.MetadataRuntimeDroppedTargetRatio)
		resource.Metadata[model.MetadataRuntimeEndpointEvaluable] = "false"
		delete(resource.Metadata, model.MetadataRuntimeEndpointCount)
		delete(resource.Metadata, model.MetadataRuntimeMissingEndpointCount)
		delete(resource.Metadata, model.MetadataRuntimeMissingEndpoints)
		nonzeroSelected, parseErr := strconv.Atoi(strings.TrimSpace(resource.Metadata["prometheus_nonzero_selected_count"]))
		if parseErr == nil && nonzeroSelected > 0 && runtimeDiscoveryComplete {
			namespace := strings.TrimSpace(resource.Metadata["namespace"])
			scope := ""
			if singletonScope {
				scope = "singleton"
			} else if observedScopes[kubernetesRuntimeCoverageScopeKey(kind, namespace)] {
				scope = "kind_namespace"
			}
			if scope != "" {
				coverageKey := kubernetesRuntimeCoverageKey(kind, namespace, kubernetesRuntimeCoverageName(resource))
				activeCount := runtimeTargets[coverageKey]
				droppedCount := runtimeDroppedTargets[coverageKey]
				observedCount := activeCount + droppedCount
				resource.Metadata[model.MetadataRuntimeCoverageEvaluable] = "true"
				resource.Metadata[model.MetadataRuntimeTargetCount] = strconv.Itoa(activeCount)
				resource.Metadata[model.MetadataRuntimeDroppedTargetCount] = strconv.Itoa(droppedCount)
				resource.Metadata[model.MetadataRuntimeObservedTargetCount] = strconv.Itoa(observedCount)
				if observedCount > 0 {
					resource.Metadata[model.MetadataRuntimeDroppedTargetRatio] = strconv.FormatFloat(float64(droppedCount)/float64(observedCount), 'f', 4, 64)
				}
				resource.Metadata[model.MetadataRuntimeCoverageScope] = scope
				addKubernetesRuntimeEndpointCoverage(resource.Metadata, kind, coverageKey, runtimeEndpoints, runtimeEndpointUnknown)
			}
		}
		if err := e.store.Resources.Upsert(ctx, resource); err != nil {
			return err
		}
	}
	return nil
}

func isKubernetesPrometheusWorkloadKind(kind string) bool {
	return kind == "Prometheus" || kind == "PrometheusAgent"
}

func addKubernetesRuntimeEndpointCoverage(metadata map[string]string, kind string, coverageKey string, runtimeEndpoints map[string]map[int]bool, runtimeEndpointUnknown map[string]bool) {
	if kind != "ServiceMonitor" && kind != "PodMonitor" {
		return
	}
	expectedCount, err := strconv.Atoi(strings.TrimSpace(metadata["endpoint_count"]))
	if err != nil || expectedCount <= 0 || runtimeEndpointUnknown[coverageKey] {
		return
	}
	coveredCount := 0
	missing := make([]string, 0)
	for endpoint := 0; endpoint < expectedCount; endpoint++ {
		if runtimeEndpoints[coverageKey][endpoint] {
			coveredCount++
			continue
		}
		missing = append(missing, strconv.Itoa(endpoint))
	}
	metadata[model.MetadataRuntimeEndpointEvaluable] = "true"
	metadata[model.MetadataRuntimeEndpointCount] = strconv.Itoa(coveredCount)
	metadata[model.MetadataRuntimeMissingEndpointCount] = strconv.Itoa(len(missing))
	metadata[model.MetadataRuntimeMissingEndpoints] = strings.Join(missing, ",")
}

func kubernetesRuntimeCoverageName(resource model.Resource) string {
	name := strings.TrimSpace(resource.Name)
	namespace := strings.TrimSpace(resource.Metadata["namespace"])
	if namespace != "" && strings.HasPrefix(name, namespace+"/") {
		return strings.TrimPrefix(name, namespace+"/")
	}
	return name
}

func kubernetesRuntimeCoverageKey(kind string, namespace string, name string) string {
	return strings.TrimSpace(kind) + ":" + strings.TrimSpace(namespace) + "/" + strings.TrimSpace(name)
}

func kubernetesRuntimeCoverageScopeKey(kind string, namespace string) string {
	return strings.TrimSpace(kind) + ":" + strings.TrimSpace(namespace)
}

func isPrometheusRuntimeSource(system string) bool {
	switch system {
	case "prometheus", "thanos", "victoriametrics", "mimir", "cortex":
		return true
	default:
		return false
	}
}

func isKubernetesRuntimeCoverageKind(kind string) bool {
	switch kind {
	case "ServiceMonitor", "PodMonitor", "Probe", "ScrapeConfig":
		return true
	default:
		return false
	}
}

func appendSnapshotDiagnostics(diagnostics []model.Diagnostic, diagnostic model.Diagnostic) []model.Diagnostic {
	result := append([]model.Diagnostic(nil), diagnostics...)
	return append(result, diagnostic)
}

func diagnosticsHaveWarning(diagnostics []model.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Status == model.ExecutionStatusWarning || diagnostic.Status == model.ExecutionStatusFailed {
			return true
		}
	}
	return false
}

func stampConnectorSnapshot(snapshot connectorpkg.Snapshot, connectorID string, snapshotID string, syncedAt time.Time, complete bool) (connectorpkg.Snapshot, map[string]bool, map[string]bool) {
	resourceIDs := make(map[string]bool, len(snapshot.Resources))
	completeness := "partial"
	if complete {
		completeness = "complete"
	}
	for index := range snapshot.Resources {
		resource := &snapshot.Resources[index]
		if isDerivedBusinessService(*resource) {
			continue
		}
		resource.Metadata = copyMetadata(resource.Metadata)
		resource.Metadata[model.MetadataConnectorID] = connectorID
		resource.Metadata[model.MetadataConnectorLastSeenAt] = syncedAt.Format(time.RFC3339Nano)
		resource.Metadata[model.MetadataConnectorSnapshotID] = snapshotID
		resource.Metadata[model.MetadataConnectorSnapshotCompletedAt] = syncedAt.Format(time.RFC3339Nano)
		resource.Metadata[model.MetadataConnectorSnapshotCompleteness] = completeness
		delete(resource.Metadata, model.MetadataConnectorOrphanedAt)
		delete(resource.Metadata, model.MetadataConnectorOrphanedSnapshotID)
		delete(resource.Metadata, model.MetadataConnectorOrphanedSnapshotComplete)
		resourceIDs[resource.ID] = true
	}
	relationshipIDs := make(map[string]bool, len(snapshot.Relationships))
	for index := range snapshot.Relationships {
		relationship := &snapshot.Relationships[index]
		relationship.Metadata = copyMetadata(relationship.Metadata)
		relationship.Metadata[model.MetadataConnectorID] = connectorID
		relationshipIDs[relationship.ID] = true
	}
	return snapshot, resourceIDs, relationshipIDs
}

func (e *Engine) reconcileConnectorSnapshot(ctx context.Context, connectorID string, snapshotID string, currentResources map[string]bool, currentRelationships map[string]bool, syncedAt time.Time) (int, int, error) {
	resources, err := e.store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return 0, 0, err
	}
	resourcesByID := make(map[string]model.Resource, len(resources))
	orphanedIDs := map[string]bool{}
	orphanedCount := 0
	for _, resource := range resources {
		resourcesByID[resource.ID] = resource
		if currentResources[resource.ID] || !resourceOwnedByConnector(resource, connectorID) || isDerivedBusinessService(resource) {
			continue
		}
		if resource.Status == model.ResourceStatusOrphan {
			continue
		}
		resource.Status = model.ResourceStatusOrphan
		resource.Metadata = copyMetadata(resource.Metadata)
		resource.Metadata[model.MetadataConnectorID] = connectorID
		resource.Metadata[model.MetadataConnectorOrphanedAt] = syncedAt.Format(time.RFC3339Nano)
		resource.Metadata[model.MetadataConnectorOrphanedSnapshotID] = snapshotID
		resource.Metadata[model.MetadataConnectorOrphanedSnapshotComplete] = "true"
		if err := e.store.Resources.Upsert(ctx, resource); err != nil {
			return orphanedCount, 0, err
		}
		orphanedIDs[resource.ID] = true
		orphanedCount++
	}

	relationships, err := e.store.Relationships.List(ctx)
	if err != nil {
		return orphanedCount, 0, err
	}
	removedCount := 0
	for _, relationship := range relationships {
		if currentRelationships[relationship.ID] {
			continue
		}
		owner := relationship.Metadata[model.MetadataConnectorID]
		migratedOwner := owner == "" && resourceOwnedByConnector(resourcesByID[relationship.FromID], connectorID)
		if owner != connectorID && !migratedOwner && !orphanedIDs[relationship.FromID] && !orphanedIDs[relationship.ToID] {
			continue
		}
		if err := e.store.Relationships.Delete(ctx, relationship.ID); err != nil {
			return orphanedCount, removedCount, err
		}
		removedCount++
	}
	return orphanedCount, removedCount, nil
}

func (e *Engine) reconcileDerivedServices(ctx context.Context) error {
	resources, err := e.store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return err
	}
	relationships, err := e.store.Relationships.List(ctx)
	if err != nil {
		return err
	}
	activeResources := make(map[string]bool, len(resources))
	for _, resource := range resources {
		activeResources[resource.ID] = resource.Status == model.ResourceStatusActive || resource.Status == model.ResourceStatusBroken
	}
	activeServices := map[string]bool{}
	for _, relationship := range relationships {
		if relationship.Type == model.RelationshipBelongsTo && activeResources[relationship.FromID] {
			activeServices[relationship.ToID] = true
		}
	}
	for _, resource := range resources {
		if !isDerivedBusinessService(resource) {
			continue
		}
		desired := model.ResourceStatusOrphan
		if activeServices[resource.ID] {
			desired = model.ResourceStatusActive
		}
		if resource.Status == desired {
			continue
		}
		resource.Status = desired
		if err := e.store.Resources.Upsert(ctx, resource); err != nil {
			return err
		}
	}
	return nil
}

func resourceOwnedByConnector(resource model.Resource, connectorID string) bool {
	if resource.ID == "" {
		return false
	}
	owner := resource.Metadata[model.MetadataConnectorID]
	return owner == connectorID || (owner == "" && resource.Source.System == connectorID)
}

func isDerivedBusinessService(resource model.Resource) bool {
	return resource.Type == model.ResourceTypeService && resource.Source.System == "monicheck" && resource.Metadata["derived"] == "true"
}

func copyMetadata(metadata map[string]string) map[string]string {
	copy := make(map[string]string, len(metadata)+3)
	for key, value := range metadata {
		copy[key] = value
	}
	return copy
}

func (e *Engine) recordConnectorStatus(status model.ConnectorStatus) {
	if status.DurationMillis == 0 && !status.LastStartedAt.IsZero() && !status.LastFinishedAt.IsZero() {
		status.DurationMillis = status.LastFinishedAt.Sub(status.LastStartedAt).Milliseconds()
	}
	e.statusMu.Lock()
	defer e.statusMu.Unlock()
	e.statuses[status.ID] = status
}

func (e *Engine) RunAnalyzers(ctx context.Context) (model.ExecutionResult, error) {
	e.analyzerRunMu.Lock()
	defer e.analyzerRunMu.Unlock()

	startedAt := time.Now().UTC()
	result := model.ExecutionResult{
		ID:          model.StableID("execution", startedAt.Format(time.RFC3339Nano)),
		Status:      model.ExecutionStatusSucceeded,
		StartedAt:   startedAt,
		AnalyzerIDs: []string{},
	}

	resourceGraph, err := graph.Build(ctx, e.store.Resources, e.store.Relationships)
	if err != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, err
	}

	items := e.analyzers.List()
	executions := e.executeAnalyzerBatch(ctx, items, resourceGraph, e.analyzerConfigSnapshot())
	var runErrors []error
	waivers, waiverErr := e.listWaivers(ctx)
	if waiverErr != nil {
		runErrors = append(runErrors, fmt.Errorf("list waivers: %w", waiverErr))
	}
	for _, execution := range executions {
		item := execution.analyzer
		if execution.err != nil {
			runErrors = append(runErrors, fmt.Errorf("run analyzer %s: %w", item.ID(), execution.err))
			continue
		}
		findings := waiverpkg.Apply(execution.findings, waivers, startedAt)
		findings, err = e.reconcileOccurrences(ctx, item.ID(), findings, startedAt)
		if err != nil {
			runErrors = append(runErrors, fmt.Errorf("reconcile occurrences for analyzer %s: %w", item.ID(), err))
			continue
		}
		if err := e.store.Findings.ReplaceOpenByAnalyzer(ctx, item.ID(), findings); err != nil {
			runErrors = append(runErrors, fmt.Errorf("store findings for analyzer %s: %w", item.ID(), err))
			continue
		}
		result.AnalyzerIDs = append(result.AnalyzerIDs, item.ID())
		result.FindingCount += len(execution.findings)
	}

	result.FinishedAt = time.Now().UTC()
	runErr := errors.Join(runErrors...)
	if runErr != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = runErr.Error()
	}
	if err := e.store.Executions.Save(ctx, result); err != nil {
		return result, errors.Join(runErr, err)
	}
	return result, runErr
}

func (e *Engine) RunAnalyzer(ctx context.Context, analyzerID string) (model.ExecutionResult, error) {
	result, _, err := e.RunAnalyzerWithFindings(ctx, analyzerID)
	return result, err
}

func (e *Engine) RunAnalyzerWithFindings(ctx context.Context, analyzerID string) (model.ExecutionResult, []model.Finding, error) {
	e.analyzerRunMu.Lock()
	defer e.analyzerRunMu.Unlock()

	startedAt := time.Now().UTC()
	result := model.ExecutionResult{
		ID:          model.StableID("execution", analyzerID, startedAt.Format(time.RFC3339Nano)),
		Status:      model.ExecutionStatusSucceeded,
		StartedAt:   startedAt,
		AnalyzerIDs: []string{},
	}

	item, ok := e.analyzers.Get(analyzerID)
	if !ok {
		err := fmt.Errorf("analyzer %s not found", analyzerID)
		result.Status = model.ExecutionStatusFailed
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, nil, err
	}

	resourceGraph, err := graph.Build(ctx, e.store.Resources, e.store.Relationships)
	if err != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, nil, err
	}

	e.logger.Info(ctx, "run analyzer", logger.FieldAnalyzerID, item.ID())
	findings, err := executeAnalyzerSafely(ctx, item, analyzer.Context{
		Resources:            e.store.Resources,
		Findings:             e.store.Findings,
		ReportExports:        e.store.ReportExports,
		FindingWorkflow:      e.store.FindingWorkflow,
		CoverageExpectations: e.store.CoverageExpectations,
		CoverageExceptions:   e.store.CoverageExceptions,
		Graph:                resourceGraph,
		Config:               e.analyzerConfigSnapshot(),
	})
	if err != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, nil, fmt.Errorf("run analyzer %s: %w", item.ID(), err)
	}
	waivers, waiverErr := e.listWaivers(ctx)
	if waiverErr != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = waiverErr.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, nil, fmt.Errorf("list waivers: %w", waiverErr)
	}
	findings = waiverpkg.Apply(findings, waivers, startedAt)
	findings, err = e.reconcileOccurrences(ctx, item.ID(), findings, startedAt)
	if err != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, nil, fmt.Errorf("reconcile occurrences for analyzer %s: %w", item.ID(), err)
	}
	if err := e.store.Findings.ReplaceOpenByAnalyzer(ctx, item.ID(), findings); err != nil {
		result.Status = model.ExecutionStatusFailed
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		_ = e.store.Executions.Save(ctx, result)
		return result, nil, fmt.Errorf("store findings for analyzer %s: %w", item.ID(), err)
	}
	result.AnalyzerIDs = append(result.AnalyzerIDs, item.ID())
	result.FindingCount = len(findings)
	result.FinishedAt = time.Now().UTC()
	if err := e.store.Executions.Save(ctx, result); err != nil {
		return result, findings, err
	}
	return result, findings, nil
}

func (e *Engine) listWaivers(ctx context.Context) ([]model.Waiver, error) {
	if e.store == nil || e.store.Waivers == nil {
		return nil, nil
	}
	return e.store.Waivers.List(ctx)
}

func (e *Engine) reconcileOccurrences(ctx context.Context, analyzerID string, findings []model.Finding, observedAt time.Time) ([]model.Finding, error) {
	if e.store == nil || e.store.FindingOccurrences == nil {
		return findings, nil
	}
	previous, err := e.store.FindingOccurrences.List(ctx, analyzerID)
	if err != nil {
		return nil, err
	}
	records := occurrence.Reconcile(analyzerID, previous, findings, observedAt)
	if err := e.store.FindingOccurrences.ReplaceByAnalyzer(ctx, analyzerID, records); err != nil {
		return nil, err
	}
	return occurrence.Attach(findings, records), nil
}

type analyzerExecutionResult struct {
	analyzer analyzer.Analyzer
	findings []model.Finding
	err      error
}

func (e *Engine) executeAnalyzerBatch(
	ctx context.Context,
	items []analyzer.Analyzer,
	resourceGraph *graph.Graph,
	config map[string]any,
) []analyzerExecutionResult {
	results := make([]analyzerExecutionResult, len(items))
	if len(items) == 0 {
		return results
	}

	_, workerCount := e.WorkerLimits()
	if workerCount > len(items) {
		workerCount = len(items)
	}
	e.logger.Info(ctx, "run analyzer batch", "analyzer_count", len(items), "worker_count", workerCount)

	jobs := make(chan int, len(items))
	for index := range items {
		jobs <- index
	}
	close(jobs)

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				item := items[index]
				e.logger.Info(ctx, "run analyzer", logger.FieldAnalyzerID, item.ID())
				findings, err := executeAnalyzerSafely(ctx, item, analyzer.Context{
					Resources:            e.store.Resources,
					Findings:             e.store.Findings,
					ReportExports:        e.store.ReportExports,
					FindingWorkflow:      e.store.FindingWorkflow,
					CoverageExpectations: e.store.CoverageExpectations,
					CoverageExceptions:   e.store.CoverageExceptions,
					Graph:                resourceGraph,
					Config:               cloneAnalyzerConfig(config),
				})
				results[index] = analyzerExecutionResult{
					analyzer: item,
					findings: findings,
					err:      err,
				}
			}
		}()
	}
	workers.Wait()
	return results
}

func executeAnalyzerSafely(ctx context.Context, item analyzer.Analyzer, analysis analyzer.Context) (findings []model.Finding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("analyzer panic: %v", recovered)
		}
	}()
	findings, err = item.Execute(ctx, analysis)
	if err != nil {
		return nil, err
	}
	findings = contract.NormalizeFindings(item.ID(), findings)
	for index := range findings {
		findings[index] = risk.ScoreFinding(findings[index])
	}
	validation := contract.ValidateFindings(findings)
	if !validation.Valid {
		return nil, fmt.Errorf("validate findings: %s", validation.Violations[0].Message)
	}
	return findings, nil
}

func (e *Engine) analyzerConfigSnapshot() map[string]any {
	e.configMu.RLock()
	defer e.configMu.RUnlock()
	return cloneAnalyzerConfig(e.config)
}

func cloneAnalyzerConfig(config map[string]any) map[string]any {
	if config == nil {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(config))
	for key, value := range config {
		cloned[key] = cloneAnalyzerConfigValue(value)
	}
	return cloned
}

func cloneAnalyzerConfigValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneAnalyzerConfig(typed)
	case map[string]string:
		cloned := make(map[string]string, len(typed))
		for key, item := range typed {
			cloned[key] = item
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneAnalyzerConfigValue(item)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}

func (e *Engine) Bootstrap(ctx context.Context) (model.ExecutionResult, error) {
	if err := e.Sync(ctx); err != nil {
		result := model.ExecutionResult{
			ID:         model.StableID("execution", "bootstrap", time.Now().UTC().Format(time.RFC3339Nano)),
			Status:     model.ExecutionStatusFailed,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
			Error:      err.Error(),
		}
		_ = e.store.Executions.Save(ctx, result)
		return result, err
	}
	return e.RunAnalyzers(ctx)
}
