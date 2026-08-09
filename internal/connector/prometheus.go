package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
)

const prometheusSystem = "prometheus"
const prometheusMetricLabelValueLimit = 20
const prometheusTSDBStatsLimit = 10000

type PrometheusConnector struct {
	baseURL          string
	client           *http.Client
	id               string
	name             string
	system           string
	discoveryWorkers int
}

func NewPrometheusConnector(baseURL string) (*PrometheusConnector, error) {
	return NewPrometheusConnectorWithOptions(baseURL, HTTPOptions{Timeout: 15 * time.Second})
}

func NewPrometheusConnectorWithOptions(baseURL string, options HTTPOptions) (*PrometheusConnector, error) {
	return newPrometheusCompatibleConnector("prometheus", "Prometheus Connector", prometheusSystem, baseURL, options)
}

func NewThanosConnectorWithOptions(baseURL string, options HTTPOptions) (*PrometheusConnector, error) {
	return newPrometheusCompatibleConnector("thanos", "Thanos Connector", "thanos", baseURL, options)
}

func NewVictoriaMetricsConnectorWithOptions(baseURL string, options HTTPOptions) (*PrometheusConnector, error) {
	return newPrometheusCompatibleConnector("victoriametrics", "VictoriaMetrics Connector", "victoriametrics", baseURL, options)
}

func NewMimirConnectorWithOptions(baseURL string, options HTTPOptions) (*PrometheusConnector, error) {
	return newPrometheusCompatibleConnector("mimir", "Mimir Connector", "mimir", baseURL, options)
}

func NewCortexConnectorWithOptions(baseURL string, options HTTPOptions) (*PrometheusConnector, error) {
	return newPrometheusCompatibleConnector("cortex", "Cortex Connector", "cortex", baseURL, options)
}

func newPrometheusCompatibleConnector(id string, name string, system string, baseURL string, options HTTPOptions) (*PrometheusConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("%s url is empty", id)
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid %s url %q: %w", id, baseURL, err)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &PrometheusConnector{
		baseURL:          baseURL,
		client:           client,
		id:               id,
		name:             name,
		system:           system,
		discoveryWorkers: defaultConnectorDetailWorkers,
	}, nil
}

func (c *PrometheusConnector) ID() string {
	return c.id
}

func (c *PrometheusConnector) Name() string {
	return c.name
}

func (c *PrometheusConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()

	metricNames, err := c.metricNames(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	discovery, diagnostics := c.discoverOptionalEndpoints(ctx, now)
	metadata := discovery.Metadata
	targetMetadata := discovery.TargetMetadata
	metricNames = mergeTargetMetadata(metricNames, metadata, targetMetadata)
	targetDiscovery := discovery.TargetDiscovery
	targets := targetDiscovery.ActiveTargets
	droppedTargets := targetDiscovery.DroppedTargets
	rules := discovery.Rules
	alerts := discovery.Alerts
	series := discovery.Series
	recentSeriesCounts := seriesCountByMetric(series)
	tsdbStats := discovery.TSDBStats
	labelSummaries := metricLabelSummaries(append(series, targetMetadataSeries(targetMetadata)...))

	resources := make([]model.Resource, 0, len(metricNames)+(len(targets)*4))
	relationships := make([]model.Relationship, 0, len(targets)*3)
	resourceByID := make(map[string]model.Resource)
	targetByJobInstance := make(map[string]model.Resource)
	jobContexts := make(map[string]*prometheusResourceContext)
	instanceContexts := make(map[string]*prometheusResourceContext)
	targetMetricRelationshipIDs := make(map[string]bool)

	for _, name := range metricNames {
		resource := c.resource(model.ResourceTypeMetric, name, "metric:"+name, now)
		resource.Metadata = metricMetadata(metadata[name])
		addSeriesCount(resource.Metadata, name, recentSeriesCounts[name], tsdbStats.SeriesCountByMetricName)
		applyMetricLabelSummary(&resource, labelSummaries[name])
		addResource(resourceByID, resource)
	}

	for _, target := range targets {
		targetResource := c.resource(model.ResourceTypeTarget, target.ScrapeURL, "target:"+target.ScrapeURL, now)
		targetResource.Labels = cloneLabels(target.Labels)
		targetResource.Metadata = map[string]string{
			model.MetadataHealth:      target.Health,
			model.MetadataScrapeURL:   target.ScrapeURL,
			model.MetadataTargetState: "active",
		}
		applyTargetDiscoveredLabels(&targetResource, target.DiscoveredLabels)
		if target.ScrapePool != "" {
			targetResource.Metadata[model.MetadataScrapePool] = target.ScrapePool
			applyPrometheusOperatorScrapePool(&targetResource, target.ScrapePool)
		}
		if !target.LastScrape.IsZero() {
			targetResource.Metadata[model.MetadataLastScrape] = target.LastScrape.Format(time.RFC3339)
		}
		if target.LastScrapeDuration > 0 {
			targetResource.Metadata[model.MetadataScrapeDuration] = prometheusDuration(target.LastScrapeDuration)
		}
		if target.ScrapeInterval != "" {
			targetResource.Metadata[model.MetadataScrapeInterval] = target.ScrapeInterval
		}
		if target.ScrapeTimeout != "" {
			targetResource.Metadata[model.MetadataScrapeTimeout] = target.ScrapeTimeout
		}
		if target.LastError != "" {
			targetResource.Metadata[model.MetadataLastError] = target.LastError
			targetResource.Status = model.ResourceStatusBroken
		}
		addResource(resourceByID, targetResource)
		if key := jobInstanceKey(targetResource.Labels["job"], targetResource.Labels["instance"]); key != "" {
			targetByJobInstance[key] = targetResource
		}

		if job := targetResource.Labels["job"]; job != "" {
			jobResource := c.resource(model.ResourceTypeJob, job, "job:"+job, now)
			addResource(resourceByID, jobResource)
			addPrometheusResourceContext(jobContexts, jobResource.ID, targetResource.Labels)
			relationships = append(relationships, c.relationship(targetResource.ID, jobResource.ID, model.RelationshipBelongsTo, now))
		}

		if instance := targetResource.Labels["instance"]; instance != "" {
			instanceResource := c.resource(model.ResourceTypeInstance, instance, "instance:"+instance, now)
			addResource(resourceByID, instanceResource)
			addPrometheusResourceContext(instanceContexts, instanceResource.ID, targetResource.Labels)
			relationships = append(relationships, c.relationship(targetResource.ID, instanceResource.ID, model.RelationshipBelongsTo, now))
		}

		exporterName := exporterName(target)
		if exporterName != "" {
			exporterResource := c.resource(model.ResourceTypeExporter, exporterName, "exporter:"+exporterName, now)
			addResource(resourceByID, exporterResource)
			relationships = append(relationships, c.relationship(targetResource.ID, exporterResource.ID, model.RelationshipProduces, now))
		}
	}
	for _, target := range droppedTargets {
		fingerprint := model.StableID(target.ScrapePool, alertFingerprint(target.DiscoveredLabels))
		name := strings.TrimSpace(target.ScrapePool)
		if name == "" {
			name = "dropped"
		}
		name += " dropped target " + fingerprint[:8]
		resource := c.resource(model.ResourceTypeTarget, name, "dropped_target:"+fingerprint, now)
		resource.Status = model.ResourceStatusDeprecated
		resource.Metadata = map[string]string{
			model.MetadataTargetState: "dropped",
		}
		if target.ScrapePool != "" {
			resource.Metadata[model.MetadataScrapePool] = target.ScrapePool
			applyPrometheusOperatorScrapePool(&resource, target.ScrapePool)
		}
		applyTargetDiscoveredLabels(&resource, target.DiscoveredLabels)
		addResource(resourceByID, resource)
	}
	applyPrometheusResourceContexts(resourceByID, jobContexts)
	applyPrometheusResourceContexts(resourceByID, instanceContexts)

	for _, item := range targetMetadata {
		metricName := strings.TrimSpace(item.Metric)
		if metricName == "" {
			continue
		}
		targetResource, ok := targetByJobInstance[jobInstanceKey(item.Target["job"], item.Target["instance"])]
		if !ok {
			continue
		}
		metricResource := c.resource(model.ResourceTypeMetric, metricName, "metric:"+metricName, now)
		metricResource.Metadata = metricMetadata(metadata[metricName])
		addSeriesCount(metricResource.Metadata, metricName, recentSeriesCounts[metricName], tsdbStats.SeriesCountByMetricName)
		applyMetricLabelSummary(&metricResource, labelSummaries[metricName])
		addResource(resourceByID, metricResource)
		relationship := c.relationship(targetResource.ID, metricResource.ID, model.RelationshipProduces, now)
		if !targetMetricRelationshipIDs[relationship.ID] {
			targetMetricRelationshipIDs[relationship.ID] = true
			relationships = append(relationships, relationship)
		}
	}

	for _, item := range series {
		metricName := item["__name__"]
		if metricName == "" {
			continue
		}
		metricResource := c.resource(model.ResourceTypeMetric, metricName, "metric:"+metricName, now)
		metricResource.Metadata = metricMetadata(metadata[metricName])
		addSeriesCount(metricResource.Metadata, metricName, recentSeriesCounts[metricName], tsdbStats.SeriesCountByMetricName)
		applyMetricLabelSummary(&metricResource, labelSummaries[metricName])
		addResource(resourceByID, metricResource)

		key := jobInstanceKey(item["job"], item["instance"])
		if key == "" {
			continue
		}
		targetResource, ok := targetByJobInstance[key]
		if !ok {
			continue
		}
		relationship := c.relationship(targetResource.ID, metricResource.ID, model.RelationshipProduces, now)
		if !targetMetricRelationshipIDs[relationship.ID] {
			targetMetricRelationshipIDs[relationship.ID] = true
			relationships = append(relationships, relationship)
		}
	}
	addMetricLabelResources(c, resourceByID, &relationships, labelSummaries, tsdbStats, now)
	addTSDBResource(
		c,
		resourceByID,
		tsdbStats,
		targets,
		droppedTargets,
		rules,
		discovery.Alertmanagers,
		discovery.RuntimeInfo,
		discovery.Flags,
		diagnosticByID(diagnostics, "prometheus_targets"),
		diagnosticByID(diagnostics, "prometheus_rules"),
		diagnosticByID(diagnostics, "prometheus_alertmanagers"),
		diagnosticByID(diagnostics, "prometheus_runtime_info"),
		diagnosticByID(diagnostics, "prometheus_flags"),
		now,
	)

	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			ruleResource, ok := c.ruleResource(group, rule, now)
			if !ok {
				continue
			}
			addResource(resourceByID, ruleResource)
			var outputMetricResource model.Resource
			var hasOutputMetric bool
			if rule.Type == "recording" && strings.TrimSpace(rule.Name) != "" {
				metricResource := c.resource(model.ResourceTypeMetric, rule.Name, "metric:"+rule.Name, now)
				metricResource.Metadata = metricMetadata(metadata[rule.Name])
				addSeriesCount(metricResource.Metadata, rule.Name, recentSeriesCounts[rule.Name], tsdbStats.SeriesCountByMetricName)
				applyMetricLabelSummary(&metricResource, labelSummaries[rule.Name])
				addResource(resourceByID, metricResource)
				relationships = append(relationships, c.relationship(ruleResource.ID, metricResource.ID, model.RelationshipProduces, now))
				outputMetricResource = metricResource
				hasOutputMetric = true
			}
			for _, metricName := range ExtractPromQLMetricNames(rule.Query) {
				metricResource := c.resource(model.ResourceTypeMetric, metricName, "metric:"+metricName, now)
				metricResource.Metadata = metricMetadata(metadata[metricName])
				addSeriesCount(metricResource.Metadata, metricName, recentSeriesCounts[metricName], tsdbStats.SeriesCountByMetricName)
				applyMetricLabelSummary(&metricResource, labelSummaries[metricName])
				addResource(resourceByID, metricResource)
				relationships = append(relationships, c.relationship(ruleResource.ID, metricResource.ID, model.RelationshipUses, now))
				if hasOutputMetric && metricResource.ID != outputMetricResource.ID {
					relationship := c.relationship(metricResource.ID, outputMetricResource.ID, model.RelationshipProduces, now)
					relationship.Metadata = map[string]string{
						"via_rule_id":   ruleResource.ID,
						"via_rule_name": ruleResource.Name,
					}
					relationships = append(relationships, relationship)
				}
			}
		}
	}

	for _, alert := range alerts {
		alertResource := c.alertResource(alert, now)
		addResource(resourceByID, alertResource)

		alertName := strings.TrimSpace(alert.Labels["alertname"])
		if alertName == "" {
			continue
		}
		ruleResource := c.resource(model.ResourceTypeAlertRule, alertName, "rule:alerting:"+alertName, now)
		ruleResource.Labels = cloneLabels(alert.Labels)
		mergeResourceLabels(resourceByID, ruleResource)
		relationships = append(relationships, c.relationship(alertResource.ID, ruleResource.ID, model.RelationshipReferences, now))
	}

	for _, resource := range resourceByID {
		resources = append(resources, resource)
	}

	return Snapshot{
		Resources:     resources,
		Relationships: relationships,
		Diagnostics:   diagnostics,
		Partial:       diagnosticsHaveFailures(diagnostics),
	}, nil
}

type prometheusOptionalDiscovery struct {
	Metadata        map[string][]prometheusMetadata
	TargetMetadata  []prometheusTargetMetadata
	TargetDiscovery prometheusTargetDiscovery
	Rules           prometheusRules
	Alerts          []prometheusAlert
	Series          []map[string]string
	TSDBStats       prometheusTSDBStats
	Alertmanagers   prometheusAlertmanagerDiscovery
	RuntimeInfo     prometheusRuntimeInfo
	Flags           prometheusFlags
}

type prometheusOptionalDiscoveryResult struct {
	Discovery  prometheusOptionalDiscovery
	Diagnostic model.Diagnostic
}

func (c *PrometheusConnector) discoverOptionalEndpoints(ctx context.Context, now time.Time) (prometheusOptionalDiscovery, []model.Diagnostic) {
	const endpointCount = 10
	results, workerCount := boundedDetailFetch(ctx, endpointCount, c.discoveryWorkers, func(ctx context.Context, index int) (prometheusOptionalDiscoveryResult, error) {
		var result prometheusOptionalDiscoveryResult
		if c.system != prometheusSystem && index >= 7 {
			result.Diagnostic = c.unsupportedPrometheusServerDiagnostic(index)
			return result, nil
		}
		switch index {
		case 0:
			result.Discovery.Metadata, result.Diagnostic = c.metadata(ctx)
		case 1:
			result.Discovery.TargetMetadata, result.Diagnostic = c.targetMetadata(ctx)
		case 2:
			result.Discovery.TargetDiscovery, result.Diagnostic = c.targets(ctx)
		case 3:
			result.Discovery.Rules, result.Diagnostic = c.rules(ctx)
		case 4:
			result.Discovery.Alerts, result.Diagnostic = c.alerts(ctx)
		case 5:
			result.Discovery.Series, result.Diagnostic = c.series(ctx, now.Add(-time.Hour), now)
		case 6:
			result.Discovery.TSDBStats, result.Diagnostic = c.tsdbStats(ctx)
		case 7:
			result.Discovery.Alertmanagers, result.Diagnostic = c.alertmanagers(ctx)
		case 8:
			result.Discovery.RuntimeInfo, result.Diagnostic = c.runtimeInfo(ctx)
		case 9:
			result.Discovery.Flags, result.Diagnostic = c.flags(ctx)
		}
		return result, nil
	})

	var discovery prometheusOptionalDiscovery
	diagnostics := make([]model.Diagnostic, 0, endpointCount)
	for index, result := range results {
		switch index {
		case 0:
			discovery.Metadata = result.Value.Discovery.Metadata
		case 1:
			discovery.TargetMetadata = result.Value.Discovery.TargetMetadata
		case 2:
			discovery.TargetDiscovery = result.Value.Discovery.TargetDiscovery
		case 3:
			discovery.Rules = result.Value.Discovery.Rules
		case 4:
			discovery.Alerts = result.Value.Discovery.Alerts
		case 5:
			discovery.Series = result.Value.Discovery.Series
		case 6:
			discovery.TSDBStats = result.Value.Discovery.TSDBStats
		case 7:
			discovery.Alertmanagers = result.Value.Discovery.Alertmanagers
		case 8:
			discovery.RuntimeInfo = result.Value.Discovery.RuntimeInfo
		case 9:
			discovery.Flags = result.Value.Discovery.Flags
		}
		diagnostic := result.Value.Diagnostic
		if diagnostic.Metadata == nil {
			diagnostic.Metadata = map[string]string{}
		}
		diagnostic.Metadata["discovery_mode"] = "bounded_concurrent"
		diagnostic.Metadata["worker_count"] = strconv.Itoa(workerCount)
		diagnostics = append(diagnostics, diagnostic)
	}
	return discovery, diagnostics
}

func (c *PrometheusConnector) unsupportedPrometheusServerDiagnostic(index int) model.Diagnostic {
	type endpoint struct {
		id   string
		name string
		path string
	}
	endpoints := map[int]endpoint{
		7: {id: "prometheus_alertmanagers", name: "Prometheus Alertmanager discovery", path: "/api/v1/alertmanagers"},
		8: {id: "prometheus_runtime_info", name: "Prometheus runtime information", path: "/api/v1/status/runtimeinfo"},
		9: {id: "prometheus_flags", name: "Prometheus runtime flags", path: "/api/v1/status/flags"},
	}
	item := endpoints[index]
	return model.Diagnostic{
		ID:      item.id,
		Name:    item.name,
		Status:  model.ExecutionStatusSucceeded,
		Message: item.name + " is not part of this compatible platform capability profile",
		Metadata: map[string]string{
			"endpoint":  item.path,
			"optional":  "true",
			"system":    c.system,
			"supported": "false",
			"skipped":   "true",
		},
	}
}

func diagnosticsHaveFailures(diagnostics []model.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Status == model.ExecutionStatusWarning || diagnostic.Status == model.ExecutionStatusFailed {
			return true
		}
	}
	return false
}

func (c *PrometheusConnector) metricNames(ctx context.Context) ([]string, error) {
	var response struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
		Error  string   `json:"error"`
	}
	if err := c.get(ctx, "/api/v1/label/__name__/values", &response); err != nil {
		return nil, err
	}
	if response.Status != "success" {
		return nil, fmt.Errorf("prometheus metric names failed: %s", response.Error)
	}
	return response.Data, nil
}

func (c *PrometheusConnector) metadata(ctx context.Context) (map[string][]prometheusMetadata, model.Diagnostic) {
	var response struct {
		Status string                          `json:"status"`
		Data   map[string][]prometheusMetadata `json:"data"`
		Error  string                          `json:"error"`
	}
	path := "/api/v1/metadata"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return nil, c.optionalDiagnostic("prometheus_metadata", "Prometheus metric metadata", path, false, err)
	}
	if response.Status != "success" {
		return nil, c.optionalDiagnostic("prometheus_metadata", "Prometheus metric metadata", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return response.Data, c.optionalDiagnostic("prometheus_metadata", "Prometheus metric metadata", path, true, nil)
}

func (c *PrometheusConnector) targetMetadata(ctx context.Context) ([]prometheusTargetMetadata, model.Diagnostic) {
	var response struct {
		Status string                     `json:"status"`
		Data   []prometheusTargetMetadata `json:"data"`
		Error  string                     `json:"error"`
	}
	path := "/api/v1/targets/metadata"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found || response.Status != "success" {
		if err == nil && found {
			err = fmt.Errorf("API status %q: %s", response.Status, response.Error)
		}
		return nil, c.optionalDiagnostic("prometheus_target_metadata", "Prometheus target metadata", path, false, err)
	}
	return response.Data, c.optionalDiagnostic("prometheus_target_metadata", "Prometheus target metadata", path, true, nil)
}

func (c *PrometheusConnector) tsdbStats(ctx context.Context) (prometheusTSDBStats, model.Diagnostic) {
	values := url.Values{}
	values.Set("limit", strconv.Itoa(prometheusTSDBStatsLimit))
	var response struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			HeadStats struct {
				NumSeries  int64 `json:"numSeries"`
				ChunkCount int64 `json:"chunkCount"`
				MinTime    int64 `json:"minTime"`
				MaxTime    int64 `json:"maxTime"`
			} `json:"headStats"`
			SeriesCountByMetricName     []prometheusTSDBStat `json:"seriesCountByMetricName"`
			LabelValueCountByLabelName  []prometheusTSDBStat `json:"labelValueCountByLabelName"`
			MemoryInBytesByLabelName    []prometheusTSDBStat `json:"memoryInBytesByLabelName"`
			SeriesCountByLabelValuePair []prometheusTSDBStat `json:"seriesCountByLabelValuePair"`
		} `json:"data"`
	}
	path := "/api/v1/status/tsdb?" + values.Encode()
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found || response.Status != "success" {
		if err == nil && found {
			err = fmt.Errorf("API status %q: %s", response.Status, response.Error)
		}
		return prometheusTSDBStats{}, c.optionalDiagnostic("prometheus_tsdb_stats", "Prometheus TSDB statistics", path, false, err)
	}

	return prometheusTSDBStats{
		Available:                   true,
		HeadNumSeries:               response.Data.HeadStats.NumSeries,
		HeadChunkCount:              response.Data.HeadStats.ChunkCount,
		HeadMinTime:                 response.Data.HeadStats.MinTime,
		HeadMaxTime:                 response.Data.HeadStats.MaxTime,
		SeriesCountByMetricName:     prometheusTSDBStatMap(response.Data.SeriesCountByMetricName, false),
		LabelValueCountByLabelName:  prometheusTSDBStatMap(response.Data.LabelValueCountByLabelName, true),
		MemoryInBytesByLabelName:    prometheusTSDBStatMap(response.Data.MemoryInBytesByLabelName, true),
		SeriesCountByLabelValuePair: response.Data.SeriesCountByLabelValuePair,
	}, c.optionalDiagnostic("prometheus_tsdb_stats", "Prometheus TSDB statistics", path, true, nil)
}

func (c *PrometheusConnector) targets(ctx context.Context) (prometheusTargetDiscovery, model.Diagnostic) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			ActiveTargets  []prometheusTarget `json:"activeTargets"`
			DroppedTargets []prometheusTarget `json:"droppedTargets"`
		} `json:"data"`
		Error string `json:"error"`
	}
	path := "/api/v1/targets"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return prometheusTargetDiscovery{}, c.optionalDiagnostic("prometheus_targets", "Prometheus targets", path, false, err)
	}
	if response.Status != "success" {
		return prometheusTargetDiscovery{}, c.optionalDiagnostic("prometheus_targets", "Prometheus targets", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return prometheusTargetDiscovery{ActiveTargets: response.Data.ActiveTargets, DroppedTargets: response.Data.DroppedTargets}, c.optionalDiagnostic("prometheus_targets", "Prometheus targets", path, true, nil)
}

func (c *PrometheusConnector) rules(ctx context.Context) (prometheusRules, model.Diagnostic) {
	var response struct {
		Status string          `json:"status"`
		Data   prometheusRules `json:"data"`
		Error  string          `json:"error"`
	}
	path := "/api/v1/rules"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return prometheusRules{}, c.optionalDiagnostic("prometheus_rules", "Prometheus rules", path, false, err)
	}
	if response.Status != "success" {
		return prometheusRules{}, c.optionalDiagnostic("prometheus_rules", "Prometheus rules", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return response.Data, c.optionalDiagnostic("prometheus_rules", "Prometheus rules", path, true, nil)
}

func (c *PrometheusConnector) alerts(ctx context.Context) ([]prometheusAlert, model.Diagnostic) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			Alerts []prometheusAlert `json:"alerts"`
		} `json:"data"`
		Error string `json:"error"`
	}
	path := "/api/v1/alerts"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return nil, c.optionalDiagnostic("prometheus_alerts", "Prometheus alerts", path, false, err)
	}
	if response.Status != "success" {
		return nil, c.optionalDiagnostic("prometheus_alerts", "Prometheus alerts", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return response.Data.Alerts, c.optionalDiagnostic("prometheus_alerts", "Prometheus alerts", path, true, nil)
}

func (c *PrometheusConnector) alertmanagers(ctx context.Context) (prometheusAlertmanagerDiscovery, model.Diagnostic) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			Active []struct {
				URL string `json:"url"`
			} `json:"activeAlertmanagers"`
			Dropped []struct {
				URL string `json:"url"`
			} `json:"droppedAlertmanagers"`
		} `json:"data"`
		Error string `json:"error"`
	}
	path := "/api/v1/alertmanagers"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return prometheusAlertmanagerDiscovery{}, c.optionalDiagnostic("prometheus_alertmanagers", "Prometheus Alertmanager discovery", path, false, err)
	}
	if response.Status != "success" {
		return prometheusAlertmanagerDiscovery{}, c.optionalDiagnostic("prometheus_alertmanagers", "Prometheus Alertmanager discovery", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return prometheusAlertmanagerDiscovery{
		ActiveCount:  len(response.Data.Active),
		DroppedCount: len(response.Data.Dropped),
	}, c.optionalDiagnostic("prometheus_alertmanagers", "Prometheus Alertmanager discovery", path, true, nil)
}

func (c *PrometheusConnector) runtimeInfo(ctx context.Context) (prometheusRuntimeInfo, model.Diagnostic) {
	var response struct {
		Status string                `json:"status"`
		Data   prometheusRuntimeInfo `json:"data"`
		Error  string                `json:"error"`
	}
	path := "/api/v1/status/runtimeinfo"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return prometheusRuntimeInfo{}, c.optionalDiagnostic("prometheus_runtime_info", "Prometheus runtime information", path, false, err)
	}
	if response.Status != "success" {
		return prometheusRuntimeInfo{}, c.optionalDiagnostic("prometheus_runtime_info", "Prometheus runtime information", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return response.Data, c.optionalDiagnostic("prometheus_runtime_info", "Prometheus runtime information", path, true, nil)
}

func (c *PrometheusConnector) flags(ctx context.Context) (prometheusFlags, model.Diagnostic) {
	var response struct {
		Status string            `json:"status"`
		Data   map[string]string `json:"data"`
		Error  string            `json:"error"`
	}
	path := "/api/v1/status/flags"
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return prometheusFlags{}, c.optionalDiagnostic("prometheus_flags", "Prometheus runtime flags", path, false, err)
	}
	if response.Status != "success" {
		return prometheusFlags{}, c.optionalDiagnostic("prometheus_flags", "Prometheus runtime flags", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return prometheusFlags{
		AdminAPIEnabled:            parsePrometheusFlagBool(response.Data["web.enable-admin-api"]),
		LifecycleAPIEnabled:        parsePrometheusFlagBool(response.Data["web.enable-lifecycle"]),
		RemoteWriteReceiverEnabled: parsePrometheusReceiverFlag(response.Data, "web.enable-remote-write-receiver", "remote-write-receiver"),
		OTLPReceiverEnabled:        parsePrometheusReceiverFlag(response.Data, "web.enable-otlp-receiver", "otlp-write-receiver"),
		AgentMode:                  parsePrometheusFlagBool(response.Data["agent"]),
		AgentWALCompression:        parsePrometheusFlagBool(response.Data["storage.agent.wal-compression"]),
		AgentRetentionMinSeconds:   parsePrometheusPositiveDuration(response.Data["storage.agent.retention.min-time"]),
		AgentRetentionMaxSeconds:   parsePrometheusPositiveDuration(response.Data["storage.agent.retention.max-time"]),
		AgentNoLockfile:            parsePrometheusFlagBool(response.Data["storage.agent.no-lockfile"]),
		RemoteFlushDeadlineSeconds: parsePrometheusPositiveDuration(response.Data["storage.remote.flush-deadline"]),
		TSDBWALCompression:         parsePrometheusFlagBool(response.Data["storage.tsdb.wal-compression"]),
		TSDBNoLockfile:             parsePrometheusFlagBool(response.Data["storage.tsdb.no-lockfile"]),
		ConcurrentRuleEvalEnabled:  parsePrometheusFeatureFlag(response.Data, "concurrent-rule-eval"),
		RuleMaxConcurrentEvals:     parsePrometheusPositiveIntFlag(response.Data, "rules.max-concurrent-evals", "rules.max-concurrent-rule-evals"),
		AlertForOutageTolerance:    parsePrometheusPositiveDuration(response.Data["rules.alert.for-outage-tolerance"]),
		AlertForGracePeriod:        parsePrometheusPositiveDuration(response.Data["rules.alert.for-grace-period"]),
		QueryMaxConcurrency:        parsePrometheusPositiveInt(response.Data["query.max-concurrency"]),
		QueryMaxSamples:            parsePrometheusPositiveInt(response.Data["query.max-samples"]),
		QueryTimeoutSeconds:        parsePrometheusPositiveDuration(response.Data["query.timeout"]),
		QueryLookbackSeconds:       parsePrometheusPositiveDuration(response.Data["query.lookback-delta"]),
		RemoteReadConcurrentLimit:  parsePrometheusNonNegativeInt(response.Data["storage.remote.read-concurrent-limit"]),
		RemoteReadSampleLimit:      parsePrometheusNonNegativeInt(response.Data["storage.remote.read-sample-limit"]),
		RemoteReadFrameBytes:       parsePrometheusNonNegativeInt(response.Data["storage.remote.read-max-bytes-in-frame"]),
		SearchAPIEnabled:           parsePrometheusFeatureFlag(response.Data, "search-api"),
		SearchMaxLimit:             parsePrometheusNonNegativeInt(response.Data["web.search.max-limit"]),
		WebMaxConnections:          parsePrometheusNonNegativeInt(response.Data["web.max-connections"]),
		WebReadTimeoutSeconds:      parsePrometheusPositiveDuration(response.Data["web.read-timeout"]),
		NotificationQueueCapacity:  parsePrometheusNonNegativeInt(response.Data["alertmanager.notification-queue-capacity"]),
		DrainNotificationQueue:     parsePrometheusFlagBool(response.Data["alertmanager.drain-notification-queue-on-shutdown"]),
		AlertResendDelaySeconds:    parsePrometheusPositiveDuration(response.Data["rules.alert.resend-delay"]),
		NotificationBatchSize:      parsePrometheusPositiveInt(response.Data["alertmanager.notification-batch-size"]),
		AutoGOMAXPROCSEnabled:      parsePrometheusFlagBool(response.Data["auto-gomaxprocs"]),
		AutoGOMEMLIMITEnabled:      parsePrometheusFlagBool(response.Data["auto-gomemlimit"]),
		AutoGOMEMLIMITRatio:        parsePrometheusPositiveFloat(response.Data["auto-gomemlimit.ratio"]),
		ConfigAutoReloadEnabled:    parsePrometheusFlagBool(response.Data["config.auto-reload"]),
		AutoReloadIntervalSeconds:  parsePrometheusPositiveDuration(response.Data["config.auto-reload-interval"]),
		MaxNotificationSubscribers: parsePrometheusPositiveInt(response.Data["web.max-notifications-subscribers"]),
		LogLevel:                   parsePrometheusLogLevel(response.Data["log.level"]),
		ExemplarStorageEnabled:     parsePrometheusFeatureFlag(response.Data, "exemplar-storage"),
		ExtraScrapeMetricsEnabled:  parsePrometheusFeatureFlag(response.Data, "extra-scrape-metrics"),
		CreatedTimestampZero:       parsePrometheusFeatureFlag(response.Data, "created-timestamp-zero-ingestion"),
		OTLPDeltaToCumulative:      parsePrometheusFeatureFlag(response.Data, "otlp-deltatocumulative"),
		XOR2EncodingEnabled:        parsePrometheusFeatureFlag(response.Data, "xor2-encoding"),
		STStorageEnabled:           parsePrometheusFeatureFlag(response.Data, "st-storage"),
		STSynthesisEnabled:         parsePrometheusFeatureFlag(response.Data, "st-synthesis"),
		OTLPNativeDeltaEnabled:     parsePrometheusFeatureFlag(response.Data, "otlp-native-delta-ingestion"),
		MetadataWALRecordsEnabled:  parsePrometheusFeatureFlag(response.Data, "metadata-wal-records"),
		TypeUnitLabelsEnabled:      parsePrometheusFeatureFlag(response.Data, "type-and-unit-labels"),
		UncachedIOEnabled:          parsePrometheusFeatureFlag(response.Data, "use-uncached-io"),
	}, c.optionalDiagnostic("prometheus_flags", "Prometheus runtime flags", path, true, nil)
}

func parsePrometheusFlagBool(raw string) *bool {
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	return &value
}

func parsePrometheusPositiveFloat(raw string) *float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || value <= 0 {
		return nil
	}
	return &value
}

func parsePrometheusLogLevel(raw string) string {
	switch value := strings.ToLower(strings.TrimSpace(raw)); value {
	case "debug", "info", "warn", "error":
		return value
	default:
		return ""
	}
}

func parsePrometheusReceiverFlag(flags map[string]string, key string, legacyFeature string) *bool {
	if value := parsePrometheusFlagBool(flags[key]); value != nil {
		return value
	}
	rawFeatures, exists := flags["enable-feature"]
	if !exists {
		return nil
	}
	enabled := false
	for _, feature := range strings.Split(rawFeatures, ",") {
		if strings.TrimSpace(feature) == legacyFeature {
			enabled = true
			break
		}
	}
	return &enabled
}

func parsePrometheusFeatureFlag(flags map[string]string, featureName string) *bool {
	rawFeatures, exists := flags["enable-feature"]
	if !exists {
		return nil
	}
	enabled := false
	for _, feature := range strings.Split(rawFeatures, ",") {
		if strings.TrimSpace(feature) == featureName {
			enabled = true
			break
		}
	}
	return &enabled
}

func parsePrometheusPositiveIntFlag(flags map[string]string, keys ...string) *int64 {
	for _, key := range keys {
		raw, exists := flags[key]
		if exists {
			return parsePrometheusPositiveInt(raw)
		}
	}
	return nil
}

func parsePrometheusPositiveInt(raw string) *int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return nil
	}
	return &value
}

func parsePrometheusNonNegativeInt(raw string) *int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	value, ok := new(big.Rat).SetString(raw)
	if !ok || value.Sign() < 0 || value.Denom().Cmp(big.NewInt(1)) != 0 || !value.Num().IsInt64() {
		return nil
	}
	parsed := value.Num().Int64()
	return &parsed
}

func parsePrometheusPositiveDuration(raw string) *int64 {
	seconds, ok := parsePrometheusRetentionDuration(raw)
	if !ok || seconds <= 0 {
		return nil
	}
	return &seconds
}

func (c *PrometheusConnector) series(ctx context.Context, start time.Time, end time.Time) ([]map[string]string, model.Diagnostic) {
	values := url.Values{}
	values.Add("match[]", `{__name__=~".+"}`)
	values.Set("start", strconv.FormatInt(start.Unix(), 10))
	values.Set("end", strconv.FormatInt(end.Unix(), 10))

	var response struct {
		Status string              `json:"status"`
		Data   []map[string]string `json:"data"`
		Error  string              `json:"error"`
	}
	path := "/api/v1/series?" + values.Encode()
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return nil, c.optionalDiagnostic("prometheus_recent_series", "Prometheus recent series", path, false, err)
	}
	if response.Status != "success" {
		return nil, c.optionalDiagnostic("prometheus_recent_series", "Prometheus recent series", path, false, fmt.Errorf("API status %q: %s", response.Status, response.Error))
	}
	return response.Data, c.optionalDiagnostic("prometheus_recent_series", "Prometheus recent series", path, true, nil)
}

func (c *PrometheusConnector) optionalDiagnostic(id string, name string, path string, succeeded bool, err error) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := name + " discovery completed"
	if !succeeded {
		status = model.ExecutionStatusWarning
		message = name + " endpoint is unavailable; metric discovery continued"
	}
	diagnostic := model.Diagnostic{
		ID:      id,
		Name:    name,
		Status:  status,
		Message: message,
		Metadata: map[string]string{
			"endpoint": path,
			"optional": "true",
			"system":   c.system,
		},
	}
	if err != nil {
		diagnostic.Metadata["error"] = err.Error()
	}
	return diagnostic
}

func (c *PrometheusConnector) get(ctx context.Context, path string, target any) error {
	found, err := c.getOptional(ctx, path, target)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s %s returned status %d", c.id, path, http.StatusNotFound)
	}
	return nil
}

func (c *PrometheusConnector) getOptional(ctx context.Context, path string, target any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("%s %s returned status %d", c.id, path, resp.StatusCode)
	}
	return true, json.NewDecoder(resp.Body).Decode(target)
}

type prometheusMetadata struct {
	Type string `json:"type"`
	Help string `json:"help"`
	Unit string `json:"unit"`
}

type prometheusTargetMetadata struct {
	Target map[string]string `json:"target"`
	Metric string            `json:"metric"`
	Type   string            `json:"type"`
	Help   string            `json:"help"`
	Unit   string            `json:"unit"`
}

type prometheusTSDBStat struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

type prometheusTSDBStats struct {
	Available                   bool
	HeadNumSeries               int64
	HeadChunkCount              int64
	HeadMinTime                 int64
	HeadMaxTime                 int64
	SeriesCountByMetricName     map[string]int
	LabelValueCountByLabelName  map[string]int
	MemoryInBytesByLabelName    map[string]int
	SeriesCountByLabelValuePair []prometheusTSDBStat
}

type prometheusTarget struct {
	Labels             map[string]string `json:"labels"`
	DiscoveredLabels   map[string]string `json:"discoveredLabels"`
	ScrapePool         string            `json:"scrapePool"`
	ScrapeURL          string            `json:"scrapeUrl"`
	Health             string            `json:"health"`
	LastError          string            `json:"lastError"`
	LastScrape         time.Time         `json:"lastScrape"`
	LastScrapeDuration float64           `json:"lastScrapeDuration"`
	ScrapeInterval     string            `json:"scrapeInterval"`
	ScrapeTimeout      string            `json:"scrapeTimeout"`
}

type prometheusTargetDiscovery struct {
	ActiveTargets  []prometheusTarget
	DroppedTargets []prometheusTarget
}

type prometheusAlertmanagerDiscovery struct {
	ActiveCount  int
	DroppedCount int
}

type prometheusRuntimeInfo struct {
	StartTime           string `json:"startTime"`
	ReloadConfigSuccess *bool  `json:"reloadConfigSuccess"`
	LastConfigTime      string `json:"lastConfigTime"`
	CorruptionCount     *int64 `json:"corruptionCount"`
	StorageRetention    string `json:"storageRetention"`
}

type prometheusFlags struct {
	AdminAPIEnabled            *bool
	LifecycleAPIEnabled        *bool
	RemoteWriteReceiverEnabled *bool
	OTLPReceiverEnabled        *bool
	AgentMode                  *bool
	AgentWALCompression        *bool
	AgentRetentionMinSeconds   *int64
	AgentRetentionMaxSeconds   *int64
	AgentNoLockfile            *bool
	RemoteFlushDeadlineSeconds *int64
	TSDBWALCompression         *bool
	TSDBNoLockfile             *bool
	ConcurrentRuleEvalEnabled  *bool
	RuleMaxConcurrentEvals     *int64
	AlertForOutageTolerance    *int64
	AlertForGracePeriod        *int64
	QueryMaxConcurrency        *int64
	QueryMaxSamples            *int64
	QueryTimeoutSeconds        *int64
	QueryLookbackSeconds       *int64
	RemoteReadConcurrentLimit  *int64
	RemoteReadSampleLimit      *int64
	RemoteReadFrameBytes       *int64
	SearchAPIEnabled           *bool
	SearchMaxLimit             *int64
	WebMaxConnections          *int64
	WebReadTimeoutSeconds      *int64
	NotificationQueueCapacity  *int64
	DrainNotificationQueue     *bool
	AlertResendDelaySeconds    *int64
	NotificationBatchSize      *int64
	AutoGOMAXPROCSEnabled      *bool
	AutoGOMEMLIMITEnabled      *bool
	AutoGOMEMLIMITRatio        *float64
	ConfigAutoReloadEnabled    *bool
	AutoReloadIntervalSeconds  *int64
	MaxNotificationSubscribers *int64
	LogLevel                   string
	ExemplarStorageEnabled     *bool
	ExtraScrapeMetricsEnabled  *bool
	CreatedTimestampZero       *bool
	OTLPDeltaToCumulative      *bool
	XOR2EncodingEnabled        *bool
	STStorageEnabled           *bool
	STSynthesisEnabled         *bool
	OTLPNativeDeltaEnabled     *bool
	MetadataWALRecordsEnabled  *bool
	TypeUnitLabelsEnabled      *bool
	UncachedIOEnabled          *bool
}

type prometheusRules struct {
	Groups []prometheusRuleGroup `json:"groups"`
}

type prometheusRuleGroup struct {
	Name           string           `json:"name"`
	File           string           `json:"file"`
	Interval       float64          `json:"interval"`
	EvaluationTime float64          `json:"evaluationTime"`
	LastEvaluation time.Time        `json:"lastEvaluation"`
	Rules          []prometheusRule `json:"rules"`
}

type prometheusRule struct {
	Type           string            `json:"type"`
	Name           string            `json:"name"`
	Query          string            `json:"query"`
	Labels         map[string]string `json:"labels"`
	Annotations    map[string]string `json:"annotations"`
	Health         string            `json:"health"`
	Duration       float64           `json:"duration"`
	LastError      string            `json:"lastError"`
	EvaluationTime float64           `json:"evaluationTime"`
	LastEvaluation time.Time         `json:"lastEvaluation"`
}

type prometheusAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	State       string            `json:"state"`
	ActiveAt    time.Time         `json:"activeAt"`
	Value       string            `json:"value"`
}

func (c *PrometheusConnector) resource(resourceType model.ResourceType, name string, externalID string, now time.Time) model.Resource {
	uid := model.StableID(string(resourceType), c.system, c.baseURL, externalID)
	return model.Resource{
		ID:        uid,
		Type:      resourceType,
		Name:      name,
		UID:       uid,
		Source:    model.SourceInfo{System: c.system, Instance: c.baseURL, ExternalID: externalID},
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func prometheusResource(resourceType model.ResourceType, name string, instance string, externalID string, now time.Time) model.Resource {
	uid := model.StableID(string(resourceType), prometheusSystem, instance, externalID)
	return model.Resource{
		ID:        uid,
		Type:      resourceType,
		Name:      name,
		UID:       uid,
		Source:    model.SourceInfo{System: prometheusSystem, Instance: instance, ExternalID: externalID},
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *PrometheusConnector) relationship(fromID, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID(fromID, string(relationshipType), toID),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}

func (c *PrometheusConnector) ruleResource(group prometheusRuleGroup, rule prometheusRule, now time.Time) (model.Resource, bool) {
	var resourceType model.ResourceType
	switch rule.Type {
	case "alerting":
		resourceType = model.ResourceTypeAlertRule
	case "recording":
		resourceType = model.ResourceTypeRecordingRule
	default:
		return model.Resource{}, false
	}

	name := rule.Name
	if name == "" {
		name = rule.Query
	}
	resource := c.resource(resourceType, name, prometheusRuleExternalID(group, rule, name), now)
	resource.Labels = cloneLabels(rule.Labels)
	resource.Metadata = map[string]string{
		model.MetadataHealth: rule.Health,
	}
	setQueryMetadata(resource.Metadata, model.MetadataPromQL, rule.Query)
	if rule.Type == "recording" && rule.Name != "" {
		resource.Metadata[model.MetadataRecordingRuleOutput] = rule.Name
	}
	if group.Name != "" {
		resource.Metadata[model.MetadataRuleGroup] = group.Name
	}
	if group.File != "" {
		resource.Metadata[model.MetadataRuleFile] = group.File
	}
	if group.Interval > 0 {
		resource.Metadata[model.MetadataEvaluationInterval] = prometheusDuration(group.Interval)
	}
	if rule.EvaluationTime > 0 {
		resource.Metadata[model.MetadataEvaluationTime] = prometheusDuration(rule.EvaluationTime)
	} else if group.EvaluationTime > 0 {
		resource.Metadata[model.MetadataEvaluationTime] = prometheusDuration(group.EvaluationTime)
	}
	if !rule.LastEvaluation.IsZero() {
		resource.Metadata[model.MetadataLastEvaluation] = rule.LastEvaluation.Format(time.RFC3339)
	} else if !group.LastEvaluation.IsZero() {
		resource.Metadata[model.MetadataLastEvaluation] = group.LastEvaluation.Format(time.RFC3339)
	}
	if rule.LastError != "" {
		resource.Metadata[model.MetadataLastError] = rule.LastError
	}
	if rule.Duration > 0 {
		resource.Metadata[model.MetadataAlertFor] = prometheusDuration(rule.Duration)
	}
	for key, value := range rule.Annotations {
		if key == "" || value == "" {
			continue
		}
		resource.Metadata["annotation."+key] = value
	}
	if rule.Health != "" && !strings.EqualFold(rule.Health, "ok") {
		resource.Status = model.ResourceStatusBroken
	}
	annotateSLORuleMetadata(&resource)
	return resource, true
}

func prometheusRuleExternalID(group prometheusRuleGroup, rule prometheusRule, name string) string {
	if rule.Type != "recording" {
		return "rule:" + rule.Type + ":" + name
	}
	parts := []string{"rule", rule.Type}
	if group.File != "" {
		parts = append(parts, "file:"+group.File)
	}
	if group.Name != "" {
		parts = append(parts, "group:"+group.Name)
	}
	parts = append(parts, "name:"+name)
	return strings.Join(parts, ":")
}

func prometheusDuration(seconds float64) string {
	duration := time.Duration(seconds * float64(time.Second))
	if duration <= 0 {
		return ""
	}
	return duration.String()
}

func (c *PrometheusConnector) alertResource(alert prometheusAlert, now time.Time) model.Resource {
	alertName := strings.TrimSpace(alert.Labels["alertname"])
	if alertName == "" {
		alertName = "alert"
	}
	fingerprint := alertFingerprint(alert.Labels)
	resource := c.resource(model.ResourceTypeAlert, alertName, "alert:"+fingerprint, now)
	resource.Labels = cloneLabels(alert.Labels)
	resource.Metadata = map[string]string{
		model.MetadataAlertState:  alert.State,
		model.MetadataFingerprint: fingerprint,
	}
	if !alert.ActiveAt.IsZero() {
		resource.Metadata[model.MetadataStartsAt] = alert.ActiveAt.Format(time.RFC3339)
	}
	if alert.Value != "" {
		resource.Metadata[model.MetadataAlertValue] = alert.Value
	}
	for key, value := range alert.Annotations {
		if key == "" || value == "" {
			continue
		}
		resource.Metadata["annotation."+key] = value
	}
	return resource
}

func metricMetadata(items []prometheusMetadata) map[string]string {
	metadata := make(map[string]string)
	if len(items) == 0 {
		return metadata
	}
	types := prometheusMetadataValues(items, func(item prometheusMetadata) string { return item.Type })
	helpTexts := prometheusMetadataValues(items, func(item prometheusMetadata) string { return item.Help })
	units := prometheusMetadataValues(items, func(item prometheusMetadata) string { return item.Unit })
	setMetricMetadataValue(metadata, model.MetadataMetricType, model.MetadataMetricTypeVariants, types)
	setMetricMetadataValue(metadata, model.MetadataMetricHelp, model.MetadataMetricHelpVariants, helpTexts)
	setMetricMetadataValue(metadata, model.MetadataMetricUnit, model.MetadataMetricUnitVariants, units)
	return metadata
}

func prometheusMetadataValues(items []prometheusMetadata, value func(prometheusMetadata) string) []string {
	seen := make(map[string]bool)
	values := make([]string, 0)
	for _, item := range items {
		candidate := strings.TrimSpace(value(item))
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		values = append(values, candidate)
	}
	return values
}

func setMetricMetadataValue(metadata map[string]string, valueKey string, variantsKey string, values []string) {
	if len(values) == 0 {
		return
	}
	metadata[valueKey] = values[0]
	if len(values) <= 1 {
		return
	}
	encoded, err := json.Marshal(values)
	if err == nil {
		metadata[variantsKey] = string(encoded)
	}
}

func mergeTargetMetadata(metricNames []string, metadata map[string][]prometheusMetadata, targetMetadata []prometheusTargetMetadata) []string {
	seenNames := make(map[string]bool, len(metricNames)+len(targetMetadata))
	mergedNames := make([]string, 0, len(metricNames)+len(targetMetadata))
	for _, name := range metricNames {
		name = strings.TrimSpace(name)
		if name == "" || seenNames[name] {
			continue
		}
		seenNames[name] = true
		mergedNames = append(mergedNames, name)
	}
	for _, item := range targetMetadata {
		name := strings.TrimSpace(item.Metric)
		if name == "" {
			continue
		}
		candidate := prometheusMetadata{Type: item.Type, Help: item.Help, Unit: item.Unit}
		if !containsPrometheusMetadata(metadata[name], candidate) {
			metadata[name] = append(metadata[name], candidate)
		}
		if !seenNames[name] {
			seenNames[name] = true
			mergedNames = append(mergedNames, name)
		}
	}
	sort.Strings(mergedNames)
	return mergedNames
}

func containsPrometheusMetadata(items []prometheusMetadata, candidate prometheusMetadata) bool {
	for _, item := range items {
		if item == candidate {
			return true
		}
	}
	return false
}

func targetMetadataSeries(targetMetadata []prometheusTargetMetadata) []map[string]string {
	series := make([]map[string]string, 0, len(targetMetadata))
	for _, item := range targetMetadata {
		metricName := strings.TrimSpace(item.Metric)
		if metricName == "" {
			continue
		}
		labels := cloneLabels(item.Target)
		labels["__name__"] = metricName
		series = append(series, labels)
	}
	return series
}

func addSeriesCount(metadata map[string]string, metricName string, recentCount int, tsdbCounts map[string]int) {
	if recentCount > 0 {
		metadata[model.MetadataRecentSeriesCount] = strconv.Itoa(recentCount)
	}
	if tsdbCount := tsdbCounts[metricName]; tsdbCount > 0 {
		metadata[model.MetadataTSDBHeadSeriesCount] = strconv.Itoa(tsdbCount)
		metadata[model.MetadataSeriesCount] = strconv.Itoa(tsdbCount)
		metadata[model.MetadataSeriesCountSource] = "tsdb_head"
		return
	}
	if recentCount > 0 {
		metadata[model.MetadataSeriesCount] = strconv.Itoa(recentCount)
		metadata[model.MetadataSeriesCountSource] = "recent_1h"
	}
}

func prometheusTSDBStatMap(items []prometheusTSDBStat, excludeInternalLabels bool) map[string]int {
	values := make(map[string]int, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" || item.Value <= 0 || (excludeInternalLabels && isPrometheusInternalLabel(name)) {
			continue
		}
		values[name] = item.Value
	}
	return values
}

func addTSDBResource(
	c *PrometheusConnector,
	resources map[string]model.Resource,
	stats prometheusTSDBStats,
	targets []prometheusTarget,
	droppedTargets []prometheusTarget,
	rules prometheusRules,
	alertmanagers prometheusAlertmanagerDiscovery,
	runtimeInfo prometheusRuntimeInfo,
	flags prometheusFlags,
	targetsDiagnostic model.Diagnostic,
	rulesDiagnostic model.Diagnostic,
	alertmanagersDiagnostic model.Diagnostic,
	runtimeDiagnostic model.Diagnostic,
	flagsDiagnostic model.Diagnostic,
	now time.Time,
) {
	resource := c.resource(model.ResourceTypeTSDB, c.system+" TSDB", "tsdb", now)
	resource.Metadata = map[string]string{
		model.MetadataTargetsDiscoveryAvailable:      strconv.FormatBool(targetsDiagnostic.Status == model.ExecutionStatusSucceeded),
		model.MetadataActiveTargetCount:              strconv.Itoa(len(targets)),
		model.MetadataDroppedTargetCount:             strconv.Itoa(len(droppedTargets)),
		model.MetadataRulesDiscoveryAvailable:        strconv.FormatBool(rulesDiagnostic.Status == model.ExecutionStatusSucceeded),
		model.MetadataAlertingRuleCount:              strconv.Itoa(prometheusAlertingRuleCount(rules)),
		model.MetadataPrometheusAMDiscoveryAvailable: strconv.FormatBool(prometheusDiagnosticAvailable(alertmanagersDiagnostic)),
		model.MetadataPrometheusActiveAMCount:        strconv.Itoa(alertmanagers.ActiveCount),
		model.MetadataPrometheusDroppedAMCount:       strconv.Itoa(alertmanagers.DroppedCount),
		model.MetadataPrometheusRuntimeAvailable:     strconv.FormatBool(prometheusDiagnosticAvailable(runtimeDiagnostic)),
		model.MetadataPrometheusFlagsAvailable:       strconv.FormatBool(prometheusDiagnosticAvailable(flagsDiagnostic)),
	}
	if runtimeInfo.ReloadConfigSuccess != nil {
		resource.Metadata[model.MetadataPrometheusReloadSuccess] = strconv.FormatBool(*runtimeInfo.ReloadConfigSuccess)
	}
	if runtimeInfo.CorruptionCount != nil {
		resource.Metadata[model.MetadataPrometheusCorruptionCount] = strconv.FormatInt(*runtimeInfo.CorruptionCount, 10)
	}
	if timestamp, ok := prometheusRuntimeTimestamp(runtimeInfo.StartTime); ok {
		resource.Metadata[model.MetadataPrometheusStartedAt] = timestamp
	}
	if timestamp, ok := prometheusRuntimeTimestamp(runtimeInfo.LastConfigTime); ok {
		resource.Metadata[model.MetadataPrometheusLastConfigAt] = timestamp
	}
	if retention := strings.TrimSpace(runtimeInfo.StorageRetention); retention != "" {
		resource.Metadata[model.MetadataPrometheusStorageRetention] = retention
		if seconds, ok := parsePrometheusRetentionDuration(retention); ok {
			resource.Metadata[model.MetadataPrometheusRetentionSeconds] = strconv.FormatInt(seconds, 10)
		}
	}
	if flags.AdminAPIEnabled != nil {
		resource.Metadata[model.MetadataPrometheusAdminAPIEnabled] = strconv.FormatBool(*flags.AdminAPIEnabled)
	}
	if flags.LifecycleAPIEnabled != nil {
		resource.Metadata[model.MetadataPrometheusLifecycleAPIEnabled] = strconv.FormatBool(*flags.LifecycleAPIEnabled)
	}
	if flags.RemoteWriteReceiverEnabled != nil {
		resource.Metadata[model.MetadataPrometheusRemoteWriteReceiver] = strconv.FormatBool(*flags.RemoteWriteReceiverEnabled)
	}
	if flags.OTLPReceiverEnabled != nil {
		resource.Metadata[model.MetadataPrometheusOTLPReceiver] = strconv.FormatBool(*flags.OTLPReceiverEnabled)
	}
	if flags.AgentMode != nil {
		resource.Metadata[model.MetadataPrometheusAgentMode] = strconv.FormatBool(*flags.AgentMode)
	}
	if flags.AgentWALCompression != nil {
		resource.Metadata[model.MetadataPrometheusAgentWALCompression] = strconv.FormatBool(*flags.AgentWALCompression)
	}
	if flags.AgentRetentionMinSeconds != nil {
		resource.Metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = strconv.FormatInt(*flags.AgentRetentionMinSeconds, 10)
	}
	if flags.AgentRetentionMaxSeconds != nil {
		resource.Metadata[model.MetadataPrometheusAgentRetentionMaxSeconds] = strconv.FormatInt(*flags.AgentRetentionMaxSeconds, 10)
	}
	if flags.AgentNoLockfile != nil {
		resource.Metadata[model.MetadataPrometheusAgentNoLockfile] = strconv.FormatBool(*flags.AgentNoLockfile)
	}
	if flags.RemoteFlushDeadlineSeconds != nil {
		resource.Metadata[model.MetadataPrometheusRemoteFlushDeadline] = strconv.FormatInt(*flags.RemoteFlushDeadlineSeconds, 10)
	}
	if flags.TSDBWALCompression != nil {
		resource.Metadata[model.MetadataPrometheusTSDBWALCompression] = strconv.FormatBool(*flags.TSDBWALCompression)
	}
	if flags.TSDBNoLockfile != nil {
		resource.Metadata[model.MetadataPrometheusTSDBNoLockfile] = strconv.FormatBool(*flags.TSDBNoLockfile)
	}
	if flags.ConcurrentRuleEvalEnabled != nil {
		resource.Metadata[model.MetadataPrometheusConcurrentRuleEval] = strconv.FormatBool(*flags.ConcurrentRuleEvalEnabled)
	}
	if flags.RuleMaxConcurrentEvals != nil {
		resource.Metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] = strconv.FormatInt(*flags.RuleMaxConcurrentEvals, 10)
	}
	if flags.AlertForOutageTolerance != nil {
		resource.Metadata[model.MetadataPrometheusAlertForOutageTolerance] = strconv.FormatInt(*flags.AlertForOutageTolerance, 10)
	}
	if flags.AlertForGracePeriod != nil {
		resource.Metadata[model.MetadataPrometheusAlertForGracePeriod] = strconv.FormatInt(*flags.AlertForGracePeriod, 10)
		if rulesDiagnostic.Status == model.ExecutionStatusSucceeded {
			resource.Metadata[model.MetadataPrometheusAlertForBelowGraceCount] = strconv.Itoa(prometheusAlertForBelowGraceCount(rules, *flags.AlertForGracePeriod))
		}
	}
	if flags.QueryMaxConcurrency != nil {
		resource.Metadata[model.MetadataPrometheusQueryMaxConcurrency] = strconv.FormatInt(*flags.QueryMaxConcurrency, 10)
	}
	if flags.QueryMaxSamples != nil {
		resource.Metadata[model.MetadataPrometheusQueryMaxSamples] = strconv.FormatInt(*flags.QueryMaxSamples, 10)
	}
	if flags.QueryTimeoutSeconds != nil {
		resource.Metadata[model.MetadataPrometheusQueryTimeoutSeconds] = strconv.FormatInt(*flags.QueryTimeoutSeconds, 10)
	}
	if flags.QueryLookbackSeconds != nil {
		resource.Metadata[model.MetadataPrometheusQueryLookbackSeconds] = strconv.FormatInt(*flags.QueryLookbackSeconds, 10)
	}
	if flags.RemoteReadConcurrentLimit != nil {
		resource.Metadata[model.MetadataPrometheusRemoteReadConcurrentLimit] = strconv.FormatInt(*flags.RemoteReadConcurrentLimit, 10)
	}
	if flags.RemoteReadSampleLimit != nil {
		resource.Metadata[model.MetadataPrometheusRemoteReadSampleLimit] = strconv.FormatInt(*flags.RemoteReadSampleLimit, 10)
	}
	if flags.RemoteReadFrameBytes != nil {
		resource.Metadata[model.MetadataPrometheusRemoteReadFrameBytes] = strconv.FormatInt(*flags.RemoteReadFrameBytes, 10)
	}
	if flags.SearchAPIEnabled != nil {
		resource.Metadata[model.MetadataPrometheusSearchAPIEnabled] = strconv.FormatBool(*flags.SearchAPIEnabled)
	}
	if flags.SearchMaxLimit != nil {
		resource.Metadata[model.MetadataPrometheusSearchMaxLimit] = strconv.FormatInt(*flags.SearchMaxLimit, 10)
	}
	if flags.WebMaxConnections != nil {
		resource.Metadata[model.MetadataPrometheusWebMaxConnections] = strconv.FormatInt(*flags.WebMaxConnections, 10)
	}
	if flags.WebReadTimeoutSeconds != nil {
		resource.Metadata[model.MetadataPrometheusWebReadTimeoutSeconds] = strconv.FormatInt(*flags.WebReadTimeoutSeconds, 10)
	}
	if flags.NotificationQueueCapacity != nil {
		resource.Metadata[model.MetadataPrometheusNotificationQueueCapacity] = strconv.FormatInt(*flags.NotificationQueueCapacity, 10)
	}
	if flags.DrainNotificationQueue != nil {
		resource.Metadata[model.MetadataPrometheusDrainNotificationQueue] = strconv.FormatBool(*flags.DrainNotificationQueue)
	}
	if flags.AlertResendDelaySeconds != nil {
		resource.Metadata[model.MetadataPrometheusAlertResendDelay] = strconv.FormatInt(*flags.AlertResendDelaySeconds, 10)
	}
	if flags.NotificationBatchSize != nil {
		resource.Metadata[model.MetadataPrometheusNotificationBatchSize] = strconv.FormatInt(*flags.NotificationBatchSize, 10)
	}
	if flags.AutoGOMAXPROCSEnabled != nil {
		resource.Metadata[model.MetadataPrometheusAutoGOMAXPROCSEnabled] = strconv.FormatBool(*flags.AutoGOMAXPROCSEnabled)
	}
	if flags.AutoGOMEMLIMITEnabled != nil {
		resource.Metadata[model.MetadataPrometheusAutoGOMEMLIMITEnabled] = strconv.FormatBool(*flags.AutoGOMEMLIMITEnabled)
	}
	if flags.AutoGOMEMLIMITRatio != nil {
		resource.Metadata[model.MetadataPrometheusAutoGOMEMLIMITRatio] = strconv.FormatFloat(*flags.AutoGOMEMLIMITRatio, 'f', -1, 64)
	}
	if flags.ConfigAutoReloadEnabled != nil {
		resource.Metadata[model.MetadataPrometheusConfigAutoReloadEnabled] = strconv.FormatBool(*flags.ConfigAutoReloadEnabled)
	}
	if flags.AutoReloadIntervalSeconds != nil {
		resource.Metadata[model.MetadataPrometheusAutoReloadIntervalSeconds] = strconv.FormatInt(*flags.AutoReloadIntervalSeconds, 10)
	}
	if flags.MaxNotificationSubscribers != nil {
		resource.Metadata[model.MetadataPrometheusMaxNotificationSubscribers] = strconv.FormatInt(*flags.MaxNotificationSubscribers, 10)
	}
	if flags.LogLevel != "" {
		resource.Metadata[model.MetadataPrometheusLogLevel] = flags.LogLevel
	}
	if flags.ExemplarStorageEnabled != nil {
		resource.Metadata[model.MetadataPrometheusExemplarStorageEnabled] = strconv.FormatBool(*flags.ExemplarStorageEnabled)
	}
	if flags.ExtraScrapeMetricsEnabled != nil {
		resource.Metadata[model.MetadataPrometheusExtraScrapeMetricsEnabled] = strconv.FormatBool(*flags.ExtraScrapeMetricsEnabled)
	}
	if flags.CreatedTimestampZero != nil {
		resource.Metadata[model.MetadataPrometheusCreatedTimestampZero] = strconv.FormatBool(*flags.CreatedTimestampZero)
	}
	if flags.OTLPDeltaToCumulative != nil {
		resource.Metadata[model.MetadataPrometheusOTLPDeltaToCumulative] = strconv.FormatBool(*flags.OTLPDeltaToCumulative)
	}
	if flags.XOR2EncodingEnabled != nil {
		resource.Metadata[model.MetadataPrometheusXOR2EncodingEnabled] = strconv.FormatBool(*flags.XOR2EncodingEnabled)
	}
	if flags.STStorageEnabled != nil {
		resource.Metadata[model.MetadataPrometheusSTStorageEnabled] = strconv.FormatBool(*flags.STStorageEnabled)
	}
	if flags.STSynthesisEnabled != nil {
		resource.Metadata[model.MetadataPrometheusSTSynthesisEnabled] = strconv.FormatBool(*flags.STSynthesisEnabled)
	}
	if flags.OTLPNativeDeltaEnabled != nil {
		resource.Metadata[model.MetadataPrometheusOTLPNativeDeltaEnabled] = strconv.FormatBool(*flags.OTLPNativeDeltaEnabled)
	}
	if flags.MetadataWALRecordsEnabled != nil {
		resource.Metadata[model.MetadataPrometheusMetadataWALRecordsEnabled] = strconv.FormatBool(*flags.MetadataWALRecordsEnabled)
	}
	if flags.TypeUnitLabelsEnabled != nil {
		resource.Metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] = strconv.FormatBool(*flags.TypeUnitLabelsEnabled)
	}
	if flags.UncachedIOEnabled != nil {
		resource.Metadata[model.MetadataPrometheusUncachedIOEnabled] = strconv.FormatBool(*flags.UncachedIOEnabled)
	}
	if flags.AgentMode != nil && !*flags.AgentMode &&
		flags.ConcurrentRuleEvalEnabled != nil && *flags.ConcurrentRuleEvalEnabled &&
		flags.RuleMaxConcurrentEvals != nil && flags.QueryMaxConcurrency != nil {
		headroom := *flags.QueryMaxConcurrency - *flags.RuleMaxConcurrentEvals
		resource.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom] = strconv.FormatInt(headroom, 10)
	}
	operatorTargetCount := 0
	operatorDroppedTargetCount := 0
	for _, target := range targets {
		if _, _, _, _, ok := parsePrometheusOperatorScrapePool(target.ScrapePool); ok {
			operatorTargetCount++
		}
	}
	for _, target := range droppedTargets {
		if _, _, _, _, ok := parsePrometheusOperatorScrapePool(target.ScrapePool); ok {
			operatorDroppedTargetCount++
		}
	}
	resource.Metadata[model.MetadataOperatorTargetCount] = strconv.Itoa(operatorTargetCount)
	resource.Metadata[model.MetadataOperatorDroppedTargetCount] = strconv.Itoa(operatorDroppedTargetCount)
	setPositiveInt64Metadata(resource.Metadata, model.MetadataTSDBHeadSeries, stats.HeadNumSeries)
	setPositiveInt64Metadata(resource.Metadata, model.MetadataTSDBHeadChunks, stats.HeadChunkCount)
	setPositiveInt64Metadata(resource.Metadata, model.MetadataTSDBHeadMinTime, stats.HeadMinTime)
	setPositiveInt64Metadata(resource.Metadata, model.MetadataTSDBHeadMaxTime, stats.HeadMaxTime)
	if stats.HeadMaxTime > stats.HeadMinTime && stats.HeadMinTime > 0 {
		resource.Metadata[model.MetadataTSDBHeadRangeSeconds] = strconv.FormatInt((stats.HeadMaxTime-stats.HeadMinTime)/1000, 10)
	}
	setPositiveInt64Metadata(resource.Metadata, model.MetadataTSDBLabelValueCount, sumIntMap(stats.LabelValueCountByLabelName))
	setPositiveInt64Metadata(resource.Metadata, model.MetadataTSDBLabelMemoryBytes, sumIntMap(stats.MemoryInBytesByLabelName))
	addResource(resources, resource)
}

func prometheusDiagnosticAvailable(diagnostic model.Diagnostic) bool {
	return diagnostic.Status == model.ExecutionStatusSucceeded && diagnostic.Metadata["skipped"] != "true"
}

func prometheusRuntimeTimestamp(raw string) (string, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, strings.TrimSpace(raw))
		if err == nil {
			return parsed.UTC().Format(time.RFC3339), true
		}
	}
	return "", false
}

func prometheusAlertingRuleCount(rules prometheusRules) int {
	count := 0
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			if rule.Type == "alerting" {
				count++
			}
		}
	}
	return count
}

func prometheusAlertForBelowGraceCount(rules prometheusRules, graceSeconds int64) int {
	count := 0
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			if rule.Type == "alerting" && rule.Duration > 0 && rule.Duration < float64(graceSeconds) {
				count++
			}
		}
	}
	return count
}

func diagnosticByID(diagnostics []model.Diagnostic, id string) model.Diagnostic {
	for _, diagnostic := range diagnostics {
		if diagnostic.ID == id {
			return diagnostic
		}
	}
	return model.Diagnostic{}
}

func applyPrometheusOperatorScrapePool(resource *model.Resource, scrapePool string) {
	kind, namespace, name, endpoint, ok := parsePrometheusOperatorScrapePool(scrapePool)
	if resource == nil || !ok {
		return
	}
	resource.Metadata[model.MetadataOperatorMonitorKind] = kind
	resource.Metadata[model.MetadataOperatorMonitorNamespace] = namespace
	resource.Metadata[model.MetadataOperatorMonitorName] = name
	if endpoint != "" {
		resource.Metadata[model.MetadataOperatorMonitorEndpoint] = endpoint
	}
}

func parsePrometheusOperatorScrapePool(scrapePool string) (kind string, namespace string, name string, endpoint string, ok bool) {
	parts := strings.Split(strings.TrimSpace(scrapePool), "/")
	if len(parts) < 3 {
		return "", "", "", "", false
	}
	switch parts[0] {
	case "serviceMonitor":
		kind = "ServiceMonitor"
	case "podMonitor":
		kind = "PodMonitor"
	case "probe":
		kind = "Probe"
	case "scrapeConfig":
		kind = "ScrapeConfig"
	default:
		return "", "", "", "", false
	}
	namespace = strings.TrimSpace(parts[1])
	name = strings.TrimSpace(parts[2])
	if namespace == "" || name == "" {
		return "", "", "", "", false
	}
	if len(parts) > 3 {
		endpoint = strings.TrimSpace(strings.Join(parts[3:], "/"))
	}
	return kind, namespace, name, endpoint, true
}

func setPositiveInt64Metadata(metadata map[string]string, key string, value int64) {
	if value > 0 {
		metadata[key] = strconv.FormatInt(value, 10)
	}
}

func sumIntMap(values map[string]int) int64 {
	var total int64
	for _, value := range values {
		if value > 0 {
			total += int64(value)
		}
	}
	return total
}

func addMetricLabelResources(c *PrometheusConnector, resources map[string]model.Resource, relationships *[]model.Relationship, summaries map[string]metricLabelSummary, stats prometheusTSDBStats, now time.Time) {
	labelNames := make(map[string]bool)
	for _, summary := range summaries {
		for labelName := range summary.Values {
			if !isPrometheusInternalLabel(labelName) {
				labelNames[labelName] = true
			}
		}
	}
	for labelName := range stats.LabelValueCountByLabelName {
		labelNames[labelName] = true
	}
	for labelName := range stats.MemoryInBytesByLabelName {
		labelNames[labelName] = true
	}

	topPairs := topTSDBLabelPairs(stats.SeriesCountByLabelValuePair)
	for labelName := range topPairs {
		labelNames[labelName] = true
	}
	for _, labelName := range sortedBoolKeys(labelNames) {
		labelResource := c.resource(model.ResourceTypeMetricLabel, labelName, "metric-label:"+labelName, now)
		labelResource.Metadata = map[string]string{model.MetadataMetricLabel: labelName}
		if count := stats.LabelValueCountByLabelName[labelName]; count > 0 {
			labelResource.Metadata[model.MetadataMetricLabelValueCount] = strconv.Itoa(count)
		}
		if memoryBytes := stats.MemoryInBytesByLabelName[labelName]; memoryBytes > 0 {
			labelResource.Metadata[model.MetadataMetricLabelMemoryBytes] = strconv.Itoa(memoryBytes)
		}
		if pair, ok := topPairs[labelName]; ok {
			labelResource.Metadata[model.MetadataMetricLabelTopValue] = pair.Value
			labelResource.Metadata[model.MetadataMetricLabelTopSeries] = strconv.Itoa(pair.SeriesCount)
		}
		addResource(resources, labelResource)
	}

	for metricName, summary := range summaries {
		metricResource := c.resource(model.ResourceTypeMetric, metricName, "metric:"+metricName, now)
		if _, ok := resources[metricResource.ID]; !ok {
			continue
		}
		for _, labelName := range sortedLabelKeys(summary.Values) {
			if isPrometheusInternalLabel(labelName) {
				continue
			}
			labelResource := c.resource(model.ResourceTypeMetricLabel, labelName, "metric-label:"+labelName, now)
			*relationships = append(*relationships, c.relationship(metricResource.ID, labelResource.ID, model.RelationshipUses, now))
		}
	}
}

type prometheusTSDBLabelPair struct {
	Value       string
	SeriesCount int
}

func topTSDBLabelPairs(items []prometheusTSDBStat) map[string]prometheusTSDBLabelPair {
	pairs := make(map[string]prometheusTSDBLabelPair)
	for _, item := range items {
		labelName, value, ok := strings.Cut(strings.TrimSpace(item.Name), "=")
		labelName = strings.TrimSpace(labelName)
		if !ok || labelName == "" || isPrometheusInternalLabel(labelName) || item.Value <= 0 {
			continue
		}
		if current, exists := pairs[labelName]; !exists || item.Value > current.SeriesCount {
			pairs[labelName] = prometheusTSDBLabelPair{Value: value, SeriesCount: item.Value}
		}
	}
	return pairs
}

func isPrometheusInternalLabel(labelName string) bool {
	return strings.HasPrefix(strings.TrimSpace(labelName), "__")
}

func sortedBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type metricLabelSummary struct {
	Values    map[string]map[string]bool
	Truncated map[string]bool
}

func metricLabelSummaries(series []map[string]string) map[string]metricLabelSummary {
	summaries := make(map[string]metricLabelSummary)
	for _, item := range series {
		metricName := item["__name__"]
		if metricName == "" {
			continue
		}
		summary := summaries[metricName]
		if summary.Values == nil {
			summary.Values = map[string]map[string]bool{}
			summary.Truncated = map[string]bool{}
		}
		for key, value := range item {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "" || key == "__name__" || value == "" {
				continue
			}
			if summary.Values[key] == nil {
				summary.Values[key] = map[string]bool{}
			}
			if summary.Values[key][value] {
				continue
			}
			if len(summary.Values[key]) < prometheusMetricLabelValueLimit {
				summary.Values[key][value] = true
			} else {
				summary.Truncated[key] = true
			}
		}
		summaries[metricName] = summary
	}
	return summaries
}

func applyMetricLabelSummary(resource *model.Resource, summary metricLabelSummary) {
	if resource == nil || len(summary.Values) == 0 {
		return
	}
	if resource.Labels == nil {
		resource.Labels = map[string]string{}
	}
	if resource.Metadata == nil {
		resource.Metadata = map[string]string{}
	}

	keys := sortedLabelKeys(summary.Values)
	resource.Metadata[model.MetadataMetricLabelKeys] = strings.Join(keys, ",")
	for _, key := range keys {
		values := sortedLabelValues(summary.Values[key])
		if len(values) == 0 {
			continue
		}
		resource.Metadata["metric_label_values."+key] = strings.Join(values, ",")
		if summary.Truncated[key] {
			resource.Metadata["metric_label_values_truncated."+key] = "true"
		}
		if len(values) == 1 && resource.Labels[key] == "" {
			resource.Labels[key] = values[0]
		}
	}
}

func applyTargetDiscoveredLabels(resource *model.Resource, discovered map[string]string) {
	if resource == nil || len(discovered) == 0 {
		return
	}
	if resource.Labels == nil {
		resource.Labels = map[string]string{}
	}
	if resource.Metadata == nil {
		resource.Metadata = map[string]string{}
	}
	keys := sortedStringKeys(discovered)
	if len(keys) > 0 {
		resource.Metadata["target_discovered_label_keys"] = strings.Join(keys, ",")
	}
	for _, mapping := range prometheusDiscoveredLabelMappings() {
		value := strings.TrimSpace(discovered[mapping.Source])
		if value == "" {
			continue
		}
		resource.Metadata["target_discovered_label."+mapping.Target] = value
		if resource.Metadata[mapping.Target] == "" {
			resource.Metadata[mapping.Target] = value
		}
		if resource.Labels[mapping.Target] == "" {
			resource.Labels[mapping.Target] = value
		}
	}
}

type prometheusDiscoveredLabelMapping struct {
	Source string
	Target string
}

func prometheusDiscoveredLabelMappings() []prometheusDiscoveredLabelMapping {
	return []prometheusDiscoveredLabelMapping{
		{Source: "__meta_kubernetes_namespace", Target: "namespace"},
		{Source: "__meta_kubernetes_service_name", Target: model.MetadataService},
		{Source: "__meta_kubernetes_pod_name", Target: "pod"},
		{Source: "__meta_kubernetes_service_label_app", Target: "app"},
		{Source: "__meta_kubernetes_pod_label_app", Target: "app"},
		{Source: "__meta_kubernetes_service_label_app_kubernetes_io_name", Target: "app.kubernetes.io/name"},
		{Source: "__meta_kubernetes_pod_label_app_kubernetes_io_name", Target: "app.kubernetes.io/name"},
		{Source: "__meta_kubernetes_service_label_team", Target: "team"},
		{Source: "__meta_kubernetes_pod_label_team", Target: "team"},
		{Source: "__meta_kubernetes_service_label_owner", Target: model.MetadataOwner},
		{Source: "__meta_kubernetes_pod_label_owner", Target: model.MetadataOwner},
	}
}

func seriesCountByMetric(series []map[string]string) map[string]int {
	counts := make(map[string]int)
	for _, item := range series {
		metricName := item["__name__"]
		if metricName == "" {
			continue
		}
		counts[metricName]++
	}
	return counts
}

func sortedLabelKeys(values map[string]map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedLabelValues(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func addResource(resources map[string]model.Resource, resource model.Resource) {
	if _, ok := resources[resource.ID]; ok {
		return
	}
	resources[resource.ID] = resource
}

func mergeResourceLabels(resources map[string]model.Resource, resource model.Resource) {
	existing, ok := resources[resource.ID]
	if !ok {
		annotateSLORuleMetadata(&resource)
		resources[resource.ID] = resource
		return
	}
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	for key, value := range resource.Labels {
		if key == "" || value == "" {
			continue
		}
		if existing.Labels[key] == "" {
			existing.Labels[key] = value
		}
	}
	annotateSLORuleMetadata(&existing)
	resources[resource.ID] = existing
}

type prometheusResourceContext struct {
	TargetCount int
	Labels      map[string]string
}

func addPrometheusResourceContext(contexts map[string]*prometheusResourceContext, resourceID string, labels map[string]string) {
	resourceContext := contexts[resourceID]
	if resourceContext == nil {
		resourceContext = &prometheusResourceContext{Labels: cloneLabels(labels)}
		for key, value := range resourceContext.Labels {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				delete(resourceContext.Labels, key)
			}
		}
		contexts[resourceID] = resourceContext
	} else {
		for key, value := range resourceContext.Labels {
			if strings.TrimSpace(labels[key]) != value {
				delete(resourceContext.Labels, key)
			}
		}
	}
	resourceContext.TargetCount++
}

func applyPrometheusResourceContexts(resources map[string]model.Resource, contexts map[string]*prometheusResourceContext) {
	for resourceID, resourceContext := range contexts {
		resource, ok := resources[resourceID]
		if !ok || resourceContext == nil {
			continue
		}
		resource.Labels = cloneLabels(resourceContext.Labels)
		if resource.Metadata == nil {
			resource.Metadata = map[string]string{}
		}
		resource.Metadata["target_count"] = strconv.Itoa(resourceContext.TargetCount)
		resources[resourceID] = resource
	}
}

func exporterName(target prometheusTarget) string {
	if job := target.Labels["job"]; job != "" {
		return job
	}
	if target.ScrapeURL != "" {
		parsed, err := url.Parse(target.ScrapeURL)
		if err == nil {
			return parsed.Host
		}
	}
	return ""
}

func jobInstanceKey(job string, instance string) string {
	if job == "" || instance == "" {
		return ""
	}
	return job + "\x00" + instance
}
