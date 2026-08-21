package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"monicheck/internal/model"
)

const (
	grafanaSystem                         = "grafana"
	defaultGrafanaDashboardSearchPageSize = 5000
	defaultGrafanaDashboardSearchLimit    = 100000
	defaultGrafanaDashboardDetailWorkers  = 8
	maxGrafanaDashboardDetailWorkers      = 64
	defaultGrafanaDatasourceHealthWorkers = 8
	grafanaDefaultDatasourceKey           = "__monicheck_default_datasource__"
	grafanaMetricInstanceMetadataKey      = "monicheck_metric_instance"
)

type GrafanaConnector struct {
	baseURL   string
	apiKey    string
	namespace string
	client    *http.Client

	dashboardSearchPageSize  int
	dashboardSearchLimit     int
	dashboardDetailWorkers   int
	datasourceHealthWorkers  int
	prometheusMetricInstance string
	prometheusDatasourceUID  string
	dashboardDatasourceUID   string
}

// ConfigurePrometheusDatasource binds Grafana query evidence to the canonical
// Prometheus connector identity even when Grafana stores an internal URL.
func (c *GrafanaConnector) ConfigurePrometheusDatasource(metricInstance string, datasourceUID string) error {
	metricInstance = strings.TrimRight(strings.TrimSpace(metricInstance), "/")
	if metricInstance == "" {
		return fmt.Errorf("prometheus metric instance is empty")
	}
	c.prometheusMetricInstance = metricInstance
	c.prometheusDatasourceUID = strings.TrimSpace(datasourceUID)
	return nil
}

// ConfigureDashboardDatasourceFilter limits dashboard ingestion to dashboards
// that are explicitly attributable to the selected datasource. Dashboards with
// dynamic or otherwise unresolved datasource references remain in scope.
func (c *GrafanaConnector) ConfigureDashboardDatasourceFilter(datasourceUID string) error {
	datasourceUID = strings.TrimSpace(datasourceUID)
	if datasourceUID == "" {
		return fmt.Errorf("dashboard datasource filter UID is empty")
	}
	c.dashboardDatasourceUID = datasourceUID
	return nil
}

func NewGrafanaConnector(baseURL string, apiKey string) (*GrafanaConnector, error) {
	return NewGrafanaConnectorWithOptions(baseURL, HTTPOptions{BearerToken: apiKey, Timeout: 15 * time.Second})
}

func NewGrafanaConnectorWithOptions(baseURL string, options HTTPOptions) (*GrafanaConnector, error) {
	return NewGrafanaConnectorWithNamespace(baseURL, "default", options)
}

func NewGrafanaConnectorWithNamespace(baseURL string, namespace string, options HTTPOptions) (*GrafanaConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("grafana url is empty")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid grafana url %q: %w", baseURL, err)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	apiKey := strings.TrimSpace(options.BearerToken)
	if apiKey == "" {
		apiKey = strings.TrimSpace(options.APIKey)
	}
	options.BearerToken = apiKey
	options.APIKey = ""
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "default"
	}
	return &GrafanaConnector{
		baseURL:                 baseURL,
		apiKey:                  apiKey,
		namespace:               namespace,
		client:                  client,
		dashboardSearchPageSize: defaultGrafanaDashboardSearchPageSize,
		dashboardSearchLimit:    defaultGrafanaDashboardSearchLimit,
		dashboardDetailWorkers:  defaultGrafanaDashboardDetailWorkers,
		datasourceHealthWorkers: defaultGrafanaDatasourceHealthWorkers,
	}, nil
}

func (c *GrafanaConnector) ID() string {
	return "grafana"
}

func (c *GrafanaConnector) Name() string {
	return "Grafana Connector"
}

func (c *GrafanaConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()
	diagnostics := make([]model.Diagnostic, 0, 10)

	datasources, err := c.datasources(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	datasourceHealth, datasourceHealthDiagnostic := c.datasourceHealth(ctx, datasources)
	dashboardSearch, err := c.dashboardSearch(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	dashboards := dashboardSearch.Items
	diagnostics = append(diagnostics, grafanaDashboardSearchDiagnostic(dashboardSearch))
	alertRules, available, discoveryErr := c.alertRulesDiscovery(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_alert_rules", "Grafana alert rules", "provisioning alert-rules / App Platform alertrules", available, discoveryErr))
	contactPoints, available, discoveryErr := c.contactPointsDiscovery(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_contact_points", "Grafana contact points", "provisioning contact-points / App Platform receivers", available, discoveryErr))
	notificationPolicy, available, discoveryErr := c.notificationPolicyDiscovery(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_notification_policy", "Grafana notification policy", "provisioning policies / App Platform routingtrees", available, discoveryErr))
	inhibitionRules, available, discoveryErr := c.inhibitionRulesDiscovery(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_inhibition_rules", "Grafana inhibition rules", "App Platform inhibitionrules", available, discoveryErr))
	timeIntervals, timeIntervalsAvailable, err := c.timeIntervals(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_time_intervals", "Grafana notification time intervals", "provisioning mute-timings / App Platform timeintervals", timeIntervalsAvailable, err))
	notificationTemplates, notificationTemplatesAvailable, err := c.notificationTemplates(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_notification_templates", "Grafana notification templates", "provisioning templates / App Platform templategroups", notificationTemplatesAvailable, err))
	health, healthAvailable, err := c.health(ctx)
	diagnostics = append(diagnostics, c.optionalDiagnostic("grafana_health", "Grafana instance health", "/api/health", healthAvailable, err))
	diagnostics = append(diagnostics, datasourceHealthDiagnostic)

	resourceByID := make(map[string]model.Resource)
	relationships := make([]model.Relationship, 0)
	datasourceByUID := make(map[string]model.Resource)
	if healthAvailable {
		resource := grafanaResource(model.ResourceTypeInstance, "Grafana Runtime", c.baseURL, "runtime", now)
		resource.Metadata = map[string]string{
			model.MetadataGrafanaRuntime:        "true",
			model.MetadataGrafanaDatabaseStatus: strings.ToLower(strings.TrimSpace(health.Database)),
		}
		if version := strings.TrimSpace(health.Version); version != "" {
			resource.Metadata[model.MetadataGrafanaVersion] = version
		}
		addResource(resourceByID, resource)
	}

	for index, datasource := range datasources {
		name := datasource.Name
		if name == "" {
			name = datasource.UID
		}
		resource := grafanaResource(model.ResourceTypeDatasource, name, c.baseURL, "datasource:"+datasource.UID, now)
		resource.Metadata = map[string]string{
			model.MetadataDatasourceType:            datasource.Type,
			model.MetadataDatasourceURL:             datasource.URL,
			model.MetadataDatasourceAccess:          datasource.Access,
			model.MetadataDatasourceDefault:         strconv.FormatBool(datasource.IsDefault),
			model.MetadataDatasourceReadOnly:        strconv.FormatBool(datasource.ReadOnly),
			model.MetadataDatasourceBasicAuth:       strconv.FormatBool(datasource.BasicAuth),
			model.MetadataDatasourceHealthEvaluable: strconv.FormatBool(datasourceHealth[index].Err == nil),
		}
		if datasourceHealth[index].Err == nil {
			resource.Metadata[model.MetadataHealth] = datasourceHealth[index].Value.Status
		}
		if datasource.UID != "" {
			resource.Metadata[model.MetadataDatasourceUID] = datasource.UID
			datasourceByUID[datasource.UID] = resource
		}
		if datasource.IsDefault {
			datasourceByUID[grafanaDefaultDatasourceKey] = resource
		}
		if c.prometheusDatasourceUID != "" && datasource.UID == c.prometheusDatasourceUID && isPrometheusDatasource(resource) {
			resource.Metadata[grafanaMetricInstanceMetadataKey] = c.prometheusMetricInstance
			datasourceByUID[datasource.UID] = resource
			if datasource.Name != "" {
				datasourceByUID[datasource.Name] = resource
			}
			if datasource.IsDefault {
				datasourceByUID[grafanaDefaultDatasourceKey] = resource
			}
		}
		if datasource.Name != "" {
			if _, exists := datasourceByUID[datasource.Name]; !exists {
				datasourceByUID[datasource.Name] = resource
			}
		}
		if createdAt, ok := parseGrafanaTimestamp(datasource.Created); ok {
			resource.CreatedAt = createdAt
			resource.Metadata["created_at"] = createdAt.Format(time.RFC3339)
		}
		if updatedAt, ok := parseGrafanaTimestamp(datasource.Updated); ok {
			resource.UpdatedAt = updatedAt
			resource.Metadata[model.MetadataUpdatedAt] = updatedAt.Format(time.RFC3339)
		}
		addResource(resourceByID, resource)
	}
	if c.prometheusMetricInstance != "" {
		diagnostics = append(diagnostics, c.prometheusDatasourceLinkDiagnostic(datasources))
	}

	dashboardDetails := c.dashboardDetails(ctx, dashboards, dashboardSearch.Details)
	dashboardDetailFailureCount := 0
	dashboardFilterIncluded := 0
	dashboardFilterExcluded := 0
	dashboardFilterUnknown := 0
	for index, item := range dashboards {
		detail := dashboardDetails[index].Detail
		err := dashboardDetails[index].Err
		if err != nil {
			dashboardDetailFailureCount++
			dashboardResource := grafanaResource(model.ResourceTypeDashboard, item.Title, c.baseURL, "dashboard:"+item.UID, now)
			dashboardResource.Status = model.ResourceStatusBroken
			dashboardResource.Metadata = grafanaDashboardSearchMetadata(item)
			dashboardResource.Metadata[model.MetadataDashboardDetailAvailable] = "false"
			dashboardResource.Metadata[model.MetadataHealth] = "detail_unavailable"
			addResource(resourceByID, dashboardResource)
			if folderResource, ok := grafanaFolderResource(dashboardResource.Metadata, c.baseURL, now); ok {
				addResource(resourceByID, folderResource)
				appendGrafanaRelationship(&relationships, dashboardResource.ID, folderResource.ID, model.RelationshipBelongsTo, now)
			}
			continue
		}
		if c.dashboardDatasourceUID != "" {
			decision := grafanaDashboardDatasourceFilterDecision(detail.Dashboard, c.dashboardDatasourceUID)
			switch decision {
			case grafanaDatasourceFilterExcluded:
				dashboardFilterExcluded++
				continue
			case grafanaDatasourceFilterIncluded:
				dashboardFilterIncluded++
			default:
				dashboardFilterUnknown++
			}
		}
		dashboardResource := grafanaResource(model.ResourceTypeDashboard, detail.Dashboard.Title, c.baseURL, "dashboard:"+item.UID, now)
		dashboardResource.Metadata = grafanaDashboardMetadata(item, detail)
		dashboardResource.Metadata[model.MetadataDashboardDetailAvailable] = "true"
		if createdAt, ok := parseGrafanaTimestamp(detail.Meta.Created); ok {
			dashboardResource.CreatedAt = createdAt
		}
		if updatedAt, ok := parseGrafanaTimestamp(detail.Meta.Updated); ok {
			dashboardResource.UpdatedAt = updatedAt
		}
		variableExpressions := dashboardVariableExpressions(detail.Dashboard, datasourceByUID)
		if len(variableExpressions) > 0 {
			setQueryMetadata(dashboardResource.Metadata, model.MetadataPromQL, strings.Join(variableExpressions, "\n"))
		}
		addResource(resourceByID, dashboardResource)
		if folderResource, ok := grafanaFolderResource(dashboardResource.Metadata, c.baseURL, now); ok {
			addResource(resourceByID, folderResource)
			appendGrafanaRelationship(&relationships, dashboardResource.ID, folderResource.ID, model.RelationshipBelongsTo, now)
		}
		for _, variable := range detail.Dashboard.Templating.List {
			expression := grafanaVariableExpression(variable)
			if expression == "" {
				continue
			}
			metricInstance := "grafana:" + c.baseURL
			isPromQLVariable := shouldTreatGrafanaRefAsPromQL(variable.Datasource, datasourceByUID)
			if datasource, ok := datasourceForRef(variable.Datasource, datasourceByUID); ok {
				relationships = append(relationships, grafanaRelationship(dashboardResource.ID, datasource.ID, model.RelationshipUses, now))
				isPromQLVariable = isPrometheusDatasource(datasource)
				if datasourceURL := grafanaDatasourceMetricInstance(datasource); datasourceURL != "" {
					metricInstance = datasourceURL
				}
			}
			if !isPromQLVariable {
				continue
			}
			for _, metricName := range extractGrafanaVariableMetricNames(expression) {
				metricResource := prometheusResource(model.ResourceTypeMetric, metricName, metricInstance, "metric:"+metricName, now)
				addResource(resourceByID, metricResource)
				relationships = append(relationships, grafanaRelationship(dashboardResource.ID, metricResource.ID, model.RelationshipUses, now))
			}
		}

		for _, panel := range flattenPanels(detail.Dashboard.Panels) {
			panelID := fmt.Sprintf("%v", panel.ID)
			panelResource := grafanaResource(model.ResourceTypePanel, panel.Title, c.baseURL, "panel:"+item.UID+":"+panelID, now)
			panelResource.Metadata = map[string]string{
				model.MetadataDashboardUID: item.UID,
				model.MetadataPanelID:      panelID,
			}
			if panelTitle := strings.TrimSpace(panel.Title); panelTitle != "" {
				panelResource.Metadata[model.MetadataPanelTitle] = panelTitle
			}
			addGrafanaPanelGridMetadata(panelResource.Metadata, panel.GridPos)
			addGrafanaPanelDisplayMetadata(panelResource.Metadata, panel)
			addGrafanaPanelDatasourceMetadata(panelResource.Metadata, panel, datasourceByUID)
			if panel.Type != "" {
				panelResource.Metadata[model.MetadataVisualizationType] = panel.Type
			}
			expressions := panelPromQLExpressions(panel, datasourceByUID)
			if len(expressions) > 0 {
				setQueryMetadata(panelResource.Metadata, model.MetadataPromQL, strings.Join(expressions, "\n"))
			}
			if queries, language := panelNonPrometheusQueries(panel, datasourceByUID); len(queries) > 0 {
				setQueryMetadata(panelResource.Metadata, model.MetadataQuery, strings.Join(queries, "\n"))
				panelResource.Metadata[model.MetadataQueryLanguage] = language
			}
			addResource(resourceByID, panelResource)
			addGrafanaPanelQueryDependencies(resourceByID, &relationships, panelResource, panel, datasourceByUID, c.baseURL, now)
			relationships = append(relationships, grafanaRelationship(panelResource.ID, dashboardResource.ID, model.RelationshipBelongsTo, now))

			metricInstance := "grafana:" + c.baseURL
			panelDatasource, hasPanelDatasource := datasourceForRef(panel.Datasource, datasourceByUID)
			if datasource, ok := panelDatasource, hasPanelDatasource; ok {
				if panel.Datasource.UID != "" {
					panelResource.Metadata[model.MetadataDatasourceUID] = panel.Datasource.UID
					resourceByID[panelResource.ID] = panelResource
				}
				relationships = append(relationships, grafanaRelationship(panelResource.ID, datasource.ID, model.RelationshipUses, now))
				if datasourceURL := grafanaDatasourceMetricInstance(datasource); datasourceURL != "" {
					metricInstance = datasourceURL
				}
			}

			for _, target := range panel.Targets {
				if target.Expression == "" {
					continue
				}
				targetMetricInstance := metricInstance
				targetDatasource, hasTargetDatasource := effectiveGrafanaTargetDatasource(panel, target, datasourceByUID)
				if hasTargetDatasource {
					if !isPrometheusDatasource(targetDatasource) {
						continue
					}
					datasource := targetDatasource
					appendGrafanaRelationship(&relationships, panelResource.ID, datasource.ID, model.RelationshipUses, now)
					if datasourceURL := grafanaDatasourceMetricInstance(datasource); datasourceURL != "" {
						targetMetricInstance = datasourceURL
					}
				} else if target.Datasource.UID != "" {
					if !shouldTreatGrafanaRefAsPromQL(target.Datasource, datasourceByUID) {
						continue
					}
				} else if hasPanelDatasource && !isPrometheusDatasource(panelDatasource) {
					continue
				} else if !hasPanelDatasource && !shouldTreatGrafanaRefAsPromQL(panel.Datasource, datasourceByUID) {
					continue
				}
				for _, metricName := range extractMetricNames(target.Expression) {
					metricResource := prometheusResource(model.ResourceTypeMetric, metricName, targetMetricInstance, "metric:"+metricName, now)
					addResource(resourceByID, metricResource)
					relationships = append(relationships, grafanaRelationship(panelResource.ID, metricResource.ID, model.RelationshipUses, now))
				}
			}
		}
	}
	diagnostics = append(diagnostics, detailDiscoveryDiagnostic(
		"grafana_dashboard_details",
		"Grafana dashboard detail",
		grafanaSystem,
		"/api/dashboards/uid/{uid}",
		len(dashboards),
		dashboardDetailFailureCount,
	))
	if c.dashboardDatasourceUID != "" {
		diagnostics = append(diagnostics, grafanaDashboardDatasourceFilterDiagnostic(
			c.dashboardDatasourceUID,
			dashboardFilterIncluded,
			dashboardFilterExcluded,
			dashboardFilterUnknown,
		))
	}
	addGrafanaAlertRules(resourceByID, &relationships, alertRules, datasourceByUID, c.baseURL, now)
	addGrafanaReceivers(resourceByID, &relationships, contactPoints, notificationPolicy, alertRules, c.baseURL, now)
	addGrafanaInhibitionRules(resourceByID, inhibitionRules, c.baseURL, now)
	addGrafanaTimeIntervals(resourceByID, &relationships, timeIntervals, timeIntervalsAvailable, notificationPolicy, c.baseURL, now)
	addGrafanaNotificationTemplates(resourceByID, &relationships, notificationTemplates, notificationTemplatesAvailable, contactPoints, c.baseURL, now)

	resources := make([]model.Resource, 0, len(resourceByID))
	references := make([]model.Resource, 0)
	sanitizeGrafanaResourceURLs(resourceByID)
	for _, resource := range resourceByID {
		if resource.Type == model.ResourceTypeMetric &&
			resource.Source.System == prometheusSystem &&
			c.prometheusMetricInstance != "" &&
			strings.TrimRight(resource.Source.Instance, "/") == c.prometheusMetricInstance {
			references = append(references, resource)
			continue
		}
		resources = append(resources, resource)
	}
	return Snapshot{
		Resources:     resources,
		References:    references,
		Relationships: relationships,
		Diagnostics:   diagnostics,
		Partial:       diagnosticsHaveFailures(diagnostics),
	}, nil
}

func sanitizeGrafanaResourceURLs(resources map[string]model.Resource) {
	endpointFingerprints := make(map[string]string)
	for id, resource := range resources {
		if resource.Type == model.ResourceTypeDashboard {
			delete(resource.Metadata, model.MetadataDashboardURL)
			resources[id] = resource
			continue
		}
		if resource.Type != model.ResourceTypeDatasource || resource.Source.System != grafanaSystem {
			continue
		}
		rawURL := strings.TrimSpace(resource.Metadata[model.MetadataDatasourceURL])
		configured := rawURL != ""
		resource.Metadata[model.MetadataDatasourceURLConfigured] = strconv.FormatBool(configured)
		resource.Metadata[model.MetadataDatasourceURLValid] = "false"
		if configured {
			endpointFingerprint := model.StableID("datasource-endpoint", rawURL)
			resource.Metadata[model.MetadataDatasourceEndpointFingerprint] = endpointFingerprint
			endpointFingerprints[strings.TrimRight(rawURL, "/")] = endpointFingerprint
			if parsed, err := url.Parse(rawURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
				host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parsed.Hostname())), ".")
				resource.Metadata[model.MetadataDatasourceURLValid] = "true"
				resource.Metadata[model.MetadataDatasourceURLScheme] = strings.ToLower(parsed.Scheme)
				resource.Metadata[model.MetadataDatasourceURLHostFingerprint] = model.StableID("datasource-host", host)
				if isPrivateGrafanaDatasourceHost(host) {
					resource.Metadata[model.MetadataDatasourceURLHostScope] = "internal"
				} else {
					resource.Metadata[model.MetadataDatasourceURLHostScope] = "public"
				}
			}
		}
		delete(resource.Metadata, model.MetadataDatasourceURL)
		delete(resource.Metadata, grafanaMetricInstanceMetadataKey)
		delete(resource.Metadata, "url")
		resources[id] = resource
	}

	for id, resource := range resources {
		if resource.Type != model.ResourceTypeMetric {
			continue
		}
		if fingerprint := endpointFingerprints[strings.TrimRight(resource.Source.Instance, "/")]; fingerprint != "" {
			resource.Source.Instance = fingerprint
			resources[id] = resource
		}
	}
}

func isPrivateGrafanaDatasourceHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsPrivate() ||
			addr.IsLoopback() ||
			addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() ||
			addr.IsMulticast() ||
			addr.IsUnspecified()
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".local", ".internal", ".svc", ".svc.cluster.local", ".cluster.local"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func panelPromQLExpressions(panel grafanaPanel, datasourceByUID map[string]model.Resource) []string {
	expressions := make([]string, 0, len(panel.Targets))
	for _, target := range panel.Targets {
		expression := strings.TrimSpace(target.Expression)
		if expression == "" {
			continue
		}
		if datasource, ok := effectiveGrafanaTargetDatasource(panel, target, datasourceByUID); ok {
			if !isPrometheusDatasource(datasource) {
				continue
			}
		} else if target.Datasource.UID != "" {
			if !shouldTreatGrafanaRefAsPromQL(target.Datasource, datasourceByUID) {
				continue
			}
		} else if !shouldTreatGrafanaRefAsPromQL(panel.Datasource, datasourceByUID) {
			continue
		}
		expressions = append(expressions, expression)
	}
	return expressions
}

func panelNonPrometheusQueries(panel grafanaPanel, datasourceByUID map[string]model.Resource) ([]string, string) {
	queries := make([]string, 0, len(panel.Targets))
	languages := map[string]bool{}
	for _, target := range panel.Targets {
		expression := strings.TrimSpace(target.Expression)
		if expression == "" {
			continue
		}
		language := grafanaTargetQueryLanguage(panel, target, datasourceByUID)
		if language == "" || language == "promql" {
			continue
		}
		queries = append(queries, expression)
		languages[language] = true
	}
	return queries, strings.Join(sortedStringSet(languages), ",")
}

func addGrafanaPanelGridMetadata(metadata map[string]string, grid grafanaGridPos) {
	if grid.X != 0 {
		metadata[model.MetadataPanelGridX] = strconv.Itoa(grid.X)
	}
	if grid.Y != 0 {
		metadata[model.MetadataPanelGridY] = strconv.Itoa(grid.Y)
	}
	if grid.W != 0 {
		metadata[model.MetadataPanelGridW] = strconv.Itoa(grid.W)
	}
	if grid.H != 0 {
		metadata[model.MetadataPanelGridH] = strconv.Itoa(grid.H)
	}
}

func addGrafanaPanelDisplayMetadata(metadata map[string]string, panel grafanaPanel) {
	if unit := strings.TrimSpace(panel.FieldConfig.Defaults.Unit); unit != "" {
		metadata[model.MetadataPanelUnit] = unit
	}
	if thresholdCount := len(panel.FieldConfig.Defaults.Thresholds.Steps); thresholdCount > 0 {
		metadata[model.MetadataPanelThresholdCount] = strconv.Itoa(thresholdCount)
	}
	if legendMode := strings.TrimSpace(panel.Options.Legend.DisplayMode); legendMode != "" {
		metadata[model.MetadataPanelLegendMode] = legendMode
	}
}

func dashboardVariableExpressions(dashboard grafanaDashboard, datasourceByUID map[string]model.Resource) []string {
	expressions := make([]string, 0, len(dashboard.Templating.List))
	for _, variable := range dashboard.Templating.List {
		expression := grafanaVariableExpression(variable)
		if expression == "" {
			continue
		}
		if !shouldTreatGrafanaRefAsPromQL(variable.Datasource, datasourceByUID) {
			continue
		}
		expressions = append(expressions, expression)
	}
	return expressions
}

func grafanaDashboardMetadata(item grafanaDashboardSearchItem, detail grafanaDashboardResponse) map[string]string {
	metadata := grafanaDashboardSearchMetadata(item)
	if detail.Dashboard.Version > 0 {
		metadata[model.MetadataDashboardVersion] = strconv.Itoa(detail.Dashboard.Version)
	}
	if detail.Dashboard.SchemaVersion > 0 {
		metadata[model.MetadataDashboardSchemaVersion] = strconv.Itoa(detail.Dashboard.SchemaVersion)
	}
	if tags := cleanGrafanaStrings(detail.Dashboard.Tags); len(tags) > 0 {
		metadata[model.MetadataDashboardTags] = strings.Join(tags, ",")
	}
	if detail.Dashboard.Timezone != "" {
		metadata[model.MetadataDashboardTimezone] = detail.Dashboard.Timezone
	}
	if detail.Dashboard.Refresh != "" {
		metadata[model.MetadataDashboardRefresh] = detail.Dashboard.Refresh
	}
	if timeFrom := strings.TrimSpace(detail.Dashboard.Time.From); timeFrom != "" {
		metadata[model.MetadataDashboardTimeFrom] = timeFrom
	}
	if timeTo := strings.TrimSpace(detail.Dashboard.Time.To); timeTo != "" {
		metadata[model.MetadataDashboardTimeTo] = timeTo
	}
	if timeRange, ok := grafanaDashboardTimeRange(detail.Dashboard.Time); ok {
		metadata[model.MetadataDashboardTimeRange] = timeRange.String()
	}
	if annotationCount := len(detail.Dashboard.Annotations.List); annotationCount > 0 {
		metadata[model.MetadataDashboardAnnotationCnt] = strconv.Itoa(annotationCount)
	}
	metadata[model.MetadataDashboardEditable] = strconv.FormatBool(detail.Dashboard.Editable)
	if detail.Meta.Slug != "" {
		metadata[model.MetadataDashboardSlug] = detail.Meta.Slug
	}
	if detail.Meta.URL != "" {
		metadata[model.MetadataDashboardURL] = detail.Meta.URL
	}
	if createdAt, ok := parseGrafanaTimestamp(detail.Meta.Created); ok {
		metadata["created_at"] = createdAt.Format(time.RFC3339)
	}
	if updatedAt, ok := parseGrafanaTimestamp(detail.Meta.Updated); ok {
		metadata[model.MetadataUpdatedAt] = updatedAt.Format(time.RFC3339)
	}
	folderUID := strings.TrimSpace(detail.Meta.FolderUID)
	if folderUID != "" {
		metadata[model.MetadataFolderUID] = folderUID
	}
	folderTitle := strings.TrimSpace(detail.Meta.FolderTitle)
	if folderTitle != "" {
		metadata[model.MetadataFolderTitle] = folderTitle
	}
	return metadata
}

func grafanaDashboardSearchMetadata(item grafanaDashboardSearchItem) map[string]string {
	metadata := map[string]string{model.MetadataDashboardUID: item.UID}
	if folderUID := strings.TrimSpace(item.FolderUID); folderUID != "" {
		metadata[model.MetadataFolderUID] = folderUID
	}
	if folderTitle := strings.TrimSpace(item.FolderTitle); folderTitle != "" {
		metadata[model.MetadataFolderTitle] = folderTitle
	}
	return metadata
}

func grafanaFolderResource(metadata map[string]string, instance string, now time.Time) (model.Resource, bool) {
	folderUID := strings.TrimSpace(metadata[model.MetadataFolderUID])
	folderTitle := strings.TrimSpace(metadata[model.MetadataFolderTitle])
	if folderUID == "" && folderTitle == "" {
		return model.Resource{}, false
	}
	externalID := folderUID
	if externalID == "" {
		externalID = folderTitle
	}
	name := folderTitle
	if name == "" {
		name = externalID
	}
	resource := grafanaResource(model.ResourceTypeFolder, name, instance, "folder:"+externalID, now)
	resource.Metadata = map[string]string{}
	if folderUID != "" {
		resource.Metadata[model.MetadataFolderUID] = folderUID
	}
	if folderTitle != "" {
		resource.Metadata[model.MetadataFolderTitle] = folderTitle
	}
	return resource, true
}

func parseGrafanaTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func grafanaDashboardTimeRange(dashboardTime grafanaDashboardTime) (time.Duration, bool) {
	from := strings.TrimSpace(strings.ToLower(dashboardTime.From))
	to := strings.TrimSpace(strings.ToLower(dashboardTime.To))
	if to != "now" || !strings.HasPrefix(from, "now-") {
		return 0, false
	}
	return parseGrafanaDuration(strings.TrimPrefix(from, "now-"))
}

func parseGrafanaDuration(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	var total time.Duration
	runes := []rune(raw)
	for i := 0; i < len(runes); {
		if !unicode.IsDigit(runes[i]) {
			return 0, false
		}
		start := i
		for i < len(runes) && unicode.IsDigit(runes[i]) {
			i++
		}
		amount, err := strconv.Atoi(string(runes[start:i]))
		if err != nil || amount <= 0 || i >= len(runes) {
			return 0, false
		}
		unitStart := i
		for i < len(runes) && unicode.IsLetter(runes[i]) {
			i++
		}
		multiplier, ok := grafanaDurationUnit(string(runes[unitStart:i]))
		if !ok {
			return 0, false
		}
		total += time.Duration(amount) * multiplier
	}
	return total, total > 0
}

func grafanaDurationUnit(unit string) (time.Duration, bool) {
	switch unit {
	case "s":
		return time.Second, true
	case "m":
		return time.Minute, true
	case "h":
		return time.Hour, true
	case "d":
		return 24 * time.Hour, true
	case "w":
		return 7 * 24 * time.Hour, true
	case "y":
		return 365 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func cleanGrafanaStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func (c *GrafanaConnector) datasources(ctx context.Context) ([]grafanaDatasource, error) {
	var response []grafanaDatasource
	if err := c.get(ctx, "/api/datasources", &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *GrafanaConnector) dashboardSearch(ctx context.Context) (grafanaDashboardSearchResult, error) {
	result, available, err := c.legacyDashboardSearch(ctx)
	if err != nil || available {
		return result, err
	}
	result, available, err = c.appDashboardSearch(ctx)
	if err != nil {
		return grafanaDashboardSearchResult{}, err
	}
	if !available {
		return grafanaDashboardSearchResult{}, fmt.Errorf("grafana dashboard discovery endpoints are unavailable")
	}
	result.Fallback = true
	return result, nil
}

func (c *GrafanaConnector) legacyDashboardSearch(ctx context.Context) (grafanaDashboardSearchResult, bool, error) {
	pageSize := c.dashboardSearchPageSize
	if pageSize <= 0 || pageSize > defaultGrafanaDashboardSearchPageSize {
		pageSize = defaultGrafanaDashboardSearchPageSize
	}
	limit := c.dashboardSearchLimit
	if limit <= 0 {
		limit = defaultGrafanaDashboardSearchLimit
	}

	result := grafanaDashboardSearchResult{
		Items:    make([]grafanaDashboardSearchItem, 0),
		Details:  make(map[string]grafanaDashboardResponse),
		PageSize: pageSize,
		Limit:    limit,
		API:      "legacy",
		Endpoint: "/api/search?type=dash-db&limit={limit}&page={page}",
	}
	seenUIDs := map[string]bool{}
	for page := 1; ; page++ {
		path := fmt.Sprintf("/api/search?type=dash-db&limit=%d&page=%d", pageSize, page)
		var response []grafanaDashboardSearchItem
		if page == 1 {
			available, err := c.getOptional(ctx, path, &response)
			if err != nil || !available {
				return grafanaDashboardSearchResult{}, available, err
			}
		} else if err := c.get(ctx, path, &response); err != nil {
			return grafanaDashboardSearchResult{}, true, err
		}
		result.PageCount++
		result.RawItemCount += len(response)
		if len(response) == 0 {
			break
		}

		added := 0
		for _, item := range response {
			item.UID = strings.TrimSpace(item.UID)
			if item.UID == "" {
				result.InvalidItemCount++
				continue
			}
			if seenUIDs[item.UID] {
				result.DuplicateItemCount++
				continue
			}
			seenUIDs[item.UID] = true
			if len(result.Items) >= limit {
				result.Truncated = true
				continue
			}
			result.Items = append(result.Items, item)
			added++
		}
		if result.Truncated || len(response) < pageSize {
			break
		}
		if added == 0 {
			result.PaginationStalled = true
			break
		}
	}
	return result, true, nil
}

func (c *GrafanaConnector) appDashboardSearch(ctx context.Context) (grafanaDashboardSearchResult, bool, error) {
	pageSize := c.dashboardSearchPageSize
	if pageSize <= 0 || pageSize > defaultGrafanaDashboardSearchPageSize {
		pageSize = defaultGrafanaDashboardSearchPageSize
	}
	limit := c.dashboardSearchLimit
	if limit <= 0 {
		limit = defaultGrafanaDashboardSearchLimit
	}

	basePath := "/apis/dashboard.grafana.app/v1/namespaces/" + url.PathEscape(c.namespace) + "/dashboards"
	result := grafanaDashboardSearchResult{
		Items:    make([]grafanaDashboardSearchItem, 0),
		Details:  make(map[string]grafanaDashboardResponse),
		PageSize: pageSize,
		Limit:    limit,
		API:      "app",
		Endpoint: basePath + "?limit={limit}&continue={continue}",
	}
	seenUIDs := map[string]bool{}
	seenTokens := map[string]bool{}
	continueToken := ""
	for page := 1; ; page++ {
		path := fmt.Sprintf("%s?limit=%d", basePath, pageSize)
		if continueToken != "" {
			path += "&continue=" + url.QueryEscape(continueToken)
		}
		var response grafanaAppDashboardList
		if page == 1 {
			available, err := c.getOptional(ctx, path, &response)
			if err != nil || !available {
				return grafanaDashboardSearchResult{}, available, err
			}
		} else if err := c.get(ctx, path, &response); err != nil {
			return grafanaDashboardSearchResult{}, true, err
		}
		result.PageCount++
		result.RawItemCount += len(response.Items)

		added := 0
		for _, appItem := range response.Items {
			uid := strings.TrimSpace(appItem.Metadata.Name)
			if uid == "" {
				uid = strings.TrimSpace(appItem.Spec.UID)
			}
			if uid == "" {
				result.InvalidItemCount++
				continue
			}
			if seenUIDs[uid] {
				result.DuplicateItemCount++
				continue
			}
			seenUIDs[uid] = true
			if len(result.Items) >= limit {
				result.Truncated = true
				continue
			}
			title := strings.TrimSpace(appItem.Spec.Title)
			if title == "" {
				title = uid
			}
			folderUID := strings.TrimSpace(appItem.Metadata.Annotations["grafana.app/folder"])
			item := grafanaDashboardSearchItem{
				UID:       uid,
				Title:     title,
				FolderUID: folderUID,
			}
			result.Items = append(result.Items, item)
			result.Details[uid] = appItem.dashboardResponse()
			added++
		}
		if result.Truncated {
			break
		}

		nextToken := strings.TrimSpace(response.Metadata.Continue)
		if nextToken == "" {
			break
		}
		if added == 0 || nextToken == continueToken || seenTokens[nextToken] {
			result.PaginationStalled = true
			break
		}
		seenTokens[nextToken] = true
		continueToken = nextToken
	}
	return result, true, nil
}

func grafanaDashboardSearchDiagnostic(result grafanaDashboardSearchResult) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := fmt.Sprintf("Grafana dashboard search discovered %d unique dashboards across %d pages", len(result.Items), result.PageCount)
	if result.Truncated || result.PaginationStalled || result.InvalidItemCount > 0 {
		status = model.ExecutionStatusWarning
		message = "Grafana dashboard search completed with incomplete or invalid pagination results"
	}
	return model.Diagnostic{
		ID:            "grafana_dashboard_search",
		Name:          "Grafana dashboard search",
		Status:        status,
		Message:       message,
		ResourceCount: len(result.Items),
		Metadata: map[string]string{
			"api":                  result.API,
			"endpoint":             result.Endpoint,
			"fallback":             strconv.FormatBool(result.Fallback),
			"page_size":            strconv.Itoa(result.PageSize),
			"page_count":           strconv.Itoa(result.PageCount),
			"limit":                strconv.Itoa(result.Limit),
			"raw_item_count":       strconv.Itoa(result.RawItemCount),
			"unique_item_count":    strconv.Itoa(len(result.Items)),
			"duplicate_item_count": strconv.Itoa(result.DuplicateItemCount),
			"invalid_item_count":   strconv.Itoa(result.InvalidItemCount),
			"truncated":            strconv.FormatBool(result.Truncated),
			"pagination_stalled":   strconv.FormatBool(result.PaginationStalled),
		},
	}
}

func (c *GrafanaConnector) alertRules(ctx context.Context) ([]grafanaAlertRule, error) {
	rules, _, err := c.alertRulesDiscovery(ctx)
	return rules, err
}

func (c *GrafanaConnector) alertRulesDiscovery(ctx context.Context) ([]grafanaAlertRule, bool, error) {
	rules, found, err := c.legacyAlertRules(ctx)
	if err != nil || found {
		return rules, found, err
	}
	return c.appAlertRulesDiscovery(ctx)
}

func (c *GrafanaConnector) legacyAlertRules(ctx context.Context) ([]grafanaAlertRule, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/provisioning/alert-rules", nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return nil, false, nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, false, fmt.Errorf("grafana /api/v1/provisioning/alert-rules returned status %d", resp.StatusCode)
	}

	var response []grafanaAlertRule
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, false, err
	}
	return response, true, nil
}

func (c *GrafanaConnector) contactPoints(ctx context.Context) ([]grafanaContactPoint, error) {
	contactPoints, _, err := c.contactPointsDiscovery(ctx)
	return contactPoints, err
}

func (c *GrafanaConnector) contactPointsDiscovery(ctx context.Context) ([]grafanaContactPoint, bool, error) {
	var response []grafanaContactPoint
	found, err := c.getOptional(ctx, "/api/v1/provisioning/contact-points", &response)
	if err != nil || found {
		for index := range response {
			response[index].TemplateReferences = grafanaTemplateReferences(response[index].Settings)
			response[index].InsecureEndpointCount = insecureEndpointCount(response[index].Settings)
			response[index].Settings = nil
		}
		return response, found, err
	}
	return c.appContactPointsDiscovery(ctx)
}

func (c *GrafanaConnector) notificationPolicy(ctx context.Context) (*grafanaNotificationRoute, error) {
	policy, _, err := c.notificationPolicyDiscovery(ctx)
	return policy, err
}

func (c *GrafanaConnector) notificationPolicyDiscovery(ctx context.Context) (*grafanaNotificationRoute, bool, error) {
	var response grafanaNotificationRoute
	found, err := c.getOptional(ctx, "/api/v1/provisioning/policies", &response)
	if err != nil || found {
		if !found {
			return nil, false, err
		}
		return &response, true, err
	}
	return c.appNotificationPolicyDiscovery(ctx)
}

func (c *GrafanaConnector) getOptional(ctx context.Context, path string, target any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return false, nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("grafana %s returned status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return false, err
	}
	return true, nil
}

func (c *GrafanaConnector) health(ctx context.Context) (grafanaHealth, bool, error) {
	var response grafanaHealth
	found, err := c.getOptional(ctx, "/api/health", &response)
	return response, found, err
}

func (c *GrafanaConnector) datasourceHealth(
	ctx context.Context,
	datasources []grafanaDatasource,
) ([]detailFetchResult[grafanaDatasourceHealth], model.Diagnostic) {
	results, workerCount := boundedDetailFetch(
		ctx,
		len(datasources),
		c.datasourceHealthWorkers,
		func(ctx context.Context, index int) (grafanaDatasourceHealth, error) {
			uid := strings.TrimSpace(datasources[index].UID)
			if uid == "" {
				return grafanaDatasourceHealth{}, fmt.Errorf("datasource UID is empty")
			}
			var response grafanaDatasourceHealth
			found, err := c.getOptional(ctx, "/api/datasources/uid/"+url.PathEscape(uid)+"/health", &response)
			if err != nil {
				return grafanaDatasourceHealth{}, err
			}
			if !found {
				return grafanaDatasourceHealth{}, fmt.Errorf("datasource health endpoint is unavailable")
			}
			response.Status = strings.ToLower(strings.TrimSpace(response.Status))
			if response.Status == "" {
				return grafanaDatasourceHealth{}, fmt.Errorf("datasource health status is empty")
			}
			return response, nil
		},
	)
	failed := 0
	for _, result := range results {
		if result.Err != nil {
			failed++
		}
	}
	diagnostic := detailDiscoveryDiagnostic(
		"grafana_datasource_health",
		"Grafana datasource health",
		grafanaSystem,
		"/api/datasources/uid/{uid}/health",
		len(datasources),
		failed,
	)
	addDetailDiscoveryWorkerCount(&diagnostic, workerCount)
	return results, diagnostic
}

func (c *GrafanaConnector) optionalDiagnostic(id string, name string, endpoint string, available bool, err error) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := name + " discovery completed"
	if err != nil || !available {
		status = model.ExecutionStatusWarning
		message = name + " endpoints are unavailable; core dashboard discovery continued"
	}
	diagnostic := model.Diagnostic{
		ID:      id,
		Name:    name,
		Status:  status,
		Message: message,
		Metadata: map[string]string{
			"endpoint":  endpoint,
			"optional":  "true",
			"system":    grafanaSystem,
			"available": strconv.FormatBool(available),
		},
	}
	if err != nil {
		diagnostic.Metadata["error"] = err.Error()
	}
	return diagnostic
}

func (c *GrafanaConnector) prometheusDatasourceLinkDiagnostic(datasources []grafanaDatasource) model.Diagnostic {
	prometheusCount := 0
	matchedCount := 0
	for _, datasource := range datasources {
		if !strings.EqualFold(strings.TrimSpace(datasource.Type), "prometheus") {
			continue
		}
		prometheusCount++
		if c.prometheusDatasourceUID != "" {
			if strings.TrimSpace(datasource.UID) == c.prometheusDatasourceUID {
				matchedCount++
			}
			continue
		}
		if strings.TrimRight(strings.TrimSpace(datasource.URL), "/") == c.prometheusMetricInstance {
			matchedCount++
		}
	}

	status := model.ExecutionStatusSucceeded
	message := "Grafana Prometheus datasource identity is linked to the configured Prometheus source"
	if matchedCount == 0 {
		status = model.ExecutionStatusWarning
		message = "Grafana Prometheus datasource identity is not linked; dashboard metric usage may be incomplete. Configure --prometheus-datasource-uid."
	}
	return model.Diagnostic{
		ID:      "grafana_prometheus_datasource_link",
		Name:    "Grafana Prometheus datasource link",
		Status:  status,
		Message: message,
		Metadata: map[string]string{
			"explicit_binding":            strconv.FormatBool(c.prometheusDatasourceUID != ""),
			"prometheus_datasource_count": strconv.Itoa(prometheusCount),
			"matched_count":               strconv.Itoa(matchedCount),
		},
	}
}

func (c *GrafanaConnector) appAlertRules(ctx context.Context) ([]grafanaAlertRule, error) {
	rules, _, err := c.appAlertRulesDiscovery(ctx)
	return rules, err
}

func (c *GrafanaConnector) appAlertRulesDiscovery(ctx context.Context) ([]grafanaAlertRule, bool, error) {
	path := "/apis/rules.alerting.grafana.app/v0alpha1/namespaces/" + url.PathEscape(c.namespace) + "/alertrules"
	var response grafanaAppAlertRuleList
	found, err := c.getOptional(ctx, path, &response)
	if err != nil || !found {
		return nil, found, err
	}
	rules := make([]grafanaAlertRule, 0, len(response.Items))
	for _, item := range response.Items {
		rules = append(rules, item.legacyRule())
	}
	return rules, true, nil
}

func (c *GrafanaConnector) appContactPoints(ctx context.Context) ([]grafanaContactPoint, error) {
	contactPoints, _, err := c.appContactPointsDiscovery(ctx)
	return contactPoints, err
}

func (c *GrafanaConnector) appContactPointsDiscovery(ctx context.Context) ([]grafanaContactPoint, bool, error) {
	for _, version := range []string{"v1beta1", "v0alpha1"} {
		path := "/apis/notifications.alerting.grafana.app/" + version + "/namespaces/" + url.PathEscape(c.namespace) + "/receivers"
		var response grafanaAppReceiverList
		found, err := c.getOptional(ctx, path, &response)
		if err != nil {
			return nil, false, err
		}
		if !found {
			continue
		}
		contactPoints := make([]grafanaContactPoint, 0)
		for _, receiver := range response.Items {
			contactPoints = append(contactPoints, receiver.contactPoints()...)
		}
		return contactPoints, true, nil
	}
	return nil, false, nil
}

func (c *GrafanaConnector) appNotificationPolicy(ctx context.Context) (*grafanaNotificationRoute, error) {
	policy, _, err := c.appNotificationPolicyDiscovery(ctx)
	return policy, err
}

func (c *GrafanaConnector) appNotificationPolicyDiscovery(ctx context.Context) (*grafanaNotificationRoute, bool, error) {
	for _, version := range []string{"v1beta1", "v0alpha1"} {
		path := "/apis/notifications.alerting.grafana.app/" + version + "/namespaces/" + url.PathEscape(c.namespace) + "/routingtrees"
		var response grafanaAppRoutingTreeList
		found, err := c.getOptional(ctx, path, &response)
		if err != nil {
			return nil, false, err
		}
		if !found {
			continue
		}
		if len(response.Items) == 0 {
			return nil, true, nil
		}
		selected := response.Items[0]
		for _, tree := range response.Items {
			if strings.EqualFold(strings.TrimSpace(tree.Metadata.Name), "default") {
				selected = tree
				break
			}
		}
		root := selected.notificationRoute()
		return &root, true, nil
	}
	return nil, false, nil
}

func (c *GrafanaConnector) inhibitionRules(ctx context.Context) ([]grafanaAppInhibitionRule, error) {
	rules, _, err := c.inhibitionRulesDiscovery(ctx)
	return rules, err
}

func (c *GrafanaConnector) inhibitionRulesDiscovery(ctx context.Context) ([]grafanaAppInhibitionRule, bool, error) {
	for _, version := range []string{"v1beta1", "v0alpha1"} {
		path := "/apis/notifications.alerting.grafana.app/" + version + "/namespaces/" + url.PathEscape(c.namespace) + "/inhibitionrules"
		var response grafanaAppInhibitionRuleList
		found, err := c.getOptional(ctx, path, &response)
		if err != nil {
			return nil, false, err
		}
		if found {
			return response.Items, true, nil
		}
	}
	return nil, false, nil
}

func (c *GrafanaConnector) timeIntervals(ctx context.Context) ([]grafanaTimeInterval, bool, error) {
	var legacy []grafanaTimeInterval
	found, err := c.getOptional(ctx, "/api/v1/provisioning/mute-timings", &legacy)
	if err != nil || found {
		return legacy, found, err
	}
	for _, version := range []string{"v1beta1", "v0alpha1"} {
		path := "/apis/notifications.alerting.grafana.app/" + version + "/namespaces/" + url.PathEscape(c.namespace) + "/timeintervals"
		var response grafanaAppTimeIntervalList
		found, err = c.getOptional(ctx, path, &response)
		if err != nil {
			return nil, false, err
		}
		if !found {
			continue
		}
		intervals := make([]grafanaTimeInterval, 0, len(response.Items))
		for _, item := range response.Items {
			name := strings.TrimSpace(item.Spec.Name)
			if name == "" {
				name = strings.TrimSpace(item.Metadata.Name)
			}
			intervals = append(intervals, grafanaTimeInterval{
				UID: item.Metadata.Name, Name: name, TimeIntervals: item.Spec.TimeIntervals,
				Provenance: strings.TrimSpace(item.Metadata.Annotations["grafana.com/provenance"]),
			})
		}
		return intervals, true, nil
	}
	return nil, false, nil
}

func (c *GrafanaConnector) notificationTemplates(ctx context.Context) ([]grafanaNotificationTemplate, bool, error) {
	var legacy []grafanaNotificationTemplate
	found, err := c.getOptional(ctx, "/api/v1/provisioning/templates", &legacy)
	if err != nil || found {
		return legacy, found, err
	}
	for _, version := range []string{"v1beta1", "v0alpha1"} {
		path := "/apis/notifications.alerting.grafana.app/" + version + "/namespaces/" + url.PathEscape(c.namespace) + "/templategroups"
		var response grafanaAppTemplateGroupList
		found, err = c.getOptional(ctx, path, &response)
		if err != nil {
			return nil, false, err
		}
		if !found {
			continue
		}
		result := make([]grafanaNotificationTemplate, 0, len(response.Items))
		for _, item := range response.Items {
			name := strings.TrimSpace(item.Spec.Title)
			if name == "" {
				name = strings.TrimSpace(item.Metadata.Name)
			}
			result = append(result, grafanaNotificationTemplate{
				UID: item.Metadata.Name, Name: name, Template: item.Spec.Content, Kind: item.Spec.Kind,
				Provenance: strings.TrimSpace(item.Metadata.Annotations["grafana.com/provenance"]),
			})
		}
		return result, true, nil
	}
	return nil, false, nil
}

func (c *GrafanaConnector) dashboard(ctx context.Context, uid string) (grafanaDashboardResponse, error) {
	var response grafanaDashboardResponse
	if err := c.get(ctx, "/api/dashboards/uid/"+url.PathEscape(uid), &response); err != nil {
		return grafanaDashboardResponse{}, err
	}
	return response, nil
}

func (c *GrafanaConnector) dashboardDetails(
	ctx context.Context,
	items []grafanaDashboardSearchItem,
	inline map[string]grafanaDashboardResponse,
) []grafanaDashboardDetailResult {
	results := make([]grafanaDashboardDetailResult, len(items))
	jobs := make(chan int, len(items))
	for index, item := range items {
		if detail, ok := inline[item.UID]; ok {
			results[index].Detail = detail
			continue
		}
		jobs <- index
	}
	close(jobs)

	workerCount := c.dashboardDetailWorkers
	if workerCount <= 0 {
		workerCount = defaultGrafanaDashboardDetailWorkers
	}
	if workerCount > maxGrafanaDashboardDetailWorkers {
		workerCount = maxGrafanaDashboardDetailWorkers
	}
	if workerCount > len(jobs) {
		workerCount = len(jobs)
	}

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index].Detail, results[index].Err = c.dashboard(ctx, items[index].UID)
			}
		}()
	}
	workers.Wait()
	return results
}

func (c *GrafanaConnector) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("grafana %s returned status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

type grafanaDatasource struct {
	ID        int    `json:"id"`
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	Access    string `json:"access"`
	IsDefault bool   `json:"isDefault"`
	ReadOnly  bool   `json:"readOnly"`
	BasicAuth bool   `json:"basicAuth"`
	Created   string `json:"created"`
	Updated   string `json:"updated"`
}

type grafanaHealth struct {
	Database string `json:"database"`
	Version  string `json:"version"`
}

type grafanaDatasourceHealth struct {
	Status string `json:"status"`
}

type grafanaDashboardSearchItem struct {
	UID         string `json:"uid"`
	Title       string `json:"title"`
	FolderUID   string `json:"folderUid"`
	FolderTitle string `json:"folderTitle"`
}

type grafanaDashboardSearchResult struct {
	Items              []grafanaDashboardSearchItem
	Details            map[string]grafanaDashboardResponse
	PageSize           int
	Limit              int
	PageCount          int
	RawItemCount       int
	DuplicateItemCount int
	InvalidItemCount   int
	Truncated          bool
	PaginationStalled  bool
	API                string
	Endpoint           string
	Fallback           bool
}

type grafanaDashboardDetailResult struct {
	Detail grafanaDashboardResponse
	Err    error
}

type grafanaDashboardResponse struct {
	Dashboard grafanaDashboard     `json:"dashboard"`
	Meta      grafanaDashboardMeta `json:"meta"`
}

type grafanaDashboardMeta struct {
	Slug        string `json:"slug"`
	URL         string `json:"url"`
	FolderUID   string `json:"folderUid"`
	FolderTitle string `json:"folderTitle"`
	Created     string `json:"created"`
	Updated     string `json:"updated"`
}

type grafanaDashboard struct {
	UID           string               `json:"uid"`
	Title         string               `json:"title"`
	Version       int                  `json:"version"`
	SchemaVersion int                  `json:"schemaVersion"`
	Tags          []string             `json:"tags"`
	Timezone      string               `json:"timezone"`
	Refresh       string               `json:"refresh"`
	Editable      bool                 `json:"editable"`
	Time          grafanaDashboardTime `json:"time"`
	Annotations   grafanaAnnotations   `json:"annotations"`
	Panels        []grafanaPanel       `json:"panels"`
	Templating    grafanaTemplating    `json:"templating"`
}

type grafanaDashboardTime struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type grafanaAnnotations struct {
	List []grafanaAnnotation `json:"list"`
}

type grafanaAnnotation struct {
	Name string `json:"name"`
}

type grafanaTemplating struct {
	List []grafanaVariable `json:"list"`
}

type grafanaVariable struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Datasource grafanaRef `json:"datasource"`
	Query      any        `json:"query"`
}

type grafanaPanel struct {
	ID          int                 `json:"id"`
	Title       string              `json:"title"`
	Type        string              `json:"type"`
	GridPos     grafanaGridPos      `json:"gridPos"`
	FieldConfig grafanaFieldConfig  `json:"fieldConfig"`
	Options     grafanaPanelOptions `json:"options"`
	Datasource  grafanaRef          `json:"datasource"`
	Targets     []grafanaTarget     `json:"targets"`
	Panels      []grafanaPanel      `json:"panels"`
}

type grafanaGridPos struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

type grafanaFieldConfig struct {
	Defaults grafanaFieldDefaults `json:"defaults"`
}

type grafanaFieldDefaults struct {
	Unit       string            `json:"unit"`
	Thresholds grafanaThresholds `json:"thresholds"`
}

type grafanaThresholds struct {
	Steps []grafanaThresholdStep `json:"steps"`
}

type grafanaThresholdStep struct {
	Color string `json:"color"`
	Value any    `json:"value"`
}

type grafanaPanelOptions struct {
	Legend grafanaPanelLegend `json:"legend"`
}

type grafanaPanelLegend struct {
	DisplayMode string `json:"displayMode"`
}

type grafanaRef struct {
	UID  string `json:"uid"`
	Type string `json:"type"`
}

func (r *grafanaRef) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		r.UID = value
		return nil
	}
	var raw struct {
		UID  string `json:"uid"`
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.UID = raw.UID
	if r.UID == "" {
		r.UID = raw.Name
	}
	r.Type = raw.Type
	return nil
}

type grafanaTarget struct {
	Expression string     `json:"expr"`
	Datasource grafanaRef `json:"datasource"`
}

func (t *grafanaTarget) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if value, ok := raw["datasource"]; ok {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(encoded, &t.Datasource); err != nil {
			return err
		}
	}
	for _, key := range []string{"expr", "expression", "query"} {
		if value := firstString(raw, key); value != "" {
			t.Expression = value
			return nil
		}
	}
	return nil
}

type grafanaAlertRule struct {
	UID                  string                       `json:"uid"`
	Title                string                       `json:"title"`
	Condition            string                       `json:"condition"`
	FolderUID            string                       `json:"folderUID"`
	RuleGroup            string                       `json:"ruleGroup"`
	NoDataState          string                       `json:"noDataState"`
	ExecErrState         string                       `json:"execErrState"`
	For                  string                       `json:"for"`
	Labels               map[string]string            `json:"labels"`
	Annotations          map[string]string            `json:"annotations"`
	IsPaused             bool                         `json:"isPaused"`
	Data                 []grafanaAlertRuleData       `json:"data"`
	NotificationSettings *grafanaNotificationSettings `json:"notification_settings"`
	EvaluationInterval   string                       `json:"-"`
}

type grafanaNotificationSettings struct {
	Receiver string `json:"receiver"`
}

type grafanaContactPoint struct {
	UID                   string          `json:"uid"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	Provenance            string          `json:"provenance"`
	Settings              json.RawMessage `json:"settings"`
	TemplateReferences    []string        `json:"-"`
	InsecureEndpointCount int             `json:"-"`
}

type grafanaNotificationTemplate struct {
	UID        string `json:"uid"`
	Name       string `json:"name"`
	Template   string `json:"template"`
	Provenance string `json:"provenance"`
	Kind       string `json:"kind"`
}

type grafanaTimeInterval struct {
	UID           string            `json:"uid"`
	Name          string            `json:"name"`
	TimeIntervals []json.RawMessage `json:"time_intervals"`
	Provenance    string            `json:"provenance"`
}

type grafanaTimeIntervalDetails struct {
	uid, name, provenance string
	declared              bool
	specCount             int
	muteRefs, activeRefs  int
}

type grafanaNotificationRoute struct {
	Receiver            string                     `json:"receiver"`
	Continue            bool                       `json:"continue"`
	Matchers            json.RawMessage            `json:"matchers"`
	ObjectMatchers      json.RawMessage            `json:"object_matchers"`
	Match               json.RawMessage            `json:"match"`
	MatchRE             json.RawMessage            `json:"match_re"`
	MuteTimeIntervals   []string                   `json:"mute_time_intervals"`
	ActiveTimeIntervals []string                   `json:"active_time_intervals"`
	GroupWait           string                     `json:"group_wait"`
	GroupInterval       string                     `json:"group_interval"`
	RepeatInterval      string                     `json:"repeat_interval"`
	GroupBy             []string                   `json:"group_by"`
	Routes              []grafanaNotificationRoute `json:"routes"`
}

type grafanaAppMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Annotations       map[string]string `json:"annotations"`
}

type grafanaAppListMetadata struct {
	Continue string `json:"continue"`
}

type grafanaAppDashboardList struct {
	Metadata grafanaAppListMetadata `json:"metadata"`
	Items    []grafanaAppDashboard  `json:"items"`
}

type grafanaAppDashboard struct {
	Metadata grafanaAppMetadata `json:"metadata"`
	Spec     grafanaDashboard   `json:"spec"`
}

func (dashboard grafanaAppDashboard) dashboardResponse() grafanaDashboardResponse {
	return grafanaDashboardResponse{
		Dashboard: dashboard.Spec,
		Meta: grafanaDashboardMeta{
			FolderUID: strings.TrimSpace(dashboard.Metadata.Annotations["grafana.app/folder"]),
			Created:   strings.TrimSpace(dashboard.Metadata.CreationTimestamp),
			Updated:   strings.TrimSpace(dashboard.Metadata.Annotations["grafana.app/updatedTimestamp"]),
		},
	}
}

type grafanaAppReceiverList struct {
	Items []grafanaAppReceiver `json:"items"`
}

type grafanaAppReceiver struct {
	Metadata grafanaAppMetadata     `json:"metadata"`
	Spec     grafanaAppReceiverSpec `json:"spec"`
}

type grafanaAppReceiverSpec struct {
	Title        string                          `json:"title"`
	Integrations []grafanaAppReceiverIntegration `json:"integrations"`
}

type grafanaAppReceiverIntegration struct {
	UID      string          `json:"uid"`
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings"`
}

func (receiver grafanaAppReceiver) contactPoints() []grafanaContactPoint {
	name := strings.TrimSpace(receiver.Spec.Title)
	if name == "" {
		name = strings.TrimSpace(receiver.Metadata.Name)
	}
	provenance := strings.TrimSpace(receiver.Metadata.Annotations["grafana.com/provenance"])
	if len(receiver.Spec.Integrations) == 0 {
		return []grafanaContactPoint{{UID: receiver.Metadata.Name, Name: name, Provenance: provenance}}
	}
	result := make([]grafanaContactPoint, 0, len(receiver.Spec.Integrations))
	for _, integration := range receiver.Spec.Integrations {
		uid := strings.TrimSpace(integration.UID)
		if uid == "" {
			uid = strings.TrimSpace(receiver.Metadata.Name)
		}
		result = append(result, grafanaContactPoint{
			UID:                   uid,
			Name:                  name,
			Type:                  strings.TrimSpace(integration.Type),
			Provenance:            provenance,
			TemplateReferences:    grafanaTemplateReferences(integration.Settings),
			InsecureEndpointCount: insecureEndpointCount(integration.Settings),
		})
	}
	return result
}

type grafanaAppRoutingTreeList struct {
	Items []grafanaAppRoutingTree `json:"items"`
}

type grafanaAppInhibitionRuleList struct {
	Items []grafanaAppInhibitionRule `json:"items"`
}

type grafanaAppTimeIntervalList struct {
	Items []grafanaAppTimeInterval `json:"items"`
}

type grafanaAppTemplateGroupList struct {
	Items []grafanaAppTemplateGroup `json:"items"`
}

type grafanaAppTemplateGroup struct {
	Metadata grafanaAppMetadata          `json:"metadata"`
	Spec     grafanaAppTemplateGroupSpec `json:"spec"`
}

type grafanaAppTemplateGroupSpec struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Kind    string `json:"kind"`
}

type grafanaAppTimeInterval struct {
	Metadata grafanaAppMetadata         `json:"metadata"`
	Spec     grafanaAppTimeIntervalSpec `json:"spec"`
}

type grafanaAppTimeIntervalSpec struct {
	Name          string            `json:"name"`
	TimeIntervals []json.RawMessage `json:"time_intervals"`
}

type grafanaAppInhibitionRule struct {
	Metadata grafanaAppMetadata           `json:"metadata"`
	Spec     grafanaAppInhibitionRuleSpec `json:"spec"`
}

type grafanaAppInhibitionRuleSpec struct {
	SourceMatchers []grafanaAppInhibitionMatcher `json:"source_matchers"`
	TargetMatchers []grafanaAppInhibitionMatcher `json:"target_matchers"`
	Equal          []string                      `json:"equal"`
}

type grafanaAppInhibitionMatcher struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	Value string `json:"value"`
}

type grafanaAppRoutingTree struct {
	Metadata grafanaAppMetadata        `json:"metadata"`
	Spec     grafanaAppRoutingTreeSpec `json:"spec"`
}

type grafanaAppRoutingTreeSpec struct {
	Defaults grafanaAppRoutingDefaults `json:"defaults"`
	Routes   []grafanaAppRoutingRoute  `json:"routes"`
}

type grafanaAppRoutingDefaults struct {
	Receiver            string   `json:"receiver"`
	GroupWait           string   `json:"group_wait"`
	GroupInterval       string   `json:"group_interval"`
	RepeatInterval      string   `json:"repeat_interval"`
	GroupWaitCamel      string   `json:"groupWait"`
	GroupIntervalCamel  string   `json:"groupInterval"`
	RepeatIntervalCamel string   `json:"repeatInterval"`
	GroupBy             []string `json:"group_by"`
}

type grafanaAppRoutingRoute struct {
	Receiver            string                   `json:"receiver"`
	Continue            bool                     `json:"continue"`
	Matchers            json.RawMessage          `json:"matchers"`
	MuteTimeIntervals   []string                 `json:"mute_time_intervals"`
	ActiveTimeIntervals []string                 `json:"active_time_intervals"`
	GroupWait           string                   `json:"group_wait"`
	GroupInterval       string                   `json:"group_interval"`
	RepeatInterval      string                   `json:"repeat_interval"`
	GroupWaitCamel      string                   `json:"groupWait"`
	GroupIntervalCamel  string                   `json:"groupInterval"`
	RepeatIntervalCamel string                   `json:"repeatInterval"`
	GroupBy             []string                 `json:"group_by"`
	Routes              []grafanaAppRoutingRoute `json:"routes"`
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (tree grafanaAppRoutingTree) notificationRoute() grafanaNotificationRoute {
	root := grafanaNotificationRoute{
		Receiver:  strings.TrimSpace(tree.Spec.Defaults.Receiver),
		GroupWait: firstNonEmpty(tree.Spec.Defaults.GroupWait, tree.Spec.Defaults.GroupWaitCamel), GroupInterval: firstNonEmpty(tree.Spec.Defaults.GroupInterval, tree.Spec.Defaults.GroupIntervalCamel),
		RepeatInterval: firstNonEmpty(tree.Spec.Defaults.RepeatInterval, tree.Spec.Defaults.RepeatIntervalCamel),
		GroupBy:        tree.Spec.Defaults.GroupBy,
	}
	for _, route := range tree.Spec.Routes {
		root.Routes = append(root.Routes, route.notificationRoute())
	}
	return root
}

func (route grafanaAppRoutingRoute) notificationRoute() grafanaNotificationRoute {
	result := grafanaNotificationRoute{
		Receiver: strings.TrimSpace(route.Receiver), Continue: route.Continue,
		Matchers:          route.Matchers,
		MuteTimeIntervals: route.MuteTimeIntervals, ActiveTimeIntervals: route.ActiveTimeIntervals,
		GroupWait: firstNonEmpty(route.GroupWait, route.GroupWaitCamel), GroupInterval: firstNonEmpty(route.GroupInterval, route.GroupIntervalCamel),
		RepeatInterval: firstNonEmpty(route.RepeatInterval, route.RepeatIntervalCamel),
		GroupBy:        route.GroupBy,
	}
	for _, child := range route.Routes {
		result.Routes = append(result.Routes, child.notificationRoute())
	}
	return result
}

type grafanaAppAlertRuleList struct {
	Items []grafanaAppAlertRule `json:"items"`
}

type grafanaAppAlertRule struct {
	Metadata grafanaAppMetadata      `json:"metadata"`
	Spec     grafanaAppAlertRuleSpec `json:"spec"`
}

type grafanaAppAlertRuleSpec struct {
	Title                string                               `json:"title"`
	Paused               bool                                 `json:"paused"`
	Labels               map[string]string                    `json:"labels"`
	Annotations          map[string]string                    `json:"annotations"`
	For                  string                               `json:"for"`
	NoDataState          string                               `json:"noDataState"`
	ExecErrState         string                               `json:"execErrState"`
	NotificationSettings *grafanaAppAlertNotificationSettings `json:"notificationSettings"`
	Expressions          map[string]grafanaAppAlertExpression `json:"expressions"`
	Trigger              grafanaAppAlertTrigger               `json:"trigger"`
}

type grafanaAppAlertNotificationSettings struct {
	Type     string `json:"type"`
	Receiver string `json:"receiver"`
}

type grafanaAppAlertExpression struct {
	DatasourceUID string         `json:"datasourceUID"`
	Model         map[string]any `json:"model"`
	Source        bool           `json:"source"`
}

type grafanaAppAlertTrigger struct {
	Interval string `json:"interval"`
}

func (rule grafanaAppAlertRule) legacyRule() grafanaAlertRule {
	uid := strings.TrimSpace(rule.Metadata.Name)
	if uid == "" {
		uid = strings.TrimSpace(rule.Metadata.UID)
	}
	result := grafanaAlertRule{
		UID:                uid,
		Title:              rule.Spec.Title,
		FolderUID:          strings.TrimSpace(rule.Metadata.Annotations["grafana.app/folder"]),
		NoDataState:        rule.Spec.NoDataState,
		ExecErrState:       rule.Spec.ExecErrState,
		For:                rule.Spec.For,
		Labels:             cloneLabels(rule.Spec.Labels),
		Annotations:        cloneLabels(rule.Spec.Annotations),
		IsPaused:           rule.Spec.Paused,
		EvaluationInterval: strings.TrimSpace(rule.Spec.Trigger.Interval),
	}
	for refID, expression := range rule.Spec.Expressions {
		result.Data = append(result.Data, grafanaAlertRuleData{
			RefID:         refID,
			DatasourceUID: strings.TrimSpace(expression.DatasourceUID),
			Model:         expression.Model,
		})
		if expression.Source {
			result.Condition = refID
		}
	}
	sort.Slice(result.Data, func(i, j int) bool { return result.Data[i].RefID < result.Data[j].RefID })
	if settings := rule.Spec.NotificationSettings; settings != nil {
		settingsType := strings.TrimSpace(settings.Type)
		if settingsType == "" || strings.EqualFold(settingsType, "SimplifiedRouting") {
			result.NotificationSettings = &grafanaNotificationSettings{Receiver: strings.TrimSpace(settings.Receiver)}
		}
	}
	return result
}

type grafanaAlertRuleData struct {
	RefID         string         `json:"refId"`
	DatasourceUID string         `json:"datasourceUid"`
	Datasource    grafanaRef     `json:"datasource"`
	Model         map[string]any `json:"model"`
}

func (d *grafanaAlertRuleData) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.RefID = firstString(raw, "refId", "refID", "ref")
	d.DatasourceUID = firstString(raw, "datasourceUid", "datasourceUID")
	if value, ok := raw["model"]; ok {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(encoded, &d.Model); err != nil {
			return err
		}
	}
	if value, ok := raw["datasource"]; ok {
		if err := decodeGrafanaRef(value, &d.Datasource); err != nil {
			return err
		}
	}
	if d.Datasource.UID == "" && d.Model != nil {
		if value, ok := d.Model["datasource"]; ok {
			if err := decodeGrafanaRef(value, &d.Datasource); err != nil {
				return err
			}
		}
	}
	if d.DatasourceUID == "" {
		d.DatasourceUID = strings.TrimSpace(d.Datasource.UID)
	}
	return nil
}

func grafanaResource(resourceType model.ResourceType, name string, instance string, externalID string, now time.Time) model.Resource {
	uid := model.StableID(string(resourceType), grafanaSystem, instance, externalID)
	if name == "" {
		name = externalID
	}
	return model.Resource{
		ID:        uid,
		Type:      resourceType,
		Name:      name,
		UID:       uid,
		Source:    model.SourceInfo{System: grafanaSystem, Instance: instance, ExternalID: externalID},
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func grafanaRelationship(fromID, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID(fromID, string(relationshipType), toID),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}

func appendGrafanaRelationship(relationships *[]model.Relationship, fromID string, toID string, relationshipType model.RelationshipType, now time.Time) {
	relationship := grafanaRelationship(fromID, toID, relationshipType, now)
	for _, existing := range *relationships {
		if existing.ID == relationship.ID {
			return
		}
	}
	*relationships = append(*relationships, relationship)
}

func datasourceForRef(ref grafanaRef, datasourceByUID map[string]model.Resource) (model.Resource, bool) {
	uid := strings.TrimSpace(ref.UID)
	if uid == "" {
		uid = grafanaDefaultDatasourceKey
	}
	datasource, ok := datasourceByUID[uid]
	return datasource, ok
}

func grafanaDatasourceMetricInstance(datasource model.Resource) string {
	if bound := strings.TrimRight(strings.TrimSpace(datasource.Metadata[grafanaMetricInstanceMetadataKey]), "/"); bound != "" {
		return bound
	}
	return strings.TrimRight(strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceURL]), "/")
}

func decodeGrafanaRef(value any, target *grafanaRef) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}

func grafanaAlertRuleDataRef(item grafanaAlertRuleData) grafanaRef {
	ref := item.Datasource
	if ref.UID == "" {
		ref.UID = strings.TrimSpace(item.DatasourceUID)
	}
	return ref
}

func shouldTreatGrafanaRefAsPromQL(ref grafanaRef, datasourceByUID map[string]model.Resource) bool {
	uid := strings.ToLower(strings.TrimSpace(ref.UID))
	if uid == "__expr__" || uid == "-- mixed --" {
		return false
	}
	if datasource, ok := datasourceForRef(ref, datasourceByUID); ok {
		return isPrometheusDatasource(datasource)
	}
	if ref.Type != "" {
		return strings.EqualFold(strings.TrimSpace(ref.Type), "prometheus")
	}
	return strings.TrimSpace(ref.UID) == ""
}

func isPrometheusDatasource(datasource model.Resource) bool {
	datasourceType := strings.ToLower(strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceType]))
	return datasourceType == "" || datasourceType == "prometheus"
}

func queryLanguageForDatasource(datasource model.Resource) string {
	return queryLanguageForDatasourceType(datasource.Metadata[model.MetadataDatasourceType])
}

func sortedStringSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func addGrafanaAlertRules(resources map[string]model.Resource, relationships *[]model.Relationship, rules []grafanaAlertRule, datasourceByUID map[string]model.Resource, instance string, now time.Time) {
	for _, rule := range rules {
		ruleResource := grafanaAlertRuleResource(rule, datasourceByUID, instance, now)
		addResource(resources, ruleResource)

		for _, item := range rule.Data {
			expression := grafanaAlertRuleExpression(item)
			if expression == "" {
				continue
			}
			metricInstance := "grafana:" + instance
			datasourceRef := grafanaAlertRuleDataRef(item)
			if datasource, ok := datasourceForRef(datasourceRef, datasourceByUID); ok {
				*relationships = append(*relationships, grafanaRelationship(ruleResource.ID, datasource.ID, model.RelationshipUses, now))
				if !isPrometheusDatasource(datasource) {
					continue
				}
				if datasourceURL := grafanaDatasourceMetricInstance(datasource); datasourceURL != "" {
					metricInstance = datasourceURL
				}
			} else if !shouldTreatGrafanaRefAsPromQL(datasourceRef, datasourceByUID) {
				continue
			}
			for _, metricName := range extractMetricNames(expression) {
				metricResource := prometheusResource(model.ResourceTypeMetric, metricName, metricInstance, "metric:"+metricName, now)
				addResource(resources, metricResource)
				*relationships = append(*relationships, grafanaRelationship(ruleResource.ID, metricResource.ID, model.RelationshipUses, now))
			}
		}
	}
}

func addGrafanaReceivers(resources map[string]model.Resource, relationships *[]model.Relationship, contactPoints []grafanaContactPoint, policy *grafanaNotificationRoute, rules []grafanaAlertRule, instance string, now time.Time) {
	type receiverDetails struct {
		uids                  map[string]bool
		integrations          map[string]bool
		provenance            map[string]bool
		declared              bool
		routeCount            int
		insecureEndpointCount int
	}
	detailsByName := make(map[string]*receiverDetails)
	policyReceivers := make(map[string]bool)
	detailsFor := func(name string) *receiverDetails {
		name = strings.TrimSpace(name)
		if detailsByName[name] == nil {
			detailsByName[name] = &receiverDetails{
				uids:         make(map[string]bool),
				integrations: make(map[string]bool),
				provenance:   make(map[string]bool),
			}
		}
		return detailsByName[name]
	}

	for _, contactPoint := range contactPoints {
		name := strings.TrimSpace(contactPoint.Name)
		if name == "" {
			continue
		}
		details := detailsFor(name)
		details.declared = true
		if uid := strings.TrimSpace(contactPoint.UID); uid != "" {
			details.uids[uid] = true
		}
		if integration := strings.TrimSpace(contactPoint.Type); integration != "" {
			details.integrations[integration] = true
		}
		if provenance := strings.TrimSpace(contactPoint.Provenance); provenance != "" {
			details.provenance[provenance] = true
		}
		details.insecureEndpointCount += contactPoint.InsecureEndpointCount
	}
	var collectRoutes func(grafanaNotificationRoute)
	collectRoutes = func(route grafanaNotificationRoute) {
		if name := strings.TrimSpace(route.Receiver); name != "" {
			detailsFor(name).routeCount++
			policyReceivers[name] = true
		}
		for _, child := range route.Routes {
			collectRoutes(child)
		}
	}
	if policy != nil {
		collectRoutes(*policy)
	}
	for _, alertRule := range rules {
		if alertRule.NotificationSettings == nil {
			continue
		}
		if name := strings.TrimSpace(alertRule.NotificationSettings.Receiver); name != "" {
			detailsFor(name).routeCount++
		}
	}

	receiverByName := make(map[string]model.Resource, len(detailsByName))
	for name, details := range detailsByName {
		if name == "" {
			continue
		}
		resource := grafanaResource(model.ResourceTypeReceiver, name, instance, "receiver:"+name, now)
		resource.Metadata = map[string]string{
			"receiver_name": name,
			"declared":      strconv.FormatBool(details.declared),
		}
		if details.routeCount > 0 {
			resource.Metadata["referenced_by_route"] = "true"
			resource.Metadata[model.MetadataReceiverRouteCount] = strconv.Itoa(details.routeCount)
		}
		if values := sortedStringSet(details.integrations); len(values) > 0 {
			resource.Metadata[model.MetadataReceiverIntegrations] = strings.Join(values, ",")
		}
		if values := sortedStringSet(details.uids); len(values) > 0 {
			resource.Metadata[model.MetadataReceiverUIDs] = strings.Join(values, ",")
		}
		if values := sortedStringSet(details.provenance); len(values) > 0 {
			resource.Metadata[model.MetadataReceiverProvenance] = strings.Join(values, ",")
		}
		resource.Metadata[model.MetadataReceiverInsecureEndpointCount] = strconv.Itoa(details.insecureEndpointCount)
		addResource(resources, resource)
		receiverByName[name] = resource
	}
	if policy != nil {
		stats := grafanaRoutingPolicyStats(*policy)
		policyResource := grafanaResource(model.ResourceTypeNotificationPolicy, "default", instance, "notification-policy:default", now)
		applyRoutingPolicyMetadata(&policyResource, stats)
		addResource(resources, policyResource)
		for receiverName := range policyReceivers {
			if receiver, ok := receiverByName[receiverName]; ok {
				appendGrafanaRelationship(relationships, policyResource.ID, receiver.ID, model.RelationshipUses, now)
			}
		}
	}

	for _, alertRule := range rules {
		if alertRule.NotificationSettings == nil {
			continue
		}
		name := strings.TrimSpace(alertRule.NotificationSettings.Receiver)
		receiver, ok := receiverByName[name]
		if !ok {
			continue
		}
		externalID := strings.TrimSpace(alertRule.UID)
		if externalID == "" {
			externalID = alertRule.Title
		}
		ruleResource := grafanaResource(model.ResourceTypeAlertRule, alertRule.Title, instance, "alert-rule:"+externalID, now)
		appendGrafanaRelationship(relationships, ruleResource.ID, receiver.ID, model.RelationshipUses, now)
	}
}

func addGrafanaInhibitionRules(resources map[string]model.Resource, rules []grafanaAppInhibitionRule, instance string, now time.Time) {
	for _, rule := range rules {
		externalID := strings.TrimSpace(rule.Metadata.Name)
		if externalID == "" {
			encoded, _ := json.Marshal(rule.Spec)
			externalID = model.StableID("grafana-inhibition-rule", string(encoded))
		}
		name := strings.TrimSpace(rule.Metadata.Name)
		if name == "" {
			name = "inhibition rule " + externalID[:min(len(externalID), 8)]
		}
		sourceRegex, sourceBroad := grafanaInhibitionMatcherStats(rule.Spec.SourceMatchers)
		targetRegex, targetBroad := grafanaInhibitionMatcherStats(rule.Spec.TargetMatchers)
		details := inhibitionRuleDetails{
			name: name, externalID: "inhibition-rule:" + externalID,
			sourceMatcherCount: len(rule.Spec.SourceMatchers), targetMatcherCount: len(rule.Spec.TargetMatchers),
			equalLabelCount:  uniqueNonEmptyStringCount(rule.Spec.Equal),
			sourceRegexCount: sourceRegex, targetRegexCount: targetRegex,
			sourceBroadCount: sourceBroad, targetBroadCount: targetBroad,
		}
		resource := grafanaResource(model.ResourceTypeInhibitionRule, name, instance, details.externalID, now)
		applyInhibitionRuleMetadata(&resource, details)
		addResource(resources, resource)
	}
}

func addGrafanaTimeIntervals(resources map[string]model.Resource, relationships *[]model.Relationship, definitions []grafanaTimeInterval, definitionsAvailable bool, policy *grafanaNotificationRoute, instance string, now time.Time) {
	if !definitionsAvailable {
		return
	}
	byName := make(map[string]grafanaTimeIntervalDetails)
	for _, definition := range definitions {
		name := strings.TrimSpace(definition.Name)
		if name == "" {
			name = strings.TrimSpace(definition.UID)
		}
		if name == "" {
			continue
		}
		details := byName[name]
		details.name, details.uid, details.provenance = name, strings.TrimSpace(definition.UID), strings.TrimSpace(definition.Provenance)
		details.declared = true
		details.specCount += len(definition.TimeIntervals)
		byName[name] = details
	}
	if policy != nil {
		collectGrafanaTimeIntervalReferences(*policy, byName)
	}
	var policyResource model.Resource
	if policy != nil {
		policyResource = grafanaResource(model.ResourceTypeNotificationPolicy, "default", instance, "notification-policy:default", now)
	}
	for _, details := range byName {
		externalID := details.uid
		if externalID == "" {
			externalID = details.name
		}
		resource := grafanaResource(model.ResourceTypeTimeInterval, details.name, instance, "time-interval:"+externalID, now)
		resource.Metadata = map[string]string{
			model.MetadataTimeIntervalDeclared:       strconv.FormatBool(details.declared),
			model.MetadataTimeIntervalSpecCount:      strconv.Itoa(details.specCount),
			model.MetadataTimeIntervalMuteRefCount:   strconv.Itoa(details.muteRefs),
			model.MetadataTimeIntervalActiveRefCount: strconv.Itoa(details.activeRefs),
		}
		if details.provenance != "" {
			resource.Metadata[model.MetadataReceiverProvenance] = details.provenance
		}
		addResource(resources, resource)
		if policy != nil && details.muteRefs+details.activeRefs > 0 {
			appendGrafanaRelationship(relationships, policyResource.ID, resource.ID, model.RelationshipUses, now)
		}
	}
}

var (
	grafanaTemplateCallPattern   = regexp.MustCompile(`\{\{\s*template\s+"([^"]+)"`)
	grafanaTemplateDefinePattern = regexp.MustCompile(`\{\{[-]?\s*define\s+"([^"]+)"`)
)

var grafanaDocumentedBuiltinTemplateNames = map[string]bool{
	"__subject": true, "__text_values_list": true, "__text_alert_list": true,
	"default.title": true, "default.message": true,
}

func grafanaTemplateReferences(settings json.RawMessage) []string {
	if len(settings) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(settings, &decoded); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			for _, match := range grafanaTemplateCallPattern.FindAllStringSubmatch(typed, -1) {
				if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
					seen[strings.TrimSpace(match[1])] = true
				}
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(decoded)
	return sortedStringSet(seen)
}

func grafanaTemplateDefinitionNames(content string) []string {
	seen := make(map[string]bool)
	for _, match := range grafanaTemplateDefinePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			seen[strings.TrimSpace(match[1])] = true
		}
	}
	return sortedStringSet(seen)
}

func grafanaTemplateDefinitionOccurrences(content string) map[string]int {
	result := make(map[string]int)
	for _, match := range grafanaTemplateDefinePattern.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			result[strings.TrimSpace(match[1])]++
		}
	}
	return result
}

func isGrafanaBuiltinTemplateName(name string) bool {
	name = strings.TrimSpace(name)
	return grafanaDocumentedBuiltinTemplateNames[name] || strings.HasPrefix(name, "__") || strings.Contains(name, ".default.")
}

func addGrafanaNotificationTemplates(resources map[string]model.Resource, relationships *[]model.Relationship, templates []grafanaNotificationTemplate, templatesAvailable bool, contactPoints []grafanaContactPoint, instance string, now time.Time) {
	if !templatesAvailable {
		return
	}
	resourcesByDefinition := make(map[string][]string)
	definitionResources := make(map[string][]string)
	definitionOccurrences := make(map[string]map[string]int)
	definitionNamesByResource := make(map[string][]string)
	for _, template := range templates {
		name := strings.TrimSpace(template.Name)
		if name == "" {
			name = strings.TrimSpace(template.UID)
		}
		if name == "" {
			continue
		}
		externalID := strings.TrimSpace(template.UID)
		if externalID == "" {
			externalID = name
		}
		definitionNames := grafanaTemplateDefinitionNames(template.Template)
		resource := grafanaResource(model.ResourceTypeNotificationTemplate, name, instance, "notification-template:"+externalID, now)
		resource.Metadata = map[string]string{
			model.MetadataTemplateDeclared:        "true",
			model.MetadataTemplateContentLength:   strconv.Itoa(len(template.Template)),
			model.MetadataTemplateDefinitionCount: strconv.Itoa(len(definitionNames)),
			model.MetadataTemplateConflictCount:   "0",
			model.MetadataTemplateReferenceCount:  "0",
		}
		if len(definitionNames) > 0 {
			resource.Metadata[model.MetadataTemplateDefinitionNames] = strings.Join(definitionNames, ",")
		}
		if provenance := strings.TrimSpace(template.Provenance); provenance != "" {
			resource.Metadata[model.MetadataReceiverProvenance] = provenance
		}
		if kind := strings.TrimSpace(template.Kind); kind != "" {
			resource.Metadata[model.MetadataTemplateKind] = kind
		}
		addResource(resources, resource)
		definitionOccurrences[resource.ID] = grafanaTemplateDefinitionOccurrences(template.Template)
		definitionNamesByResource[resource.ID] = definitionNames
		resourcesByDefinition[name] = append(resourcesByDefinition[name], resource.ID)
		for _, definitionName := range definitionNames {
			resourcesByDefinition[definitionName] = append(resourcesByDefinition[definitionName], resource.ID)
			definitionResources[definitionName] = append(definitionResources[definitionName], resource.ID)
		}
	}
	for resourceID, definitionNames := range definitionNamesByResource {
		resource := resources[resourceID]
		if strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataTemplateKind]), "grafana") {
			continue
		}
		conflicts := make(map[string]bool)
		for _, name := range definitionNames {
			if definitionOccurrences[resourceID][name] > 1 || len(definitionResources[name]) > 1 || grafanaDocumentedBuiltinTemplateNames[name] {
				conflicts[name] = true
			}
		}
		conflictNames := sortedStringSet(conflicts)
		resource.Metadata[model.MetadataTemplateConflictCount] = strconv.Itoa(len(conflictNames))
		if len(conflictNames) > 0 {
			resource.Metadata[model.MetadataTemplateConflictNames] = strings.Join(conflictNames, ",")
		}
		resources[resourceID] = resource
	}

	seenRelationship := make(map[string]bool)
	for _, contactPoint := range contactPoints {
		receiverName := strings.TrimSpace(contactPoint.Name)
		if receiverName == "" {
			continue
		}
		receiver := grafanaResource(model.ResourceTypeReceiver, receiverName, instance, "receiver:"+receiverName, now)
		for _, reference := range contactPoint.TemplateReferences {
			if len(resourcesByDefinition[reference]) == 0 && !isGrafanaBuiltinTemplateName(reference) {
				placeholder := grafanaResource(model.ResourceTypeNotificationTemplate, reference, instance, "notification-template-reference:"+reference, now)
				placeholder.Metadata = map[string]string{
					model.MetadataTemplateDeclared:        "false",
					model.MetadataTemplateDefinitionCount: "0",
					model.MetadataTemplateConflictCount:   "0",
					model.MetadataTemplateReferenceCount:  "0",
				}
				addResource(resources, placeholder)
				resourcesByDefinition[reference] = append(resourcesByDefinition[reference], placeholder.ID)
			}
			for _, templateID := range resourcesByDefinition[reference] {
				key := receiver.ID + "|" + templateID
				if seenRelationship[key] {
					continue
				}
				seenRelationship[key] = true
				appendGrafanaRelationship(relationships, receiver.ID, templateID, model.RelationshipUses, now)
				resource := resources[templateID]
				resource.Metadata[model.MetadataTemplateReferenceCount] = strconv.Itoa(notificationPolicyMetadataValue(resource.Metadata[model.MetadataTemplateReferenceCount]) + 1)
				resources[templateID] = resource
			}
		}
	}
}

func notificationPolicyMetadataValue(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func collectGrafanaTimeIntervalReferences(route grafanaNotificationRoute, byName map[string]grafanaTimeIntervalDetails) {
	for _, name := range route.MuteTimeIntervals {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		details := byName[name]
		details.name = name
		details.muteRefs++
		byName[name] = details
	}
	for _, name := range route.ActiveTimeIntervals {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		details := byName[name]
		details.name = name
		details.activeRefs++
		byName[name] = details
	}
	for _, child := range route.Routes {
		collectGrafanaTimeIntervalReferences(child, byName)
	}
}

func grafanaInhibitionMatcherStats(matchers []grafanaAppInhibitionMatcher) (int, int) {
	regexCount := 0
	broadCount := 0
	for _, matcher := range matchers {
		if matcher.Type == "=~" || matcher.Type == "!~" {
			regexCount++
		}
		if matcher.Type == "=~" && broadRegex(matcher.Value) {
			broadCount++
		}
	}
	return regexCount, broadCount
}

func grafanaRoutingPolicyStats(policy grafanaNotificationRoute) routingPolicyStats {
	stats := routingPolicyStats{defaultReceiver: strings.TrimSpace(policy.Receiver), maxDepth: 1}
	collectGrafanaRouteStats(policy, 1, true, &stats)
	collectGrafanaTimingStats(policy, defaultNotificationTiming(), &stats)
	return stats
}

func collectGrafanaTimingStats(route grafanaNotificationRoute, inherited notificationTiming, stats *routingPolicyStats) {
	effective := applyNotificationTiming(route.GroupWait, route.GroupInterval, route.RepeatInterval, inherited, stats)
	for _, child := range route.Routes {
		collectGrafanaTimingStats(child, effective, stats)
	}
}

func collectGrafanaRouteStats(route grafanaNotificationRoute, depth int, root bool, stats *routingPolicyStats) {
	stats.routeCount++
	if depth > stats.maxDepth {
		stats.maxDepth = depth
	}
	if route.Continue {
		stats.continueRouteCount++
	}
	if len(route.MuteTimeIntervals) > 0 || len(route.ActiveTimeIntervals) > 0 {
		stats.timeIntervalRouteCount++
	}
	if notificationGroupingDisabled(route.GroupBy) {
		stats.ungroupedRouteCount++
	}
	if !root && grafanaRouteMatcherCount(route) == 0 {
		stats.catchAllRouteCount++
		if route.Continue {
			stats.catchAllContinueCount++
		}
	}
	for index, child := range route.Routes {
		if grafanaRouteMatcherCount(child) == 0 && !child.Continue && index < len(route.Routes)-1 {
			for _, shadowed := range route.Routes[index+1:] {
				stats.shadowedRouteCount += grafanaRouteTreeSize(shadowed)
			}
			break
		}
	}
	for _, child := range route.Routes {
		collectGrafanaRouteStats(child, depth+1, false, stats)
	}
}

func grafanaRouteMatcherCount(route grafanaNotificationRoute) int {
	return jsonCollectionCount(route.Matchers) + jsonCollectionCount(route.ObjectMatchers) + jsonCollectionCount(route.Match) + jsonCollectionCount(route.MatchRE)
}

func grafanaRouteTreeSize(route grafanaNotificationRoute) int {
	size := 1
	for _, child := range route.Routes {
		size += grafanaRouteTreeSize(child)
	}
	return size
}

func jsonCollectionCount(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0
	}
	switch typed := value.(type) {
	case []any:
		return len(typed)
	case map[string]any:
		return len(typed)
	case string:
		if strings.TrimSpace(typed) != "" {
			return 1
		}
	}
	return 0
}

func grafanaAlertRuleResource(rule grafanaAlertRule, datasourceByUID map[string]model.Resource, instance string, now time.Time) model.Resource {
	externalID := rule.UID
	if externalID == "" {
		externalID = rule.Title
	}
	resource := grafanaResource(model.ResourceTypeAlertRule, rule.Title, instance, "alert-rule:"+externalID, now)
	resource.Labels = cloneLabels(rule.Labels)
	resource.Metadata = map[string]string{
		model.MetadataEnabled:      "true",
		"condition":                rule.Condition,
		"folder_uid":               rule.FolderUID,
		"rule_group":               rule.RuleGroup,
		model.MetadataNoDataState:  rule.NoDataState,
		model.MetadataExecErrState: rule.ExecErrState,
		model.MetadataAlertFor:     rule.For,
	}
	if interval := strings.TrimSpace(rule.EvaluationInterval); interval != "" {
		resource.Metadata[model.MetadataEvaluationInterval] = interval
	}
	if expressions := grafanaAlertRulePromQLExpressions(rule, datasourceByUID); len(expressions) > 0 {
		setQueryMetadata(resource.Metadata, model.MetadataPromQL, strings.Join(expressions, "\n"))
	}
	for key, value := range rule.Annotations {
		if key == "" || value == "" {
			continue
		}
		resource.Metadata["annotation."+key] = value
	}
	if rule.IsPaused {
		resource.Status = model.ResourceStatusDeprecated
		resource.Metadata[model.MetadataEnabled] = "false"
		resource.Metadata[model.MetadataDisabled] = "true"
	}
	annotateSLORuleMetadata(&resource)
	return resource
}

func grafanaAlertRulePromQLExpressions(rule grafanaAlertRule, datasourceByUID map[string]model.Resource) []string {
	expressions := make([]string, 0, len(rule.Data))
	for _, item := range rule.Data {
		expression := grafanaAlertRuleExpression(item)
		if expression == "" {
			continue
		}
		datasourceRef := grafanaAlertRuleDataRef(item)
		if datasource, ok := datasourceForRef(datasourceRef, datasourceByUID); ok {
			if !isPrometheusDatasource(datasource) {
				continue
			}
		} else if !shouldTreatGrafanaRefAsPromQL(datasourceRef, datasourceByUID) {
			continue
		}
		if expression != "" {
			expressions = append(expressions, expression)
		}
	}
	return expressions
}

func grafanaAlertRuleExpression(item grafanaAlertRuleData) string {
	for _, key := range []string{"expr", "expression", "query"} {
		if value := firstString(item.Model, key); value != "" {
			return value
		}
	}
	return ""
}

func grafanaVariableExpression(variable grafanaVariable) string {
	if variable.Type != "" && variable.Type != "query" {
		return ""
	}
	switch query := variable.Query.(type) {
	case string:
		return strings.TrimSpace(query)
	case map[string]any:
		for _, key := range []string{"query", "expr", "expression"} {
			if value := firstString(query, key); value != "" {
				return value
			}
		}
	}
	return ""
}

func extractGrafanaVariableMetricNames(expression string) []string {
	expression = strings.TrimSpace(expression)
	if inner, ok := grafanaFunctionArgument(expression, "label_values", 0); ok {
		return extractMetricNames(inner)
	}
	return extractMetricNames(expression)
}

func grafanaFunctionArgument(expression string, functionName string, index int) (string, bool) {
	prefix := functionName + "("
	if !strings.HasPrefix(expression, prefix) || !strings.HasSuffix(expression, ")") {
		return "", false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, prefix), ")"))
	args := splitGrafanaFunctionArgs(inner)
	if index < 0 || index >= len(args) {
		return "", false
	}
	return strings.TrimSpace(args[index]), true
}

func splitGrafanaFunctionArgs(value string) []string {
	args := make([]string, 0)
	runes := []rune(value)
	depth := 0
	inQuote := rune(0)
	start := 0
	for i, ch := range runes {
		if inQuote != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' || ch == '`' {
			inQuote = ch
			continue
		}
		switch ch {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				args = append(args, string(runes[start:i]))
				start = i + 1
			}
		}
	}
	args = append(args, string(runes[start:]))
	return args
}

func flattenPanels(panels []grafanaPanel) []grafanaPanel {
	flattened := make([]grafanaPanel, 0)
	for _, panel := range panels {
		if len(panel.Panels) > 0 {
			flattened = append(flattened, flattenPanels(panel.Panels)...)
			continue
		}
		flattened = append(flattened, panel)
	}
	return flattened
}

func extractMetricNames(expression string) []string {
	return ExtractPromQLMetricNames(expression)
}
