package connector

import (
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/queryparse"
)

func addGrafanaPanelQueryDependencies(
	resources map[string]model.Resource,
	relationships *[]model.Relationship,
	panelResource model.Resource,
	panel grafanaPanel,
	datasourceByUID map[string]model.Resource,
	instance string,
	now time.Time,
) {
	logStreams := map[string]bool{}
	traceServices := map[string]bool{}
	tables := map[string]bool{}
	parseErrors := 0

	for _, target := range panel.Targets {
		query := strings.TrimSpace(target.Expression)
		if query == "" {
			continue
		}
		datasource, ok := effectiveGrafanaTargetDatasource(panel, target, datasourceByUID)
		if !ok {
			continue
		}
		switch queryLanguageForDatasource(datasource) {
		case "logql":
			dependencies, err := queryparse.LogStreams(query)
			if err != nil {
				parseErrors++
				continue
			}
			for _, dependency := range dependencies {
				resource := grafanaResource(
					model.ResourceTypeLogStream,
					"Log stream "+dependency.Fingerprint[:8],
					instance,
					"query-log-stream:"+datasource.ID+":"+dependency.Fingerprint,
					now,
				)
				resource.Metadata = map[string]string{
					model.MetadataQueryDependencyKind:         "log_stream",
					model.MetadataQueryDependencyLanguage:     "logql",
					model.MetadataQueryDependencyMatcherCount: strconv.Itoa(dependency.MatcherCount),
					model.MetadataQueryDependencyLabelCount:   strconv.Itoa(dependency.LabelCount),
				}
				addResource(resources, resource)
				appendGrafanaRelationship(relationships, panelResource.ID, resource.ID, model.RelationshipUses, now)
				logStreams[resource.ID] = true
			}
		case "traceql":
			dependencies, err := queryparse.TraceServices(query)
			if err != nil {
				parseErrors++
				continue
			}
			for _, service := range dependencies {
				resource := grafanaResource(
					model.ResourceTypeTraceService,
					service,
					instance,
					"query-trace-service:"+datasource.ID+":"+model.StableID(service),
					now,
				)
				resource.Labels = map[string]string{model.MetadataService: service}
				resource.Metadata = map[string]string{
					model.MetadataQueryDependencyKind:     "trace_service",
					model.MetadataQueryDependencyLanguage: "traceql",
					model.MetadataTraceService:            service,
				}
				addResource(resources, resource)
				appendGrafanaRelationship(relationships, panelResource.ID, resource.ID, model.RelationshipUses, now)
				traceServices[resource.ID] = true
			}
		case "sql":
			dependencies, err := queryparse.SQLTables(query)
			if err != nil {
				parseErrors++
				continue
			}
			for _, table := range dependencies {
				resource := grafanaResource(
					model.ResourceTypeTable,
					table,
					instance,
					"query-table:"+datasource.ID+":"+model.StableID(table),
					now,
				)
				resource.Metadata = map[string]string{
					model.MetadataQueryDependencyKind:     "table",
					model.MetadataQueryDependencyLanguage: "sql",
					model.MetadataTableName:               table,
				}
				addResource(resources, resource)
				appendGrafanaRelationship(relationships, panelResource.ID, resource.ID, model.RelationshipUses, now)
				tables[resource.ID] = true
			}
		}
	}

	panelResource.Metadata[model.MetadataPanelLogStreamDependencyCount] = strconv.Itoa(len(logStreams))
	panelResource.Metadata[model.MetadataPanelTraceServiceDependencyCnt] = strconv.Itoa(len(traceServices))
	panelResource.Metadata[model.MetadataPanelTableDependencyCount] = strconv.Itoa(len(tables))
	panelResource.Metadata[model.MetadataPanelDependencyParseErrorCount] = strconv.Itoa(parseErrors)
	resources[panelResource.ID] = panelResource
}

func effectiveGrafanaTargetDatasource(panel grafanaPanel, target grafanaTarget, datasourceByUID map[string]model.Resource) (model.Resource, bool) {
	if strings.TrimSpace(target.Datasource.UID) != "" {
		return datasourceForRef(target.Datasource, datasourceByUID)
	}
	if strings.TrimSpace(panel.Datasource.UID) != "" {
		return datasourceForRef(panel.Datasource, datasourceByUID)
	}
	datasource, ok := datasourceByUID[grafanaDefaultDatasourceKey]
	return datasource, ok
}

func grafanaTargetQueryLanguage(panel grafanaPanel, target grafanaTarget, datasourceByUID map[string]model.Resource) string {
	if datasource, ok := effectiveGrafanaTargetDatasource(panel, target, datasourceByUID); ok {
		return queryLanguageForDatasource(datasource)
	}
	ref := target.Datasource
	if strings.TrimSpace(ref.UID) == "" {
		ref = panel.Datasource
	}
	if isGrafanaBuiltinDatasourceRef(ref) {
		return "expression"
	}
	if language := queryLanguageForDatasourceType(ref.Type); language != "" {
		return language
	}
	if strings.TrimSpace(ref.UID) != "" && !isGrafanaMixedDatasourceRef(ref) {
		return "raw"
	}
	return ""
}

func queryLanguageForDatasourceType(datasourceType string) string {
	switch strings.ToLower(strings.TrimSpace(datasourceType)) {
	case "loki":
		return "logql"
	case "tempo":
		return "traceql"
	case "elasticsearch":
		return "lucene"
	case "prometheus":
		return "promql"
	case "mysql", "postgres", "postgresql", "grafana-postgresql-datasource", "mssql",
		"grafana-bigquery-datasource", "grafana-athena-datasource", "grafana-clickhouse-datasource",
		"vertamedia-clickhouse-datasource", "clickhouse", "snowflake":
		return "sql"
	default:
		return strings.ToLower(strings.TrimSpace(datasourceType))
	}
}
