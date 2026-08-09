package connector

import (
	"strconv"
	"strings"

	"monicheck/internal/model"
)

type grafanaPanelDatasourceSummary struct {
	queryCount               int
	targetReferenceCount     int
	resolvedQueryCount       int
	unresolvedQueryCount     int
	dynamicQueryCount        int
	builtinQueryCount        int
	queryWithoutDatasource   int
	effectiveDatasourceIDs   map[string]bool
	effectiveDatasourceTypes map[string]bool
}

func addGrafanaPanelDatasourceMetadata(metadata map[string]string, panel grafanaPanel, datasourceByUID map[string]model.Resource) {
	summary := summarizeGrafanaPanelDatasources(panel, datasourceByUID)
	metadata[model.MetadataPanelQueryCount] = strconv.Itoa(summary.queryCount)
	metadata[model.MetadataPanelMixedDatasource] = strconv.FormatBool(isGrafanaMixedDatasourceRef(panel.Datasource))
	metadata[model.MetadataPanelTargetDatasourceRefCount] = strconv.Itoa(summary.targetReferenceCount)
	metadata[model.MetadataPanelResolvedDatasourceCount] = strconv.Itoa(summary.resolvedQueryCount)
	metadata[model.MetadataPanelUnresolvedDatasourceCount] = strconv.Itoa(summary.unresolvedQueryCount)
	metadata[model.MetadataPanelDynamicDatasourceCount] = strconv.Itoa(summary.dynamicQueryCount)
	metadata[model.MetadataPanelBuiltinDatasourceCount] = strconv.Itoa(summary.builtinQueryCount)
	metadata[model.MetadataPanelQueryWithoutDatasource] = strconv.Itoa(summary.queryWithoutDatasource)
	metadata[model.MetadataPanelDatasourceTypeCount] = strconv.Itoa(len(summary.effectiveDatasourceTypes))
	metadata[model.MetadataPanelEffectiveDatasourceCount] = strconv.Itoa(len(summary.effectiveDatasourceIDs))
}

func summarizeGrafanaPanelDatasources(panel grafanaPanel, datasourceByUID map[string]model.Resource) grafanaPanelDatasourceSummary {
	summary := grafanaPanelDatasourceSummary{
		effectiveDatasourceIDs:   map[string]bool{},
		effectiveDatasourceTypes: map[string]bool{},
	}
	for _, target := range panel.Targets {
		if strings.TrimSpace(target.Expression) == "" {
			continue
		}
		summary.queryCount++

		ref := target.Datasource
		if strings.TrimSpace(ref.UID) != "" {
			summary.targetReferenceCount++
		} else {
			ref = panel.Datasource
		}

		switch {
		case strings.TrimSpace(ref.UID) == "", isGrafanaMixedDatasourceRef(ref):
			summary.queryWithoutDatasource++
		case isGrafanaBuiltinDatasourceRef(ref):
			summary.builtinQueryCount++
		case isGrafanaDynamicDatasourceRef(ref):
			summary.dynamicQueryCount++
		default:
			datasource, ok := datasourceForRef(ref, datasourceByUID)
			if !ok {
				summary.unresolvedQueryCount++
				continue
			}
			summary.resolvedQueryCount++
			summary.effectiveDatasourceIDs[datasource.ID] = true
			if datasourceType := strings.ToLower(strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceType])); datasourceType != "" {
				summary.effectiveDatasourceTypes[datasourceType] = true
			}
		}
	}
	return summary
}

func isGrafanaMixedDatasourceRef(ref grafanaRef) bool {
	return strings.EqualFold(strings.TrimSpace(ref.UID), "-- Mixed --")
}

func isGrafanaBuiltinDatasourceRef(ref grafanaRef) bool {
	uid := strings.ToLower(strings.TrimSpace(ref.UID))
	refType := strings.ToLower(strings.TrimSpace(ref.Type))
	return uid == "__expr__" || uid == "-- grafana --" || refType == "__expr__"
}

func isGrafanaDynamicDatasourceRef(ref grafanaRef) bool {
	uid := strings.TrimSpace(ref.UID)
	return strings.Contains(uid, "$")
}
