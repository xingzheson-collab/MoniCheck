package connector

import (
	"strconv"
	"strings"

	"monicheck/internal/model"
)

type grafanaDatasourceFilterDecision string

const (
	grafanaDatasourceFilterIncluded grafanaDatasourceFilterDecision = "INCLUDED"
	grafanaDatasourceFilterExcluded grafanaDatasourceFilterDecision = "EXCLUDED"
	grafanaDatasourceFilterUnknown  grafanaDatasourceFilterDecision = "UNKNOWN"
)

func grafanaDashboardDatasourceFilterDecision(dashboard grafanaDashboard, selectedUID string) grafanaDatasourceFilterDecision {
	selectedUID = strings.TrimSpace(selectedUID)
	hasConcrete := false
	hasUnknown := false
	for _, ref := range grafanaDashboardDatasourceRefs(dashboard) {
		uid := strings.TrimSpace(ref.UID)
		switch {
		case uid == "", isGrafanaMixedDatasourceRef(ref), isGrafanaBuiltinDatasourceRef(ref), isGrafanaDynamicDatasourceRef(ref):
			hasUnknown = true
		case uid == selectedUID:
			return grafanaDatasourceFilterIncluded
		default:
			hasConcrete = true
		}
	}
	if hasUnknown || !hasConcrete {
		return grafanaDatasourceFilterUnknown
	}
	return grafanaDatasourceFilterExcluded
}

func grafanaDashboardDatasourceRefs(dashboard grafanaDashboard) []grafanaRef {
	refs := make([]grafanaRef, 0)
	for _, variable := range dashboard.Templating.List {
		refs = append(refs, variable.Datasource)
	}
	for _, panel := range flattenPanels(dashboard.Panels) {
		if len(panel.Targets) == 0 {
			refs = append(refs, panel.Datasource)
			continue
		}
		for _, target := range panel.Targets {
			if strings.TrimSpace(target.Datasource.UID) != "" {
				refs = append(refs, target.Datasource)
			} else {
				refs = append(refs, panel.Datasource)
			}
		}
	}
	return refs
}

func grafanaDashboardDatasourceFilterDiagnostic(uid string, included, excluded, unknown int) model.Diagnostic {
	return model.Diagnostic{
		ID:            "grafana_dashboard_datasource_filter",
		Name:          "Grafana dashboard datasource filter",
		Status:        model.ExecutionStatusSucceeded,
		Message:       "Grafana dashboard filter excluded only dashboards explicitly attributable to other datasources; unresolved dashboards remained in scope",
		ResourceCount: included + unknown,
		Metadata: map[string]string{
			"datasource_uid": strings.TrimSpace(uid),
			"included_count": strconv.Itoa(included),
			"excluded_count": strconv.Itoa(excluded),
			"unknown_count":  strconv.Itoa(unknown),
			"unknown_policy": "retain",
		},
	}
}
