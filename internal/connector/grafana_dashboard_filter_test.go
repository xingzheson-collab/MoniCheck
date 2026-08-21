package connector

import "testing"

func TestGrafanaDashboardDatasourceFilterIsConservative(t *testing.T) {
	tests := []struct {
		name      string
		dashboard grafanaDashboard
		want      grafanaDatasourceFilterDecision
	}{
		{
			name: "selected concrete datasource",
			dashboard: grafanaDashboard{Panels: []grafanaPanel{{
				Datasource: grafanaRef{UID: "prom-main"},
				Targets:    []grafanaTarget{{Expression: "up"}},
			}}},
			want: grafanaDatasourceFilterIncluded,
		},
		{
			name: "foreign concrete datasource",
			dashboard: grafanaDashboard{Panels: []grafanaPanel{{
				Datasource: grafanaRef{UID: "prom-other"},
				Targets:    []grafanaTarget{{Expression: "up"}},
			}}},
			want: grafanaDatasourceFilterExcluded,
		},
		{
			name: "dynamic datasource retained",
			dashboard: grafanaDashboard{Panels: []grafanaPanel{{
				Datasource: grafanaRef{UID: "${DS_PROMETHEUS}", Type: "prometheus"},
				Targets:    []grafanaTarget{{Expression: "up"}},
			}}},
			want: grafanaDatasourceFilterUnknown,
		},
		{
			name: "mixed concrete and unresolved retained",
			dashboard: grafanaDashboard{Panels: []grafanaPanel{
				{Datasource: grafanaRef{UID: "prom-other"}, Targets: []grafanaTarget{{Expression: "up"}}},
				{Datasource: grafanaRef{UID: "${DS_PROMETHEUS}"}, Targets: []grafanaTarget{{Expression: "up"}}},
			}},
			want: grafanaDatasourceFilterUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := grafanaDashboardDatasourceFilterDecision(test.dashboard, "prom-main"); got != test.want {
				t.Fatalf("decision = %s, want %s", got, test.want)
			}
		})
	}
}

func TestGrafanaDashboardDatasourceFilterDiagnosticDisclosesUnknownPolicy(t *testing.T) {
	diagnostic := grafanaDashboardDatasourceFilterDiagnostic("prom-main", 2, 3, 4)
	if diagnostic.ResourceCount != 6 ||
		diagnostic.Metadata["included_count"] != "2" ||
		diagnostic.Metadata["excluded_count"] != "3" ||
		diagnostic.Metadata["unknown_count"] != "4" ||
		diagnostic.Metadata["unknown_policy"] != "retain" {
		t.Fatalf("unexpected diagnostic: %#v", diagnostic)
	}
}
