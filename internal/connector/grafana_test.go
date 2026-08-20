package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestGrafanaConnectorSync(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[{"id":1,"uid":"prom","name":"Prometheus","type":"prometheus","url":"http://prometheus:9090","access":"proxy","isDefault":true,"readOnly":true,"basicAuth":true,"created":"2023-01-02T03:04:05Z","updated":"2024-03-04T05:06:07Z"}]`))
		case "/api/search":
			if r.URL.Query().Get("type") != "dash-db" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`[{"uid":"api","title":"API Overview","folderUid":"search-folder","folderTitle":"Search Folder"}]`))
		case "/api/dashboards/uid/api":
			_, _ = w.Write([]byte(`{"meta":{"slug":"api-overview","url":"/d/api/api-overview","folderUid":"service-folder","folderTitle":"Service Dashboards","created":"2024-01-02T03:04:05Z","updated":"2024-02-03T04:05:06Z"},"dashboard":{"title":"API Overview","version":12,"schemaVersion":39,"tags":["api","prod","api"],"timezone":"browser","refresh":"30s","editable":true,"time":{"from":"now-7d","to":"now"},"annotations":{"list":[{"name":"deploys"},{"name":"incidents"}]},"templating":{"list":[{"name":"instance","type":"query","datasource":"prom","query":"label_values(node_cpu_seconds_total, instance)"}]},"panels":[{"id":1,"title":"Request Rate","type":"timeseries","gridPos":{"x":1,"y":2,"w":12,"h":8},"fieldConfig":{"defaults":{"unit":"reqps","thresholds":{"steps":[{"color":"green"},{"color":"red","value":100}]}}},"options":{"legend":{"displayMode":"table"}},"datasource":"prom","targets":[{"query":"sum(rate(http_requests_total[5m]))"}]}]}}`))
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case "/api/health":
			_, _ = w.Write([]byte(`{"database":"ok","version":"12.1.0","commit":"secret-grafana-commit"}`))
		case "/api/datasources/uid/prom/health":
			_, _ = w.Write([]byte(`{"status":"ERROR","message":"secret-health-message","details":{"secret":"secret-health-detail"}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	if err := connector.ConfigurePrometheusDatasource("https://prometheus-public.test", "prom"); err != nil {
		t.Fatalf("configure Prometheus datasource binding: %v", err)
	}

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if snapshot.Partial {
		t.Fatal("expected successful empty optional endpoints to produce a complete snapshot")
	}
	if len(snapshot.Diagnostics) != 11 {
		t.Fatalf("expected dashboard-search, dashboard-detail, datasource-link, datasource-health, and seven optional diagnostics, got %#v", snapshot.Diagnostics)
	}
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.Status != model.ExecutionStatusSucceeded {
			t.Fatalf("expected successful optional discovery diagnostic, got %#v", diagnostic)
		}
	}

	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeDashboard, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeFolder, 1)
	assertResourceCount(t, snapshot, model.ResourceTypePanel, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 0)
	if len(snapshot.References) != 2 {
		t.Fatalf("expected 2 canonical Prometheus Metric references, got %#v", snapshot.References)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	assertRelationship(t, snapshot, model.RelationshipBelongsTo, model.ResourceTypePanel, model.ResourceTypeDashboard)
	assertRelationship(t, snapshot, model.RelationshipBelongsTo, model.ResourceTypeDashboard, model.ResourceTypeFolder)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeDatasource)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeMetric)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeDashboard, model.ResourceTypeDatasource)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeDashboard, model.ResourceTypeMetric)
	assertMetricInstance(t, snapshot, "https://prometheus-public.test")
	assertMetric(t, snapshot, "node_cpu_seconds_total")
	assertDashboardMetadata(t, snapshot, "api", "service-folder", "Service Dashboards", "api-overview")
	assertFolderMetadata(t, snapshot, "service-folder", "Service Dashboards")
	assertPanelTitle(t, snapshot, "1", "Request Rate")
	assertPanelVisualizationType(t, snapshot, "1", "timeseries")
	assertPanelGrid(t, snapshot, "1", "1", "2", "12", "8")
	assertPanelDisplayMetadata(t, snapshot, "1", "reqps", "2", "table")
	assertDatasourceMetadata(t, snapshot, "prom", "proxy", "true", "true", "true", "2023-01-02T03:04:05Z", "2024-03-04T05:06:07Z")
	assertDatasourceHealth(t, snapshot, "prom", "error", "true")
	foundRuntime := false
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeInstance && resource.Metadata[model.MetadataGrafanaRuntime] == "true" {
			foundRuntime = resource.Name == "Grafana Runtime" &&
				resource.Metadata[model.MetadataGrafanaDatabaseStatus] == "ok" &&
				resource.Metadata[model.MetadataGrafanaVersion] == "12.1.0"
		}
	}
	if !foundRuntime {
		t.Fatalf("expected Grafana runtime health resource, got %#v", snapshot.Resources)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(encoded), "secret-grafana-commit") ||
		strings.Contains(string(encoded), "secret-health-message") ||
		strings.Contains(string(encoded), "secret-health-detail") ||
		strings.Contains(string(encoded), "http://prometheus:9090") ||
		strings.Contains(string(encoded), "/d/api/api-overview") {
		t.Fatalf("Grafana secrets and discovered URLs must not be persisted: %s", encoded)
	}
}

func TestGrafanaDefaultDatasourceAndUnlinkedPrometheusAreVisible(t *testing.T) {
	defaultDatasource := model.Resource{
		ID:   "default",
		Type: model.ResourceTypeDatasource,
		Metadata: map[string]string{
			model.MetadataDatasourceType: "prometheus",
			model.MetadataDatasourceURL:  "http://prometheus.monitoring.svc:9090",
		},
	}
	resolved, ok := datasourceForRef(grafanaRef{}, map[string]model.Resource{grafanaDefaultDatasourceKey: defaultDatasource})
	if !ok || !isPrometheusDatasource(resolved) {
		t.Fatalf("empty panel datasource did not resolve to Grafana default: %#v", resolved)
	}
	panelDatasource := model.Resource{ID: "panel"}
	targetDatasource := model.Resource{ID: "target"}
	datasources := map[string]model.Resource{
		grafanaDefaultDatasourceKey: defaultDatasource,
		"panel":                     panelDatasource,
		"target":                    targetDatasource,
	}
	if got, ok := effectiveGrafanaTargetDatasource(grafanaPanel{Datasource: grafanaRef{UID: "panel"}}, grafanaTarget{Datasource: grafanaRef{UID: "target"}}, datasources); !ok || got.ID != "target" {
		t.Fatalf("target datasource did not take precedence: %#v", got)
	}
	if got, ok := effectiveGrafanaTargetDatasource(grafanaPanel{Datasource: grafanaRef{UID: "panel"}}, grafanaTarget{}, datasources); !ok || got.ID != "panel" {
		t.Fatalf("panel datasource did not take precedence over default: %#v", got)
	}
	if got, ok := effectiveGrafanaTargetDatasource(grafanaPanel{}, grafanaTarget{}, datasources); !ok || got.ID != "default" {
		t.Fatalf("empty target and panel did not use default datasource: %#v", got)
	}

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if err := connector.ConfigurePrometheusDatasource("https://prometheus-public.test", ""); err != nil {
		t.Fatalf("configure Prometheus source: %v", err)
	}
	diagnostic := connector.prometheusDatasourceLinkDiagnostic([]grafanaDatasource{{UID: "prom", Type: "prometheus", URL: "http://prometheus.monitoring.svc:9090"}})
	if diagnostic.Status != model.ExecutionStatusWarning || diagnostic.Metadata["matched_count"] != "0" || !strings.Contains(diagnostic.Message, "--prometheus-datasource-uid") {
		t.Fatalf("expected fail-visible unmatched datasource diagnostic, got %#v", diagnostic)
	}
}

func TestGrafanaConnectorUsesBasicAuthForPrivateIngress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "grafana-reader" || password != "grafana-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources", "/api/search", "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case "/api/health":
			_, _ = w.Write([]byte(`{"database":"ok","version":"12.1.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewGrafanaConnectorWithOptions(server.URL, HTTPOptions{Username: "grafana-reader", Password: "grafana-password"})
	if err != nil {
		t.Fatalf("new Basic Auth connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync through Basic Auth ingress: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("expected complete Basic Auth sync, diagnostics=%#v", snapshot.Diagnostics)
	}
}

func TestGrafanaConnectorUsesAPIKeyAsBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer grafana-api-key" {
			t.Errorf("Authorization = %q", got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("X-API-Key"); got != "" {
			t.Errorf("Grafana request must not use X-API-Key, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	connector, err := NewGrafanaConnectorWithOptions(server.URL, HTTPOptions{APIKey: "grafana-api-key"})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	response, err := connector.client.Get(server.URL)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestSanitizeGrafanaResourceURLs(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	rawURL := "https://reader:secret@metrics.example.com/api?token=sensitive"
	datasource := grafanaResource(model.ResourceTypeDatasource, "Metrics", "https://grafana.example", "datasource:metrics", now)
	datasource.Metadata = map[string]string{
		model.MetadataDatasourceURL: rawURL,
	}
	dashboard := grafanaResource(model.ResourceTypeDashboard, "Overview", "https://grafana.example", "dashboard:overview", now)
	dashboard.Metadata = map[string]string{
		model.MetadataDashboardURL: "/d/private/overview?orgId=42",
	}
	metric := prometheusResource(model.ResourceTypeMetric, "requests_total", rawURL, "metric:requests_total", now)
	metricID := metric.ID
	resources := map[string]model.Resource{
		datasource.ID: datasource,
		dashboard.ID:  dashboard,
		metric.ID:     metric,
	}

	sanitizeGrafanaResourceURLs(resources)

	sanitizedDatasource := resources[datasource.ID]
	if sanitizedDatasource.Metadata[model.MetadataDatasourceURLConfigured] != "true" ||
		sanitizedDatasource.Metadata[model.MetadataDatasourceURLValid] != "true" ||
		sanitizedDatasource.Metadata[model.MetadataDatasourceURLScheme] != "https" ||
		sanitizedDatasource.Metadata[model.MetadataDatasourceURLHostScope] != "public" ||
		sanitizedDatasource.Metadata[model.MetadataDatasourceURLHostFingerprint] != model.StableID("datasource-host", "metrics.example.com") {
		t.Fatalf("unexpected datasource endpoint metadata: %#v", sanitizedDatasource.Metadata)
	}
	if resources[metricID].ID != metricID ||
		resources[metricID].Source.Instance != model.StableID("datasource-endpoint", rawURL) {
		t.Fatalf("metric identity must remain stable while its source instance is redacted: %#v", resources[metricID])
	}
	encoded, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal sanitized resources: %v", err)
	}
	for _, secret := range []string{rawURL, "reader", "secret", "token", "sensitive", "/d/private/overview", "orgId"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("sanitized resources contain %q: %s", secret, encoded)
		}
	}
}

func TestGrafanaConnectorContinuesWhenOptionalAlertingEndpointsAreUnavailable(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources", "/api/search":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/contact-points":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync with unavailable optional alerting endpoints: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected unavailable optional alerting endpoints to mark snapshot partial")
	}
	if len(snapshot.Diagnostics) != 10 {
		t.Fatalf("expected dashboard-search, dashboard-detail, datasource-health, and seven optional diagnostics, got %#v", snapshot.Diagnostics)
	}
	foundEndpointError := false
	foundDashboardSearchSuccess := false
	foundDashboardDetailSuccess := false
	foundDatasourceHealthSuccess := false
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID == "grafana_dashboard_search" {
			if diagnostic.Status != model.ExecutionStatusSucceeded || diagnostic.Metadata["unique_item_count"] != "0" {
				t.Fatalf("expected empty dashboard-search discovery success, got %#v", diagnostic)
			}
			foundDashboardSearchSuccess = true
			continue
		}
		if diagnostic.ID == "grafana_dashboard_details" {
			if diagnostic.Status != model.ExecutionStatusSucceeded || diagnostic.Metadata["item_count"] != "0" {
				t.Fatalf("expected empty dashboard-detail discovery success, got %#v", diagnostic)
			}
			foundDashboardDetailSuccess = true
			continue
		}
		if diagnostic.ID == "grafana_datasource_health" {
			if diagnostic.Status != model.ExecutionStatusSucceeded ||
				diagnostic.Metadata["item_count"] != "0" ||
				diagnostic.Metadata["worker_count"] != "0" {
				t.Fatalf("expected empty datasource-health discovery success, got %#v", diagnostic)
			}
			foundDatasourceHealthSuccess = true
			continue
		}
		if diagnostic.Status != model.ExecutionStatusWarning || diagnostic.Metadata["available"] != "false" {
			t.Fatalf("expected unavailable optional discovery warning, got %#v", diagnostic)
		}
		if diagnostic.ID == "grafana_contact_points" && diagnostic.Metadata["error"] != "" {
			foundEndpointError = true
		}
	}
	if !foundEndpointError {
		t.Fatal("expected failed contact-point endpoint diagnostic to preserve error context")
	}
	if !foundDashboardSearchSuccess {
		t.Fatal("expected dashboard-search discovery diagnostic")
	}
	if !foundDashboardDetailSuccess {
		t.Fatal("expected dashboard-detail discovery diagnostic")
	}
	if !foundDatasourceHealthSuccess {
		t.Fatal("expected datasource-health discovery diagnostic")
	}
}

func TestGrafanaConnectorPaginatesDashboardSearch(t *testing.T) {
	requestedPages := make([]string, 0, 4)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[]`))
		case "/api/search":
			if r.URL.Query().Get("type") != "dash-db" || r.URL.Query().Get("limit") != "2" {
				t.Fatalf("unexpected dashboard search query: %s", r.URL.RawQuery)
			}
			page := r.URL.Query().Get("page")
			requestedPages = append(requestedPages, page)
			switch page {
			case "1":
				_, _ = w.Write([]byte(`[{"uid":"a"},{"uid":"b"}]`))
			case "2":
				_, _ = w.Write([]byte(`[{"uid":"b"},{"uid":"c"}]`))
			case "3":
				_, _ = w.Write([]byte(`[{"uid":"d"},{"uid":"e"}]`))
			case "4":
				_, _ = w.Write([]byte(`[{"uid":"f"}]`))
			default:
				t.Fatalf("unexpected dashboard search page %q", page)
			}
		case "/api/dashboards/uid/a", "/api/dashboards/uid/b", "/api/dashboards/uid/c", "/api/dashboards/uid/d", "/api/dashboards/uid/e":
			uid := strings.TrimPrefix(r.URL.Path, "/api/dashboards/uid/")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"dashboard":{"uid":%q,"title":%q}}`, uid, uid)))
		case "/api/dashboards/uid/f":
			t.Fatal("dashboard beyond the discovery limit must not be fetched")
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.dashboardSearchPageSize = 2
	connector.dashboardSearchLimit = 5
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync paginated dashboard search: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected capped dashboard discovery to mark snapshot partial")
	}
	if strings.Join(requestedPages, ",") != "1,2,3,4" {
		t.Fatalf("unexpected requested pages: %#v", requestedPages)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeDashboard, 5)
	diagnostic := findGrafanaDiagnostic(t, snapshot.Diagnostics, "grafana_dashboard_search")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["page_count"] != "4" ||
		diagnostic.Metadata["raw_item_count"] != "7" ||
		diagnostic.Metadata["unique_item_count"] != "5" ||
		diagnostic.Metadata["duplicate_item_count"] != "1" ||
		diagnostic.Metadata["invalid_item_count"] != "0" ||
		diagnostic.Metadata["truncated"] != "true" ||
		diagnostic.Metadata["pagination_stalled"] != "false" {
		t.Fatalf("unexpected dashboard-search diagnostic: %#v", diagnostic)
	}
}

func TestGrafanaConnectorStopsStalledDashboardPagination(t *testing.T) {
	searchRequests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[]`))
		case "/api/search":
			searchRequests++
			_, _ = w.Write([]byte(`[{"uid":"a"},{"uid":"b"}]`))
		case "/api/dashboards/uid/a", "/api/dashboards/uid/b":
			uid := strings.TrimPrefix(r.URL.Path, "/api/dashboards/uid/")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"dashboard":{"uid":%q,"title":%q}}`, uid, uid)))
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.dashboardSearchPageSize = 2
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync stalled dashboard search: %v", err)
	}
	if searchRequests != 2 || !snapshot.Partial {
		t.Fatalf("expected two search requests and a partial snapshot, got requests=%d partial=%t", searchRequests, snapshot.Partial)
	}
	diagnostic := findGrafanaDiagnostic(t, snapshot.Diagnostics, "grafana_dashboard_search")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["page_count"] != "2" ||
		diagnostic.Metadata["duplicate_item_count"] != "2" ||
		diagnostic.Metadata["pagination_stalled"] != "true" {
		t.Fatalf("unexpected stalled dashboard-search diagnostic: %#v", diagnostic)
	}
}

func TestGrafanaConnectorUsesAppDashboardAPIFallback(t *testing.T) {
	appSearchRequests := 0
	legacyDetailRequests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[{"uid":"prom","name":"Prometheus","type":"prometheus","url":"http://prometheus:9090"}]`))
		case "/api/search":
			http.NotFound(w, r)
		case "/apis/dashboard.grafana.app/v1/namespaces/org-2/dashboards":
			appSearchRequests++
			if r.URL.Query().Get("limit") != "2" {
				t.Fatalf("unexpected App dashboard limit: %s", r.URL.RawQuery)
			}
			switch r.URL.Query().Get("continue") {
			case "":
				_, _ = w.Write([]byte(`{
					"metadata":{"continue":"next page"},
					"items":[{
						"metadata":{
							"name":"api",
							"namespace":"org-2",
							"creationTimestamp":"2026-07-01T01:02:03Z",
							"annotations":{
								"grafana.app/folder":"operations",
								"grafana.app/updatedTimestamp":"2026-07-02T02:03:04Z"
							}
						},
						"spec":{
							"uid":"ignored-spec-uid",
							"title":"API Overview",
							"version":3,
							"panels":[{
								"id":1,
								"title":"Request Rate",
								"type":"timeseries",
								"datasource":{"uid":"prom","type":"prometheus"},
								"targets":[{"expr":"rate(http_requests_total[5m])"}]
							}]
						}
					}]
				}`))
			case "next page":
				_, _ = w.Write([]byte(`{
					"metadata":{},
					"items":[{
						"metadata":{"name":"workers","namespace":"org-2","annotations":{}},
						"spec":{
							"title":"Worker Overview",
							"panels":[{"id":2,"title":"Workers","type":"stat"}]
						}
					}]
				}`))
			default:
				t.Fatalf("unexpected App dashboard continue token: %s", r.URL.RawQuery)
			}
		case "/api/dashboards/uid/api", "/api/dashboards/uid/workers":
			legacyDetailRequests++
			http.NotFound(w, r)
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/org-2/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case "/api/health":
			_, _ = w.Write([]byte(`{"database":"ok","version":"12.0.0"}`))
		case "/api/datasources/uid/prom/health":
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnectorWithNamespace("http://grafana.test", "org-2", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.dashboardSearchPageSize = 2
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync App dashboard fallback: %v", err)
	}
	if snapshot.Partial {
		t.Fatal("expected complete App dashboard discovery")
	}
	if appSearchRequests != 2 || legacyDetailRequests != 0 {
		t.Fatalf("expected two App list requests and no legacy detail requests, got app=%d legacy_detail=%d", appSearchRequests, legacyDetailRequests)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeDashboard, 2)
	assertResourceCount(t, snapshot, model.ResourceTypePanel, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeFolder, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeMetric)

	diagnostic := findGrafanaDiagnostic(t, snapshot.Diagnostics, "grafana_dashboard_search")
	if diagnostic.Status != model.ExecutionStatusSucceeded ||
		diagnostic.Metadata["api"] != "app" ||
		diagnostic.Metadata["fallback"] != "true" ||
		diagnostic.Metadata["page_count"] != "2" ||
		diagnostic.Metadata["unique_item_count"] != "2" {
		t.Fatalf("unexpected App dashboard-search diagnostic: %#v", diagnostic)
	}

	foundAPI := false
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeDashboard || resource.Metadata[model.MetadataDashboardUID] != "api" {
			continue
		}
		foundAPI = resource.Name == "API Overview" &&
			resource.Metadata[model.MetadataFolderUID] == "operations" &&
			resource.Metadata[model.MetadataDashboardVersion] == "3" &&
			resource.Metadata["created_at"] == "2026-07-01T01:02:03Z" &&
			resource.Metadata[model.MetadataUpdatedAt] == "2026-07-02T02:03:04Z"
	}
	if !foundAPI {
		t.Fatal("expected App dashboard metadata and spec to be mapped")
	}
}

func TestGrafanaConnectorDoesNotHideLegacyDashboardSearchFailure(t *testing.T) {
	appRequested := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/datasources":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/api/search":
			http.Error(w, "failed", http.StatusInternalServerError)
		case "/apis/dashboard.grafana.app/v1/namespaces/default/dashboards":
			appRequested = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatal("expected legacy dashboard search failure to fail core sync")
	}
	if appRequested {
		t.Fatal("unexpected App dashboard fallback after a legacy server error")
	}
}

func TestGrafanaConnectorFetchesDashboardDetailsWithBoundedConcurrency(t *testing.T) {
	var mu sync.Mutex
	currentRequests := 0
	maxConcurrentRequests := 0
	requestCounts := map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := strings.TrimPrefix(r.URL.Path, "/api/dashboards/uid/")
		mu.Lock()
		currentRequests++
		requestCounts[uid]++
		if currentRequests > maxConcurrentRequests {
			maxConcurrentRequests = currentRequests
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		currentRequests--
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"dashboard":{"title":%q}}`, uid)))
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.dashboardDetailWorkers = 2
	connector.client = testHTTPClient(handler)
	items := []grafanaDashboardSearchItem{
		{UID: "a"},
		{UID: "b"},
		{UID: "inline"},
		{UID: "c"},
	}
	inline := map[string]grafanaDashboardResponse{
		"inline": {Dashboard: grafanaDashboard{Title: "Inline"}},
	}

	results := connector.dashboardDetails(context.Background(), items, inline)
	if len(results) != len(items) {
		t.Fatalf("unexpected detail result count: %d", len(results))
	}
	for index, expected := range []string{"a", "b", "Inline", "c"} {
		if results[index].Err != nil || results[index].Detail.Dashboard.Title != expected {
			t.Fatalf("unexpected detail result at %d: %#v", index, results[index])
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if maxConcurrentRequests != 2 {
		t.Fatalf("expected detail concurrency of 2, got %d", maxConcurrentRequests)
	}
	if requestCounts["inline"] != 0 || requestCounts["a"] != 1 || requestCounts["b"] != 1 || requestCounts["c"] != 1 {
		t.Fatalf("unexpected dashboard detail requests: %#v", requestCounts)
	}
}

func TestGrafanaConnectorIsolatesDatasourceHealthFailures(t *testing.T) {
	var mu sync.Mutex
	currentRequests := 0
	maxConcurrentRequests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[
				{"uid":"healthy","name":"Healthy","type":"prometheus","url":"https://healthy.example","access":"proxy","readOnly":true},
				{"uid":"failed","name":"Failed","type":"loki","url":"https://failed.example","access":"proxy","readOnly":true},
				{"uid":"empty","name":"Empty","type":"tempo","url":"https://empty.example","access":"proxy","readOnly":true}
			]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case "/api/health":
			_, _ = w.Write([]byte(`{"database":"ok","version":"13.0.0"}`))
		case "/api/datasources/uid/healthy/health", "/api/datasources/uid/failed/health", "/api/datasources/uid/empty/health":
			mu.Lock()
			currentRequests++
			if currentRequests > maxConcurrentRequests {
				maxConcurrentRequests = currentRequests
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			currentRequests--
			mu.Unlock()
			switch r.URL.Path {
			case "/api/datasources/uid/healthy/health":
				_, _ = w.Write([]byte(`{"status":"OK","message":"not-persisted"}`))
			case "/api/datasources/uid/failed/health":
				http.Error(w, "secret-upstream-health-error", http.StatusInternalServerError)
			default:
				_, _ = w.Write([]byte(`{"message":"secret-empty-health-message","details":{"token":"secret"}}`))
			}
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.datasourceHealthWorkers = 2
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync with isolated datasource-health failures: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected datasource-health failures to mark the snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 3)
	assertDatasourceHealth(t, snapshot, "healthy", "ok", "true")
	assertDatasourceHealth(t, snapshot, "failed", "", "false")
	assertDatasourceHealth(t, snapshot, "empty", "", "false")

	diagnostic := findGrafanaDiagnostic(t, snapshot.Diagnostics, "grafana_datasource_health")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["item_count"] != "3" ||
		diagnostic.Metadata["succeeded_count"] != "1" ||
		diagnostic.Metadata["failed_count"] != "2" ||
		diagnostic.Metadata["worker_count"] != "2" {
		t.Fatalf("unexpected datasource-health diagnostic: %#v", diagnostic)
	}
	mu.Lock()
	if maxConcurrentRequests != 2 {
		t.Fatalf("expected datasource-health concurrency of 2, got %d", maxConcurrentRequests)
	}
	mu.Unlock()

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, secret := range []string{"not-persisted", "secret-upstream-health-error", "secret-empty-health-message"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("datasource-health response details must not be persisted: %s", encoded)
		}
	}
}

func findGrafanaDiagnostic(t *testing.T, diagnostics []model.Diagnostic, id string) model.Diagnostic {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.ID == id {
			return diagnostic
		}
	}
	t.Fatalf("missing diagnostic %q", id)
	return model.Diagnostic{}
}

func TestGrafanaConnectorIsolatesDashboardDetailFailures(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[
				{"uid":"healthy","title":"Healthy Dashboard","folderUid":"ops","folderTitle":"Operations"},
				{"uid":"broken","title":"Broken Dashboard","folderUid":"ops","folderTitle":"Operations"}
			]`))
		case "/api/dashboards/uid/healthy":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Healthy Dashboard","panels":[{"id":1,"title":"Text","type":"text"}]}}`))
		case "/api/dashboards/uid/broken":
			http.Error(w, "internal detail", http.StatusInternalServerError)
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("expected per-dashboard failure isolation, got %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected a dashboard-detail failure to mark the snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeDashboard, 2)
	assertResourceCount(t, snapshot, model.ResourceTypePanel, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeFolder, 1)
	assertRelationship(t, snapshot, model.RelationshipBelongsTo, model.ResourceTypeDashboard, model.ResourceTypeFolder)

	foundBroken := false
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeDashboard || resource.Metadata[model.MetadataDashboardUID] != "broken" {
			continue
		}
		foundBroken = true
		if resource.Status != model.ResourceStatusBroken ||
			resource.Metadata[model.MetadataDashboardDetailAvailable] != "false" ||
			resource.Metadata[model.MetadataHealth] != "detail_unavailable" ||
			resource.Metadata[model.MetadataFolderUID] != "ops" {
			t.Fatalf("unexpected broken dashboard placeholder: %#v", resource)
		}
		if strings.Contains(fmt.Sprint(resource.Metadata), "internal detail") {
			t.Fatalf("dashboard error response must not be persisted: %#v", resource.Metadata)
		}
	}
	if !foundBroken {
		t.Fatal("expected broken dashboard placeholder")
	}
	foundDiagnostic := false
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID != "grafana_dashboard_details" {
			continue
		}
		foundDiagnostic = true
		if diagnostic.Status != model.ExecutionStatusWarning ||
			diagnostic.Metadata["item_count"] != "2" ||
			diagnostic.Metadata["succeeded_count"] != "1" ||
			diagnostic.Metadata["failed_count"] != "1" {
			t.Fatalf("unexpected dashboard detail diagnostic: %#v", diagnostic)
		}
	}
	if !foundDiagnostic {
		t.Fatal("expected aggregate dashboard detail diagnostic")
	}
}

func TestGrafanaNotificationTimingStatsAndAppMapping(t *testing.T) {
	tree := grafanaAppRoutingTree{Spec: grafanaAppRoutingTreeSpec{
		Defaults: grafanaAppRoutingDefaults{Receiver: "default", GroupIntervalCamel: "5m", RepeatIntervalCamel: "9m", GroupBy: []string{"alertname"}},
		Routes:   []grafanaAppRoutingRoute{{Receiver: "pager", RepeatInterval: "2m", GroupBy: []string{"..."}}},
	}}
	policy := tree.notificationRoute()
	if policy.GroupInterval != "5m" || policy.RepeatInterval != "9m" || len(policy.GroupBy) != 1 || len(policy.Routes) != 1 || policy.Routes[0].RepeatInterval != "2m" || len(policy.Routes[0].GroupBy) != 1 {
		t.Fatalf("unexpected App Platform timing mapping: %#v", policy)
	}
	stats := grafanaRoutingPolicyStats(policy)
	if stats.invalidTimingCount != 1 || stats.roundedRepeatCount != 1 || stats.ungroupedRouteCount != 1 {
		t.Fatalf("unexpected Grafana timing stats: %#v", stats)
	}
}

func TestGrafanaConnectorUsesTargetDatasource(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[
				{"id":1,"uid":"prom-a","name":"Prometheus A","type":"prometheus","url":"http://prom-a:9090"},
				{"id":2,"uid":"prom-b","name":"Prometheus B","type":"prometheus","url":"http://prom-b:9090"}
			]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"mixed","title":"Mixed Dashboard"}]`))
		case "/api/dashboards/uid/mixed":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Mixed Dashboard","panels":[{"id":1,"title":"Target Datasource","type":"timeseries","datasource":{"uid":"-- Mixed --"},"targets":[{"expr":"rate(target_metric_total[5m])","datasource":{"uid":"prom-b"}}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeDatasource)
	assertMetricInstanceForName(t, snapshot, "target_metric_total", model.StableID("datasource-endpoint", "http://prom-b:9090"))
}

func TestGrafanaConnectorSummarizesMixedDatasourceResolution(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[
				{"id":1,"uid":"prom","name":"Prometheus Main","type":"prometheus","url":"http://prometheus:9090"},
				{"id":2,"uid":"loki","name":"Loki Logs","type":"loki","url":"http://loki:3100"}
			]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"mixed-resolution","title":"Mixed Resolution"}]`))
		case "/api/dashboards/uid/mixed-resolution":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Mixed Resolution","panels":[{
				"id":7,
				"title":"Mixed Targets",
				"type":"timeseries",
				"datasource":{"uid":"-- Mixed --"},
				"targets":[
					{"expr":"rate(http_requests_total[5m])","datasource":{"uid":"prom"}},
					{"expr":"{app=\"api\"} |= \"error\"","datasource":"Loki Logs"},
					{"expr":"up","datasource":{"uid":"deleted-prom","type":"prometheus"}},
					{"expr":"sum(rate(worker_jobs_total[5m]))"},
					{"expr":"up","datasource":{"uid":"${DS_PROMETHEUS}","type":"prometheus"}},
					{"expression":"$A > 0","datasource":{"uid":"__expr__","type":"__expr__"}}
				]
			}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertPanelDatasourceMetadata(t, snapshot, "7", map[string]string{
		model.MetadataPanelQueryCount:                "6",
		model.MetadataPanelMixedDatasource:           "true",
		model.MetadataPanelTargetDatasourceRefCount:  "5",
		model.MetadataPanelResolvedDatasourceCount:   "2",
		model.MetadataPanelUnresolvedDatasourceCount: "1",
		model.MetadataPanelDynamicDatasourceCount:    "1",
		model.MetadataPanelBuiltinDatasourceCount:    "1",
		model.MetadataPanelQueryWithoutDatasource:    "1",
		model.MetadataPanelDatasourceTypeCount:       "2",
		model.MetadataPanelEffectiveDatasourceCount:  "2",
	})
}

func TestGrafanaConnectorSkipsNonPrometheusQueryMetrics(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[
				{"id":1,"uid":"prom","name":"Prometheus","type":"prometheus","url":"http://prometheus:9090"},
				{"id":2,"uid":"loki","name":"Loki","type":"loki","url":"http://loki:3100"}
			]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"logs","title":"Logs Dashboard"}]`))
		case "/api/dashboards/uid/logs":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Logs Dashboard","templating":{"list":[{"name":"service","type":"query","datasource":"loki","query":"label_values({app=\"api\"}, service)"}]},"panels":[{"id":1,"title":"Request Rate","type":"timeseries","datasource":"prom","targets":[{"expr":"rate(http_requests_total[5m])"}]},{"id":2,"title":"Errors","type":"logs","datasource":"loki","targets":[{"expr":"sum by (level) (count_over_time({app=\"api\"} |= \"error\" [5m]))"}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertMetric(t, snapshot, "http_requests_total")
	assertNoMetric(t, snapshot, "app")
	assertNoMetric(t, snapshot, "level")
	assertNoMetric(t, snapshot, "error")
	assertPanelPromQL(t, snapshot, "1", "rate(http_requests_total[5m])")
	assertPanelNoPromQL(t, snapshot, "2")
	assertPanelQuery(t, snapshot, "2", `sum by (level) (count_over_time({app="api"} |= "error" [5m]))`, "logql")
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeDatasource)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeLogStream)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeDashboard, model.ResourceTypeDatasource)
	assertResourceCount(t, snapshot, model.ResourceTypeLogStream, 1)
	assertPanelDependencyMetadata(t, snapshot, "2", "1", "0", "0", "0")
	assertLogStreamDependencyIsRedacted(t, snapshot)
}

func TestGrafanaConnectorPreservesTempoTraceQL(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[{"id":1,"uid":"tempo","name":"Tempo","type":"tempo","url":"http://tempo:3200"}]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"traces","title":"Trace Dashboard"}]`))
		case "/api/dashboards/uid/traces":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Trace Dashboard","panels":[{"id":1,"title":"Checkout Traces","type":"traces","datasource":"tempo","targets":[{"query":"{ resource.service.name = \"checkout\" }"}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 0)
	assertPanelNoPromQL(t, snapshot, "1")
	assertPanelQuery(t, snapshot, "1", `{ resource.service.name = "checkout" }`, "traceql")
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeDatasource)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeTraceService)
	assertResourceCount(t, snapshot, model.ResourceTypeTraceService, 1)
	assertPanelDependencyMetadata(t, snapshot, "1", "0", "1", "0", "0")
}

func TestGrafanaConnectorBuildsSQLTableDependencies(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[{"id":1,"uid":"warehouse","name":"Warehouse","type":"postgres","url":"postgres.example.internal"}]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"orders","title":"Orders Dashboard"}]`))
		case "/api/dashboards/uid/orders":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Orders Dashboard","panels":[{"id":4,"title":"Orders","type":"table","datasource":"warehouse","targets":[{"query":"WITH recent AS (SELECT * FROM sales.orders) SELECT * FROM recent JOIN customers c ON c.id = recent.customer_id"}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertPanelQuery(t, snapshot, "4", "WITH recent AS (SELECT * FROM sales.orders) SELECT * FROM recent JOIN customers c ON c.id = recent.customer_id", "sql")
	assertResourceCount(t, snapshot, model.ResourceTypeTable, 2)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypePanel, model.ResourceTypeTable)
	assertPanelDependencyMetadata(t, snapshot, "4", "0", "0", "2", "0")
}

func TestGrafanaConnectorDoesNotFallbackExplicitUnresolvedTargetDatasource(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[{"id":1,"uid":"loki","name":"Loki","type":"loki","url":"http://loki:3100"}]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"drift","title":"Datasource Drift"}]`))
		case "/api/dashboards/uid/drift":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Datasource Drift","panels":[{"id":9,"title":"Drifted Target","type":"traces","datasource":"loki","targets":[{"query":"{ resource.service.name = \"checkout\" }","datasource":{"uid":"deleted-tempo","type":"tempo"}}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertPanelQuery(t, snapshot, "9", `{ resource.service.name = "checkout" }`, "traceql")
	assertResourceCount(t, snapshot, model.ResourceTypeLogStream, 0)
	assertResourceCount(t, snapshot, model.ResourceTypeTraceService, 0)
	assertPanelDatasourceMetadata(t, snapshot, "9", map[string]string{
		model.MetadataPanelUnresolvedDatasourceCount: "1",
	})
}

func TestGrafanaConnectorCountsQueryDependencyParseErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/datasources":
			_, _ = w.Write([]byte(`[{"id":1,"uid":"loki","name":"Loki","type":"loki","url":"http://loki:3100"}]`))
		case "/api/search":
			_, _ = w.Write([]byte(`[{"uid":"malformed","title":"Malformed Query"}]`))
		case "/api/dashboards/uid/malformed":
			_, _ = w.Write([]byte(`{"dashboard":{"title":"Malformed Query","panels":[{"id":3,"title":"Broken Logs","type":"logs","datasource":"loki","targets":[{"query":"{app=\"api\""}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	})

	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeLogStream, 0)
	assertPanelDependencyMetadata(t, snapshot, "3", "0", "0", "0", "1")
}

func assertDashboardMetadata(t *testing.T, snapshot Snapshot, uid, folderUID, folderTitle, slug string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeDashboard && resource.Metadata[model.MetadataDashboardUID] == uid {
			if resource.Metadata[model.MetadataDashboardDetailAvailable] != "true" {
				t.Fatalf("expected dashboard detail availability, got %q", resource.Metadata[model.MetadataDashboardDetailAvailable])
			}
			if resource.Metadata[model.MetadataFolderUID] != folderUID {
				t.Fatalf("expected dashboard folder uid %q, got %q", folderUID, resource.Metadata[model.MetadataFolderUID])
			}
			if resource.Metadata[model.MetadataFolderTitle] != folderTitle {
				t.Fatalf("expected dashboard folder title %q, got %q", folderTitle, resource.Metadata[model.MetadataFolderTitle])
			}
			if resource.Metadata[model.MetadataDashboardSlug] != slug {
				t.Fatalf("expected dashboard slug %q, got %q", slug, resource.Metadata[model.MetadataDashboardSlug])
			}
			if _, exists := resource.Metadata[model.MetadataDashboardURL]; exists {
				t.Fatalf("dashboard URL must not be persisted, got %q", resource.Metadata[model.MetadataDashboardURL])
			}
			if resource.Metadata[model.MetadataDashboardVersion] != "12" {
				t.Fatalf("expected dashboard version 12, got %q", resource.Metadata[model.MetadataDashboardVersion])
			}
			if resource.Metadata[model.MetadataDashboardSchemaVersion] != "39" {
				t.Fatalf("expected dashboard schema version 39, got %q", resource.Metadata[model.MetadataDashboardSchemaVersion])
			}
			if resource.Metadata[model.MetadataDashboardTags] != "api,prod" {
				t.Fatalf("expected dashboard tags api,prod, got %q", resource.Metadata[model.MetadataDashboardTags])
			}
			if resource.Metadata[model.MetadataDashboardTimezone] != "browser" {
				t.Fatalf("expected dashboard timezone browser, got %q", resource.Metadata[model.MetadataDashboardTimezone])
			}
			if resource.Metadata[model.MetadataDashboardRefresh] != "30s" {
				t.Fatalf("expected dashboard refresh 30s, got %q", resource.Metadata[model.MetadataDashboardRefresh])
			}
			if resource.Metadata[model.MetadataDashboardTimeFrom] != "now-7d" {
				t.Fatalf("expected dashboard time from now-7d, got %q", resource.Metadata[model.MetadataDashboardTimeFrom])
			}
			if resource.Metadata[model.MetadataDashboardTimeTo] != "now" {
				t.Fatalf("expected dashboard time to now, got %q", resource.Metadata[model.MetadataDashboardTimeTo])
			}
			if resource.Metadata[model.MetadataDashboardTimeRange] != "168h0m0s" {
				t.Fatalf("expected dashboard time range 168h0m0s, got %q", resource.Metadata[model.MetadataDashboardTimeRange])
			}
			if resource.Metadata[model.MetadataDashboardAnnotationCnt] != "2" {
				t.Fatalf("expected dashboard annotation count 2, got %q", resource.Metadata[model.MetadataDashboardAnnotationCnt])
			}
			if resource.Metadata[model.MetadataDashboardEditable] != "true" {
				t.Fatalf("expected dashboard editable true, got %q", resource.Metadata[model.MetadataDashboardEditable])
			}
			if resource.Metadata["created_at"] != "2024-01-02T03:04:05Z" {
				t.Fatalf("expected dashboard created_at metadata, got %q", resource.Metadata["created_at"])
			}
			if resource.Metadata[model.MetadataUpdatedAt] != "2024-02-03T04:05:06Z" {
				t.Fatalf("expected dashboard updated_at metadata, got %q", resource.Metadata[model.MetadataUpdatedAt])
			}
			if resource.Metadata[model.MetadataQueryLength] == "" {
				t.Fatalf("expected dashboard query length metadata")
			}
			return
		}
	}
	t.Fatalf("expected dashboard resource with uid %q", uid)
}

func assertFolderMetadata(t *testing.T, snapshot Snapshot, uid, title string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeFolder && resource.Metadata[model.MetadataFolderUID] == uid {
			if resource.Name != title {
				t.Fatalf("expected folder name %q, got %q", title, resource.Name)
			}
			if resource.Metadata[model.MetadataFolderTitle] != title {
				t.Fatalf("expected folder title %q, got %q", title, resource.Metadata[model.MetadataFolderTitle])
			}
			return
		}
	}
	t.Fatalf("expected folder resource with uid %q", uid)
}

func assertPanelTitle(t *testing.T, snapshot Snapshot, panelID string, expected string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataPanelTitle] != expected {
				t.Fatalf("expected panel title %q, got %q", expected, resource.Metadata[model.MetadataPanelTitle])
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertPanelVisualizationType(t *testing.T, snapshot Snapshot, panelID string, expected string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataVisualizationType] != expected {
				t.Fatalf("expected panel visualization type %q, got %q", expected, resource.Metadata[model.MetadataVisualizationType])
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertPanelGrid(t *testing.T, snapshot Snapshot, panelID string, x string, y string, w string, h string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataPanelGridX] != x {
				t.Fatalf("expected panel grid x %q, got %q", x, resource.Metadata[model.MetadataPanelGridX])
			}
			if resource.Metadata[model.MetadataPanelGridY] != y {
				t.Fatalf("expected panel grid y %q, got %q", y, resource.Metadata[model.MetadataPanelGridY])
			}
			if resource.Metadata[model.MetadataPanelGridW] != w {
				t.Fatalf("expected panel grid width %q, got %q", w, resource.Metadata[model.MetadataPanelGridW])
			}
			if resource.Metadata[model.MetadataPanelGridH] != h {
				t.Fatalf("expected panel grid height %q, got %q", h, resource.Metadata[model.MetadataPanelGridH])
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertPanelDisplayMetadata(t *testing.T, snapshot Snapshot, panelID string, unit string, thresholdCount string, legendMode string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataPanelUnit] != unit {
				t.Fatalf("expected panel unit %q, got %q", unit, resource.Metadata[model.MetadataPanelUnit])
			}
			if resource.Metadata[model.MetadataPanelThresholdCount] != thresholdCount {
				t.Fatalf("expected panel threshold count %q, got %q", thresholdCount, resource.Metadata[model.MetadataPanelThresholdCount])
			}
			if resource.Metadata[model.MetadataPanelLegendMode] != legendMode {
				t.Fatalf("expected panel legend mode %q, got %q", legendMode, resource.Metadata[model.MetadataPanelLegendMode])
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertPanelDatasourceMetadata(t *testing.T, snapshot Snapshot, panelID string, expected map[string]string) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypePanel || resource.Metadata[model.MetadataPanelID] != panelID {
			continue
		}
		for key, value := range expected {
			if resource.Metadata[key] != value {
				t.Fatalf("expected panel %s metadata %s=%q, got %q", panelID, key, value, resource.Metadata[key])
			}
		}
		return
	}
	t.Fatalf("panel %s not found", panelID)
}

func assertPanelDependencyMetadata(t *testing.T, snapshot Snapshot, panelID, logStreams, traceServices, tables, parseErrors string) {
	t.Helper()
	assertPanelDatasourceMetadata(t, snapshot, panelID, map[string]string{
		model.MetadataPanelLogStreamDependencyCount:  logStreams,
		model.MetadataPanelTraceServiceDependencyCnt: traceServices,
		model.MetadataPanelTableDependencyCount:      tables,
		model.MetadataPanelDependencyParseErrorCount: parseErrors,
	})
}

func assertLogStreamDependencyIsRedacted(t *testing.T, snapshot Snapshot) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeLogStream {
			continue
		}
		serialized := resource.Name + fmt.Sprint(resource.Metadata) + resource.Source.ExternalID
		if strings.Contains(serialized, `app`) || strings.Contains(serialized, `api`) || strings.Contains(serialized, `error`) {
			t.Fatalf("expected redacted LogStream dependency, got %#v", resource)
		}
		return
	}
	t.Fatal("LogStream dependency not found")
}

func assertPanelPromQL(t *testing.T, snapshot Snapshot, panelID string, expected string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataPromQL] != expected {
				t.Fatalf("expected panel promql %q, got %q", expected, resource.Metadata[model.MetadataPromQL])
			}
			if resource.Metadata[model.MetadataQueryLength] == "" {
				t.Fatalf("expected panel query length metadata")
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertPanelNoPromQL(t *testing.T, snapshot Snapshot, panelID string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataPromQL] != "" {
				t.Fatalf("expected no panel promql, got %q", resource.Metadata[model.MetadataPromQL])
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertPanelQuery(t *testing.T, snapshot Snapshot, panelID string, expectedQuery string, expectedLanguage string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypePanel && resource.Metadata[model.MetadataPanelID] == panelID {
			if resource.Metadata[model.MetadataQuery] != expectedQuery {
				t.Fatalf("expected panel query %q, got %q", expectedQuery, resource.Metadata[model.MetadataQuery])
			}
			if resource.Metadata[model.MetadataQueryLanguage] != expectedLanguage {
				t.Fatalf("expected panel query language %q, got %q", expectedLanguage, resource.Metadata[model.MetadataQueryLanguage])
			}
			if resource.Metadata[model.MetadataQueryLength] == "" {
				t.Fatalf("expected panel query length metadata")
			}
			return
		}
	}
	t.Fatalf("expected panel resource with panel id %q", panelID)
}

func assertDatasourceMetadata(t *testing.T, snapshot Snapshot, uid, access, isDefault, readOnly, basicAuth, createdAt, updatedAt string) {
	t.Helper()

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeDatasource && resource.Metadata[model.MetadataDatasourceUID] == uid {
			if resource.Metadata[model.MetadataDatasourceAccess] != access {
				t.Fatalf("expected datasource access %q, got %q", access, resource.Metadata[model.MetadataDatasourceAccess])
			}
			if resource.Metadata[model.MetadataDatasourceDefault] != isDefault {
				t.Fatalf("expected datasource default %q, got %q", isDefault, resource.Metadata[model.MetadataDatasourceDefault])
			}
			if resource.Metadata[model.MetadataDatasourceReadOnly] != readOnly {
				t.Fatalf("expected datasource read-only %q, got %q", readOnly, resource.Metadata[model.MetadataDatasourceReadOnly])
			}
			if resource.Metadata[model.MetadataDatasourceBasicAuth] != basicAuth {
				t.Fatalf("expected datasource basic auth %q, got %q", basicAuth, resource.Metadata[model.MetadataDatasourceBasicAuth])
			}
			if resource.Metadata[model.MetadataDatasourceURLConfigured] != "true" ||
				resource.Metadata[model.MetadataDatasourceURLValid] != "true" ||
				resource.Metadata[model.MetadataDatasourceURLScheme] != "http" ||
				resource.Metadata[model.MetadataDatasourceURLHostScope] != "internal" ||
				resource.Metadata[model.MetadataDatasourceURLHostFingerprint] != model.StableID("datasource-host", "prometheus") ||
				resource.Metadata[model.MetadataDatasourceEndpointFingerprint] != model.StableID("datasource-endpoint", "http://prometheus:9090") {
				t.Fatalf("unexpected privacy-safe datasource endpoint metadata: %#v", resource.Metadata)
			}
			if _, exists := resource.Metadata[model.MetadataDatasourceURL]; exists {
				t.Fatalf("raw datasource URL must not be persisted, got %q", resource.Metadata[model.MetadataDatasourceURL])
			}
			if resource.Metadata["created_at"] != createdAt {
				t.Fatalf("expected datasource created_at %q, got %q", createdAt, resource.Metadata["created_at"])
			}
			if resource.Metadata[model.MetadataUpdatedAt] != updatedAt {
				t.Fatalf("expected datasource updated_at %q, got %q", updatedAt, resource.Metadata[model.MetadataUpdatedAt])
			}
			if resource.CreatedAt.Format(time.RFC3339) != createdAt || resource.UpdatedAt.Format(time.RFC3339) != updatedAt {
				t.Fatalf("expected datasource resource timestamps %s/%s, got %s/%s", createdAt, updatedAt, resource.CreatedAt.Format(time.RFC3339), resource.UpdatedAt.Format(time.RFC3339))
			}
			return
		}
	}
	t.Fatalf("expected datasource resource with uid %q", uid)
}

func assertDatasourceHealth(t *testing.T, snapshot Snapshot, uid, health, evaluable string) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeDatasource || resource.Metadata[model.MetadataDatasourceUID] != uid {
			continue
		}
		if resource.Metadata[model.MetadataHealth] != health ||
			resource.Metadata[model.MetadataDatasourceHealthEvaluable] != evaluable {
			t.Fatalf(
				"expected datasource %q health/evaluable %q/%q, got %q/%q",
				uid,
				health,
				evaluable,
				resource.Metadata[model.MetadataHealth],
				resource.Metadata[model.MetadataDatasourceHealthEvaluable],
			)
		}
		return
	}
	t.Fatalf("expected datasource resource with uid %q", uid)
}

func assertMetric(t *testing.T, snapshot Snapshot, name string) {
	t.Helper()

	for _, resource := range append(snapshot.Resources, snapshot.References...) {
		if resource.Type == model.ResourceTypeMetric && resource.Name == name {
			return
		}
	}
	t.Fatalf("expected metric resource %q", name)
}

func assertNoMetric(t *testing.T, snapshot Snapshot, name string) {
	t.Helper()

	for _, resource := range append(snapshot.Resources, snapshot.References...) {
		if resource.Type == model.ResourceTypeMetric && resource.Name == name {
			t.Fatalf("expected no metric resource %q", name)
		}
	}
}

func assertMetricInstance(t *testing.T, snapshot Snapshot, expected string) {
	t.Helper()
	assertMetricInstanceForName(t, snapshot, "http_requests_total", expected)
}

func assertMetricInstanceForName(t *testing.T, snapshot Snapshot, metricName string, expected string) {
	t.Helper()

	for _, resource := range append(snapshot.Resources, snapshot.References...) {
		if resource.Type == model.ResourceTypeMetric && resource.Name == metricName {
			if resource.Source.Instance != expected {
				t.Fatalf("expected metric instance %q, got %q", expected, resource.Source.Instance)
			}
			return
		}
	}
	t.Fatalf("expected metric resource %q", metricName)
}

func TestGrafanaAlertRulesMapping(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	datasource := grafanaResource(model.ResourceTypeDatasource, "Prometheus", "http://grafana.example", "datasource:prom", now)
	datasource.Metadata = map[string]string{
		model.MetadataDatasourceUID: "prom",
		model.MetadataDatasourceURL: "http://prometheus:9090",
	}
	resources := map[string]model.Resource{datasource.ID: datasource}
	relationships := make([]model.Relationship, 0)

	addGrafanaAlertRules(resources, &relationships, []grafanaAlertRule{
		{
			UID:          "rule-1",
			Title:        "APIHighErrorRate",
			Condition:    "A",
			NoDataState:  "Alerting",
			ExecErrState: "Error",
			Labels: map[string]string{
				"severity": "warning",
			},
			Annotations: map[string]string{
				"summary": "API has high 5xx rate",
			},
			Data: []grafanaAlertRuleData{
				{
					RefID:         "A",
					DatasourceUID: "prom",
					Model: map[string]any{
						"expr": "sum(rate(http_requests_total[5m])) > 10",
					},
				},
			},
		},
	}, map[string]model.Resource{"prom": datasource}, "http://grafana.example", now)

	snapshot := Snapshot{Relationships: relationships}
	for _, resource := range resources {
		snapshot.Resources = append(snapshot.Resources, resource)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeDatasource)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeMetric)
	assertMetricInstance(t, snapshot, "http://prometheus:9090")

	var foundRule bool
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeAlertRule {
			continue
		}
		foundRule = resource.Name == "APIHighErrorRate" &&
			resource.Metadata[model.MetadataPromQL] == "sum(rate(http_requests_total[5m])) > 10" &&
			resource.Metadata[model.MetadataQueryLength] != "" &&
			resource.Metadata[model.MetadataNoDataState] == "Alerting" &&
			resource.Metadata[model.MetadataExecErrState] == "Error" &&
			resource.Metadata["annotation.summary"] == "API has high 5xx rate"
	}
	if !foundRule {
		t.Fatalf("expected grafana alert rule metadata to be mapped")
	}
}

func TestGrafanaAlertRulesUseModelDatasource(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	datasource := grafanaResource(model.ResourceTypeDatasource, "Prometheus", "http://grafana.example", "datasource:prom", now)
	datasource.Metadata = map[string]string{
		model.MetadataDatasourceUID:  "prom",
		model.MetadataDatasourceType: "prometheus",
		model.MetadataDatasourceURL:  "http://prometheus:9090",
	}
	resources := map[string]model.Resource{datasource.ID: datasource}
	relationships := make([]model.Relationship, 0)
	var rules []grafanaAlertRule
	if err := json.Unmarshal([]byte(`[
		{
			"uid": "rule-1",
			"title": "APIHighErrorRate",
			"condition": "A",
			"data": [
				{
					"refId": "A",
					"model": {
						"expr": "sum(rate(http_requests_total[5m])) > 10",
						"datasource": {"uid": "prom", "type": "prometheus"}
					}
				}
			]
		}
	]`), &rules); err != nil {
		t.Fatalf("decode alert rules: %v", err)
	}

	addGrafanaAlertRules(resources, &relationships, rules, map[string]model.Resource{"prom": datasource}, "http://grafana.example", now)
	snapshot := Snapshot{Relationships: relationships}
	for _, resource := range resources {
		snapshot.Resources = append(snapshot.Resources, resource)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeDatasource)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeMetric)
	assertMetricInstanceForName(t, snapshot, "http_requests_total", "http://prometheus:9090")
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeAlertRule && resource.Metadata[model.MetadataPromQL] != "sum(rate(http_requests_total[5m])) > 10" {
			t.Fatalf("expected alert rule PromQL from model datasource payload, got %#v", resource.Metadata)
		}
	}
}

func TestGrafanaReceiverMapping(t *testing.T) {
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	resources := make(map[string]model.Resource)
	relationships := make([]model.Relationship, 0)
	rules := []grafanaAlertRule{
		{
			UID:   "rule-1",
			Title: "APIHighErrorRate",
			NotificationSettings: &grafanaNotificationSettings{
				Receiver: "platform-oncall",
			},
		},
	}
	policy := &grafanaNotificationRoute{
		Receiver: "platform-oncall",
		Routes: []grafanaNotificationRoute{
			{Receiver: "missing-team"},
			{Receiver: "platform-oncall"},
		},
	}

	addGrafanaAlertRules(resources, &relationships, rules, nil, "http://grafana.example", now)
	addGrafanaReceivers(resources, &relationships, []grafanaContactPoint{
		{UID: "cp-slack", Name: "platform-oncall", Type: "slack", Provenance: "api"},
		{UID: "cp-pd", Name: "platform-oncall", Type: "pagerduty", Provenance: "file"},
		{UID: "cp-unused", Name: "legacy-email", Type: "email"},
	}, policy, rules, "http://grafana.example", now)

	snapshot := Snapshot{Relationships: relationships}
	for _, resource := range resources {
		snapshot.Resources = append(snapshot.Resources, resource)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 3)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeReceiver)

	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeReceiver {
			continue
		}
		switch resource.Name {
		case "platform-oncall":
			if resource.Metadata["declared"] != "true" ||
				resource.Metadata["referenced_by_route"] != "true" ||
				resource.Metadata[model.MetadataReceiverRouteCount] != "3" ||
				resource.Metadata[model.MetadataReceiverIntegrations] != "pagerduty,slack" ||
				resource.Metadata[model.MetadataReceiverUIDs] != "cp-pd,cp-slack" ||
				resource.Metadata[model.MetadataReceiverProvenance] != "api,file" {
				t.Fatalf("unexpected grouped receiver metadata: %#v", resource.Metadata)
			}
		case "missing-team":
			if resource.Metadata["declared"] != "false" || resource.Metadata["referenced_by_route"] != "true" {
				t.Fatalf("unexpected missing receiver metadata: %#v", resource.Metadata)
			}
		case "legacy-email":
			if resource.Metadata["declared"] != "true" || resource.Metadata["referenced_by_route"] != "" {
				t.Fatalf("unexpected unused receiver metadata: %#v", resource.Metadata)
			}
		}
	}
}

func TestGrafanaRoutingPolicyRiskStats(t *testing.T) {
	policy := grafanaNotificationRoute{
		Receiver: "default",
		Routes: []grafanaNotificationRoute{
			{Receiver: "catch-all"},
			{Receiver: "platform", ObjectMatchers: json.RawMessage(`[["team","=","platform"]]`), Routes: []grafanaNotificationRoute{
				{Receiver: "pagerduty", Matchers: json.RawMessage(`["severity=critical"]`)},
			}},
		},
	}
	stats := grafanaRoutingPolicyStats(policy)
	if stats.routeCount != 4 || stats.catchAllRouteCount != 1 || stats.shadowedRouteCount != 2 {
		t.Fatalf("unexpected Grafana shadowed route stats: %#v", stats)
	}

	policy.Routes[0].Continue = true
	policy.Routes[0].MuteTimeIntervals = []string{"maintenance"}
	stats = grafanaRoutingPolicyStats(policy)
	if stats.continueRouteCount != 1 || stats.catchAllContinueCount != 1 || stats.shadowedRouteCount != 0 || stats.timeIntervalRouteCount != 1 {
		t.Fatalf("unexpected Grafana fanout route stats: %#v", stats)
	}
}

func TestGrafanaOptionalAlertingProvisioningEndpoints(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/provisioning/contact-points":
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/api/v1/provisioning/policies":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	if contactPoints, err := connector.contactPoints(context.Background()); err != nil || contactPoints != nil {
		t.Fatalf("expected forbidden contact points to be optional, got %#v, %v", contactPoints, err)
	}
	if policy, err := connector.notificationPolicy(context.Background()); err != nil || policy != nil {
		t.Fatalf("expected missing policy to be optional, got %#v, %v", policy, err)
	}
}

func TestGrafanaContactPointSettingsAreNotPersisted(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"uid":"cp-1","name":"platform","type":"webhook","settings":{"url":"http://secret.example/hook","authorization_credentials":"secret-token","message":"see http://docs.example/runbook"},"provenance":"api"}]`))
	})
	connector, err := NewGrafanaConnector("http://grafana.test", "token")
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	contactPoints, err := connector.contactPoints(context.Background())
	if err != nil {
		t.Fatalf("read contact points: %v", err)
	}
	resources := make(map[string]model.Resource)
	relationships := make([]model.Relationship, 0)
	addGrafanaReceivers(resources, &relationships, contactPoints, nil, nil, "http://grafana.test", time.Now().UTC())
	for _, resource := range resources {
		if resource.Metadata[model.MetadataReceiverInsecureEndpointCount] != "1" {
			t.Fatalf("unexpected insecure endpoint count: %#v", resource.Metadata)
		}
		for key, value := range resource.Metadata {
			if strings.Contains(value, "secret.example") || value == "secret-token" || strings.Contains(value, "docs.example") {
				t.Fatalf("contact point secret leaked through metadata %q", key)
			}
		}
	}
}

func TestGrafanaAppReceiverInsecureEndpointCount(t *testing.T) {
	receiver := grafanaAppReceiver{
		Metadata: grafanaAppMetadata{Name: "platform"},
		Spec: grafanaAppReceiverSpec{Title: "platform", Integrations: []grafanaAppReceiverIntegration{{
			UID: "webhook-1", Type: "webhook", Settings: json.RawMessage(`{"url":"http://secret.example/hook","message":"http://docs.example/runbook"}`),
		}}},
	}
	contactPoints := receiver.contactPoints()
	if len(contactPoints) != 1 || contactPoints[0].InsecureEndpointCount != 1 {
		t.Fatalf("unexpected App Platform insecure endpoint mapping: %#v", contactPoints)
	}
}

func TestGrafanaAppPlatformAlertingFallback(t *testing.T) {
	requested := make(map[string]int)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/provisioning/alert-rules", "/api/v1/provisioning/policies", "/api/v1/provisioning/mute-timings", "/api/v1/provisioning/templates":
			http.NotFound(w, r)
		case "/api/v1/provisioning/contact-points":
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/apis/rules.alerting.grafana.app/v0alpha1/namespaces/org-2/alertrules":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"rule-uid","namespace":"org-2","annotations":{"grafana.app/folder":"folder-1"}},"spec":{"title":"APIHighErrorRate","paused":false,"trigger":{"interval":"1m"},"labels":{"severity":"critical"},"annotations":{"summary":"API errors"},"for":"5m","noDataState":"Alerting","execErrState":"Error","notificationSettings":{"receiver":"platform"},"expressions":{"A":{"datasourceUID":"prom","model":{"expr":"rate(http_requests_total[5m]) > 1"},"source":true}}}}]}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/org-2/receivers":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"receiver-uid","annotations":{"grafana.com/provenance":"api"}},"spec":{"title":"platform","integrations":[{"uid":"slack-uid","type":"slack","settings":{"url":"secret","message":"{{ template \"platform.message\" . }}"}},{"uid":"pd-uid","type":"pagerduty","settings":{"token":"secret"}}]}},{"metadata":{"name":"empty-uid"},"spec":{"title":"empty","integrations":[]}}]}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/org-2/routingtrees":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"default"},"spec":{"defaults":{"receiver":"platform"},"routes":[{"receiver":"missing-team","routes":[{"receiver":"blackhole","matchers":[{"type":"=","label":"severity","value":"critical"}]}]},{"routes":[{"receiver":"platform","continue":true,"mute_time_intervals":["maintenance"],"active_time_intervals":["missing-window"]}]}]}}]}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/org-2/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"critical-inhibits-warning"},"spec":{"source_matchers":[{"type":"=","label":"severity","value":"critical"}],"target_matchers":[{"type":"=~","label":"severity","value":".*"}],"equal":[]}}]}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/org-2/timeintervals":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"maintenance-id","annotations":{"grafana.com/provenance":"api"}},"spec":{"name":"maintenance","time_intervals":[{"weekdays":["monday:friday"]}]}},{"metadata":{"name":"unused-id"},"spec":{"name":"unused-window","time_intervals":[{"weekdays":["saturday"]}]}}]}`))
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/org-2/templategroups":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"platform-group","annotations":{"grafana.com/provenance":"api"}},"spec":{"title":"platform","content":"{{ define \"platform.message\" }}Platform alert{{ end }}","kind":"custom"}},{"metadata":{"name":"unused-group"},"spec":{"title":"unused","content":"{{ define \"unused.message\" }}Unused{{ end }}","kind":"custom"}},{"metadata":{"name":"empty-group"},"spec":{"title":"empty-template","content":"","kind":"custom"}}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithNamespace("http://grafana.test", "org-2", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)

	rules, err := connector.alertRules(context.Background())
	if err != nil || len(rules) != 1 {
		t.Fatalf("read app alert rules: %#v, %v", rules, err)
	}
	if rules[0].UID != "rule-uid" || rules[0].FolderUID != "folder-1" || rules[0].Condition != "A" || rules[0].EvaluationInterval != "1m" || rules[0].NotificationSettings == nil || rules[0].NotificationSettings.Receiver != "platform" {
		t.Fatalf("unexpected app alert rule mapping: %#v", rules[0])
	}
	contactPoints, err := connector.contactPoints(context.Background())
	if err != nil || len(contactPoints) != 3 {
		t.Fatalf("read app contact points: %#v, %v", contactPoints, err)
	}
	policy, err := connector.notificationPolicy(context.Background())
	if err != nil || policy == nil || policy.Receiver != "platform" || len(policy.Routes) != 2 {
		t.Fatalf("read app routing trees: %#v, %v", policy, err)
	}
	inhibitionRules, err := connector.inhibitionRules(context.Background())
	if err != nil || len(inhibitionRules) != 1 {
		t.Fatalf("read app inhibition rules: %#v, %v", inhibitionRules, err)
	}
	timeIntervals, timeIntervalsAvailable, err := connector.timeIntervals(context.Background())
	if err != nil || !timeIntervalsAvailable || len(timeIntervals) != 2 {
		t.Fatalf("read app time intervals: %#v, available=%t, %v", timeIntervals, timeIntervalsAvailable, err)
	}
	notificationTemplates, notificationTemplatesAvailable, err := connector.notificationTemplates(context.Background())
	if err != nil || !notificationTemplatesAvailable || len(notificationTemplates) != 3 {
		t.Fatalf("read app notification templates: %#v, available=%t, %v", notificationTemplates, notificationTemplatesAvailable, err)
	}

	resources := make(map[string]model.Resource)
	relationships := make([]model.Relationship, 0)
	now := time.Now().UTC()
	addGrafanaAlertRules(resources, &relationships, rules, nil, connector.baseURL, now)
	addGrafanaReceivers(resources, &relationships, contactPoints, policy, rules, connector.baseURL, now)
	addGrafanaInhibitionRules(resources, inhibitionRules, connector.baseURL, now)
	addGrafanaTimeIntervals(resources, &relationships, timeIntervals, timeIntervalsAvailable, policy, connector.baseURL, now)
	addGrafanaNotificationTemplates(resources, &relationships, notificationTemplates, notificationTemplatesAvailable, contactPoints, connector.baseURL, now)
	snapshot := Snapshot{Relationships: relationships}
	for _, resource := range resources {
		snapshot.Resources = append(snapshot.Resources, resource)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 4)
	assertResourceCount(t, snapshot, model.ResourceTypeNotificationPolicy, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeInhibitionRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTimeInterval, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeNotificationTemplate, 3)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeReceiver)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, model.ResourceTypeReceiver)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, model.ResourceTypeTimeInterval)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeReceiver, model.ResourceTypeNotificationTemplate)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeNotificationPolicy && (resource.Metadata[model.MetadataPolicyDefaultReceiver] != "platform" || resource.Metadata[model.MetadataPolicyRouteCount] != "5" || resource.Metadata[model.MetadataPolicyMaxDepth] != "3" || resource.Metadata[model.MetadataPolicyShadowedRouteCount] != "2" || resource.Metadata[model.MetadataPolicyCatchAllRouteCount] != "3" || resource.Metadata[model.MetadataPolicyContinueRouteCount] != "1" || resource.Metadata[model.MetadataPolicyTimeIntervalRouteCount] != "1") {
			t.Fatalf("unexpected Grafana notification policy metadata: %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeInhibitionRule && (resource.Metadata[model.MetadataInhibitionSourceMatcherCount] != "1" || resource.Metadata[model.MetadataInhibitionTargetMatcherCount] != "1" || resource.Metadata[model.MetadataInhibitionTargetBroadCount] != "1" || resource.Metadata[model.MetadataInhibitionEqualLabelCount] != "0") {
			t.Fatalf("unexpected Grafana inhibition rule metadata: %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeInhibitionRule {
			for key, value := range resource.Metadata {
				if strings.Contains(value, "critical") || strings.Contains(value, ".*") {
					t.Fatalf("Grafana inhibition matcher value leaked through metadata %q=%q", key, value)
				}
			}
		}
		if resource.Type == model.ResourceTypeTimeInterval && resource.Name == "maintenance" && (resource.Metadata[model.MetadataTimeIntervalDeclared] != "true" || resource.Metadata[model.MetadataTimeIntervalSpecCount] != "1" || resource.Metadata[model.MetadataTimeIntervalMuteRefCount] != "1" || resource.Metadata[model.MetadataReceiverProvenance] != "api") {
			t.Fatalf("unexpected declared Grafana time interval metadata: %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeTimeInterval && resource.Name == "missing-window" && (resource.Metadata[model.MetadataTimeIntervalDeclared] != "false" || resource.Metadata[model.MetadataTimeIntervalActiveRefCount] != "1") {
			t.Fatalf("unexpected undefined Grafana time interval metadata: %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeTimeInterval {
			for key, value := range resource.Metadata {
				if strings.Contains(value, "monday") || strings.Contains(value, "saturday") {
					t.Fatalf("Grafana time interval expression leaked through metadata %q=%q", key, value)
				}
			}
		}
		if resource.Type == model.ResourceTypeNotificationTemplate && resource.Name == "platform" && (resource.Metadata[model.MetadataTemplateDefinitionNames] != "platform.message" || resource.Metadata[model.MetadataTemplateDefinitionCount] != "1" || resource.Metadata[model.MetadataTemplateReferenceCount] != "1" || resource.Metadata[model.MetadataTemplateKind] != "custom") {
			t.Fatalf("unexpected used notification template metadata: %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeNotificationTemplate {
			for key, value := range resource.Metadata {
				if strings.Contains(value, "Platform alert") || strings.Contains(value, "secret") {
					t.Fatalf("notification template content or contact point secret leaked through metadata %q=%q", key, value)
				}
			}
		}
	}
	if requested["/apis/notifications.alerting.grafana.app/v0alpha1/namespaces/org-2/receivers"] != 0 {
		t.Fatalf("v0alpha1 receivers should not be called after v1beta1 succeeds")
	}
}

func TestGrafanaLegacyNotificationTemplatesPrecedeAppPlatform(t *testing.T) {
	appRequests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/apis/") {
			appRequests++
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/api/v1/provisioning/templates" {
			_, _ = w.Write([]byte(`[{"name":"custom-email","template":"{{ define \"custom.email\" }}Email{{ end }}","provenance":"file"}]`))
			return
		}
		http.NotFound(w, r)
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	templates, available, err := connector.notificationTemplates(context.Background())
	if err != nil || !available || len(templates) != 1 || templates[0].Name != "custom-email" || templates[0].Provenance != "file" {
		t.Fatalf("unexpected legacy notification templates: %#v, available=%t, %v", templates, available, err)
	}
	if appRequests != 0 {
		t.Fatalf("expected no App Platform request after legacy success, got %d", appRequests)
	}
}

func TestGrafanaAppPlatformNotificationTemplateV0Alpha1Fallback(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/provisioning/templates", "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/templategroups":
			http.NotFound(w, r)
		case "/apis/notifications.alerting.grafana.app/v0alpha1/namespaces/default/templategroups":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"legacy-group"},"spec":{"title":"legacy","content":"{{ define \"legacy.message\" }}Legacy{{ end }}","kind":"custom"}}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	templates, available, err := connector.notificationTemplates(context.Background())
	if err != nil || !available || len(templates) != 1 || templates[0].Name != "legacy" || templates[0].Kind != "custom" {
		t.Fatalf("unexpected v0alpha1 notification template fallback: %#v, available=%t, %v", templates, available, err)
	}
}

func TestGrafanaTemplateReferenceExtraction(t *testing.T) {
	settings := json.RawMessage(`{"message":"{{ template \"custom.message\" . }}","nested":{"title":"{{template \"custom.title\" .}}","token":"secret"}}`)
	references := grafanaTemplateReferences(settings)
	if len(references) != 2 || references[0] != "custom.message" || references[1] != "custom.title" {
		t.Fatalf("unexpected template references: %#v", references)
	}
}

func TestGrafanaNotificationTemplateConflictAndUndefinedReferenceMapping(t *testing.T) {
	templates := []grafanaNotificationTemplate{
		{UID: "one", Name: "one", Template: `{{ define "shared.message" }}One{{ end }}{{ define "shared.message" }}Again{{ end }}`, Kind: "custom"},
		{UID: "two", Name: "two", Template: `{{ define "shared.message" }}Two{{ end }}`, Kind: "custom"},
		{UID: "reserved", Name: "reserved", Template: `{{ define "default.title" }}Override{{ end }}`, Kind: "custom"},
	}
	contactPoints := []grafanaContactPoint{{Name: "platform", TemplateReferences: []string{"shared.message", "missing.custom", "default.message", "slack.default.text"}}}
	resources := make(map[string]model.Resource)
	relationships := make([]model.Relationship, 0)
	addGrafanaNotificationTemplates(resources, &relationships, templates, true, contactPoints, "http://grafana.test", time.Now().UTC())

	conflicts := make(map[string]string)
	undefined := make([]model.Resource, 0)
	for _, resource := range resources {
		if resource.Type != model.ResourceTypeNotificationTemplate {
			continue
		}
		if resource.Metadata[model.MetadataTemplateDeclared] == "false" {
			undefined = append(undefined, resource)
		}
		if resource.Metadata[model.MetadataTemplateConflictCount] != "0" {
			conflicts[resource.Name] = resource.Metadata[model.MetadataTemplateConflictNames]
		}
	}
	if len(resources) != 4 || len(undefined) != 1 || undefined[0].Name != "missing.custom" || undefined[0].Metadata[model.MetadataTemplateReferenceCount] != "1" {
		t.Fatalf("unexpected undefined template mapping: resources=%d undefined=%#v", len(resources), undefined)
	}
	if conflicts["one"] != "shared.message" || conflicts["two"] != "shared.message" || conflicts["reserved"] != "default.title" {
		t.Fatalf("unexpected template conflicts: %#v", conflicts)
	}
	if len(relationships) != 3 {
		t.Fatalf("expected receiver relationships to two shared definitions and one unresolved reference, got %#v", relationships)
	}
}

func TestGrafanaLegacyTimeIntervalsPrecedeAppPlatform(t *testing.T) {
	appRequests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/apis/") {
			appRequests++
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/api/v1/provisioning/mute-timings" {
			_, _ = w.Write([]byte(`[{"name":"office-hours","time_intervals":[{"weekdays":["monday:friday"]}],"provenance":"api"}]`))
			return
		}
		http.NotFound(w, r)
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	intervals, available, err := connector.timeIntervals(context.Background())
	if err != nil || !available || len(intervals) != 1 || intervals[0].Name != "office-hours" || len(intervals[0].TimeIntervals) != 1 {
		t.Fatalf("unexpected legacy time intervals: %#v, available=%t, %v", intervals, available, err)
	}
	if appRequests != 0 {
		t.Fatalf("expected no App Platform request after legacy success, got %d", appRequests)
	}
}

func TestGrafanaAppPlatformTimeIntervalV0Alpha1Fallback(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/provisioning/mute-timings", "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/timeintervals":
			http.NotFound(w, r)
		case "/apis/notifications.alerting.grafana.app/v0alpha1/namespaces/default/timeintervals":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"legacy-id"},"spec":{"name":"legacy-window","time_intervals":[{"months":["january"]}]}}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	intervals, available, err := connector.timeIntervals(context.Background())
	if err != nil || !available || len(intervals) != 1 || intervals[0].Name != "legacy-window" {
		t.Fatalf("unexpected v0alpha1 time interval fallback: %#v, available=%t, %v", intervals, available, err)
	}
}

func TestGrafanaAppPlatformNotificationV0Alpha1Fallback(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/provisioning/contact-points", "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers":
			http.NotFound(w, r)
		case "/apis/notifications.alerting.grafana.app/v0alpha1/namespaces/default/receivers":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"receiver-uid"},"spec":{"title":"legacy-app","integrations":[{"uid":"email-uid","type":"email"}]}}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	contactPoints, err := connector.contactPoints(context.Background())
	if err != nil || len(contactPoints) != 1 || contactPoints[0].Name != "legacy-app" || contactPoints[0].Type != "email" {
		t.Fatalf("unexpected v0alpha1 fallback: %#v, %v", contactPoints, err)
	}
}

func TestGrafanaAppPlatformInhibitionV0Alpha1Fallback(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/inhibitionrules":
			http.NotFound(w, r)
		case "/apis/notifications.alerting.grafana.app/v0alpha1/namespaces/default/inhibitionrules":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"legacy-inhibition"},"spec":{"source_matchers":[{"type":"=","label":"severity","value":"critical"}],"target_matchers":[{"type":"=","label":"severity","value":"warning"}],"equal":["cluster"]}}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	rules, err := connector.inhibitionRules(context.Background())
	if err != nil || len(rules) != 1 || rules[0].Metadata.Name != "legacy-inhibition" || len(rules[0].Spec.Equal) != 1 {
		t.Fatalf("unexpected inhibition v0alpha1 fallback: %#v, %v", rules, err)
	}
}

func TestGrafanaAppPlatformSelectsDefaultRoutingTree(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/provisioning/policies":
			http.NotFound(w, r)
		case "/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/routingtrees":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"named-team"},"spec":{"defaults":{"receiver":"team"}}},{"metadata":{"name":"default"},"spec":{"defaults":{"receiver":"platform"}}}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	policy, err := connector.notificationPolicy(context.Background())
	if err != nil || policy == nil || policy.Receiver != "platform" {
		t.Fatalf("expected default routing tree, got %#v, %v", policy, err)
	}
}

func TestGrafanaLegacyAlertingAPIPrecedesAppPlatform(t *testing.T) {
	appRequests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/apis/") {
			appRequests++
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/v1/provisioning/alert-rules":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/contact-points":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v1/provisioning/policies":
			_, _ = w.Write([]byte(`{"receiver":"legacy"}`))
		default:
			http.NotFound(w, r)
		}
	})
	connector, err := NewGrafanaConnectorWithOptions("http://grafana.test", HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	connector.client = testHTTPClient(handler)
	if _, err := connector.alertRules(context.Background()); err != nil {
		t.Fatalf("legacy alert rules: %v", err)
	}
	if _, err := connector.contactPoints(context.Background()); err != nil {
		t.Fatalf("legacy contact points: %v", err)
	}
	if _, err := connector.notificationPolicy(context.Background()); err != nil {
		t.Fatalf("legacy policy: %v", err)
	}
	if appRequests != 0 {
		t.Fatalf("expected no App Platform requests after legacy success, got %d", appRequests)
	}
}
