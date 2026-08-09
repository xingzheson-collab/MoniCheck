package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

type skyWalkingGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

func TestSkyWalkingConnectorDiscoversAPMTopology(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleSkyWalkingHealth(w, r, http.StatusOK, "") {
			if r.Header.Get("Authorization") != "Bearer secret" {
				t.Fatalf("unexpected health auth: %q", r.Header.Get("Authorization"))
			}
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/custom/graphql" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("unexpected request: method=%s path=%s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		request := decodeSkyWalkingRequest(t, r)
		switch {
		case strings.Contains(request.Query, "MoniCheckCatalog"):
			fmt.Fprint(w, `{"data":{"listServices":[{"id":"checkout-id","name":"checkout","group":"shop","shortName":"checkout","layers":["GENERAL"],"normal":true},{"id":"payments-id","name":"payments","group":"","shortName":"payments","layers":["GENERAL"],"normal":true},{"id":"checkout-id","name":"checkout-duplicate","layers":["GENERAL"],"normal":true}],"getTimeInfo":{"timezone":"+0800","currentTimestamp":1710000000000}}}`)
		case strings.Contains(request.Query, "MoniCheckServiceDetails") && request.Variables["serviceId"] == "checkout-id":
			assertSkyWalkingDuration(t, request)
			fmt.Fprint(w, `{"data":{"listInstances":[{"id":"checkout-1","name":"checkout-pod-1","language":"JAVA"},{"id":"checkout-1","name":"duplicate","language":"JAVA"}],"findEndpoint":[{"id":"get-checkout","name":"GET /checkout"},{"id":"post-order","name":"POST /orders"}]}}`)
		case strings.Contains(request.Query, "MoniCheckServiceDetails") && request.Variables["serviceId"] == "payments-id":
			assertSkyWalkingDuration(t, request)
			fmt.Fprint(w, `{"data":{"listInstances":[],"findEndpoint":[{"id":"post-charge","name":"POST /charge"}]}}`)
		case strings.Contains(request.Query, "MoniCheckTopology"):
			assertSkyWalkingDuration(t, request)
			fmt.Fprint(w, `{"data":{"getGlobalTopology":{"nodes":[{"id":"checkout-id","name":"checkout","type":"SpringMVC","isReal":true,"layers":["GENERAL"]},{"id":"payments-id","name":"payments","type":"gRPC","isReal":true,"layers":["GENERAL"]},{"id":"mysql-id","name":"mysql","type":"MySQL","isReal":false,"layers":["DATABASE"]}],"calls":[{"source":"checkout-id","target":"payments-id","detectPoints":["CLIENT","SERVER"]},{"source":"payments-id","target":"mysql-id","detectPoints":["CLIENT"]}]}}}`)
		case strings.Contains(request.Query, "MoniCheckAlarms"):
			assertSkyWalkingDuration(t, request)
			fmt.Fprint(w, `{"data":{"getAlarm":{"msgs":[{"id":"alarm-service","name":"checkout","message":"checkout latency high","startTime":1709990000000,"recoveryTime":null,"scope":"Service","tags":[{"key":"severity","value":"critical"},{"key":"customer","value":"secret-customer"}]},{"id":"alarm-instance","name":"checkout-pod-1","message":"instance recovered","startTime":1709991000000,"recoveryTime":1709992000000,"scope":"ServiceInstance","tags":[]},{"id":"alarm-endpoint","name":"POST /charge","message":"endpoint slow","startTime":1709993000000,"recoveryTime":null,"scope":"Endpoint","tags":[]},{"id":"alarm-service","name":"duplicate","message":"duplicate","startTime":1709990000000,"recoveryTime":null,"scope":"Service","tags":[]}]}}}`)
		default:
			t.Fatalf("unexpected query: %s variables=%#v", request.Query, request.Variables)
		}
	}))
	defer server.Close()

	connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "/custom/graphql", 6*time.Hour, 10, HTTPOptions{BearerToken: "secret"})
	if err != nil {
		t.Fatalf("new skywalking connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync skywalking: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("expected complete snapshot: %#v", snapshot.Diagnostics)
	}
	assertSkyWalkingDiagnostic(t, snapshot, "skywalking_service_details", 2, 0)
	assertSkyWalkingDiagnostic(t, snapshot, "skywalking_global_topology", 1, 0)
	assertSkyWalkingDiagnostic(t, snapshot, "skywalking_alarms", 1, 0)
	assertSkyWalkingHealthDiagnostic(t, snapshot, true, true, http.StatusOK)
	assertResourceCount(t, snapshot, model.ResourceTypeService, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeTraceOperation, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeAlert, 3)
	assertRelationship(t, snapshot, model.RelationshipBelongsTo, model.ResourceTypeInstance, model.ResourceTypeService)
	assertRelationship(t, snapshot, model.RelationshipBelongsTo, model.ResourceTypeTraceOperation, model.ResourceTypeService)
	assertRelationship(t, snapshot, model.RelationshipDependsOn, model.ResourceTypeService, model.ResourceTypeService)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeAlert, model.ResourceTypeService)

	var checkout model.Resource
	var mysql model.Resource
	var checkoutAlarm model.Resource
	var runtime model.Resource
	for _, resource := range snapshot.Resources {
		if resource.Metadata[model.MetadataSkyWalkingRuntime] == "true" {
			runtime = resource
		}
		if resource.Type == model.ResourceTypeAlert && resource.Name == "checkout" {
			checkoutAlarm = resource
		}
		if resource.Type != model.ResourceTypeService {
			continue
		}
		switch resource.Name {
		case "checkout":
			checkout = resource
		case "mysql":
			mysql = resource
		}
	}
	if checkout.Metadata[model.MetadataAPMInstanceCount] != "1" ||
		checkout.Metadata[model.MetadataAPMEndpointCount] != "2" ||
		checkout.Metadata[model.MetadataAPMType] != "SpringMVC" ||
		checkout.Metadata[model.MetadataAPMLookback] != "6h0m0s" ||
		checkout.Metadata[model.MetadataAPMAlarmCount] != "2" ||
		checkout.Metadata[model.MetadataAPMActiveAlarmCount] != "1" ||
		checkout.Metadata[model.MetadataAPMRecoveredAlarmCount] != "1" {
		t.Fatalf("unexpected checkout metadata: %#v", checkout.Metadata)
	}
	if mysql.Metadata[model.MetadataAPMReal] != "false" || mysql.Metadata[model.MetadataAPMLayer] != "DATABASE" {
		t.Fatalf("unexpected topology-only service: %#v", mysql)
	}
	if checkoutAlarm.Metadata[model.MetadataAlertState] != "active" ||
		checkoutAlarm.Metadata[model.MetadataStartsAt] == "" ||
		checkoutAlarm.Metadata[model.MetadataAPMAlarmTagKeys] != "customer,severity" ||
		checkoutAlarm.Labels["severity"] != "critical" {
		t.Fatalf("unexpected SkyWalking alarm resource: %#v", checkoutAlarm)
	}
	if runtime.Name != "SkyWalking OAP Runtime" ||
		runtime.Source.ExternalID != "oap-runtime" ||
		runtime.Metadata[model.MetadataSkyWalkingHealthAvailable] != "true" ||
		runtime.Metadata[model.MetadataSkyWalkingHealthy] != "true" ||
		runtime.Metadata[model.MetadataSkyWalkingHealthSource] != "http" {
		t.Fatalf("unexpected SkyWalking runtime resource: %#v", runtime)
	}
	if strings.Contains(fmt.Sprint(snapshot), "secret-customer") {
		t.Fatalf("snapshot leaked arbitrary alarm tag value: %#v", snapshot)
	}
}

func TestSkyWalkingConnectorRetainsCatalogOnOptionalFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleSkyWalkingHealth(w, r, http.StatusNotFound, "secret health module detail") {
			return
		}
		request := decodeSkyWalkingRequest(t, r)
		switch {
		case strings.Contains(request.Query, "MoniCheckCatalog"):
			fmt.Fprint(w, `{"data":{"listServices":[{"id":"checkout-id","name":"checkout","normal":true},{"id":"payments-id","name":"payments","normal":true}],"getTimeInfo":{"timezone":"+0000","currentTimestamp":1710000000000}}}`)
		case strings.Contains(request.Query, "MoniCheckServiceDetails") && request.Variables["serviceId"] == "checkout-id":
			fmt.Fprint(w, `{"data":{"listInstances":null,"findEndpoint":null},"errors":[{"message":"secret backend detail"}]}`)
		case strings.Contains(request.Query, "MoniCheckServiceDetails"):
			fmt.Fprint(w, `{"data":{"listInstances":[],"findEndpoint":[]}}`)
		case strings.Contains(request.Query, "MoniCheckTopology"):
			fmt.Fprint(w, `{"data":{"getGlobalTopology":null},"errors":[{"message":"secret topology detail"}]}`)
		case strings.Contains(request.Query, "MoniCheckAlarms"):
			fmt.Fprint(w, `{"data":{"getAlarm":null},"errors":[{"message":"secret alarm detail"}]}`)
		case strings.Contains(request.Query, "MoniCheckHealth"):
			fmt.Fprint(w, `{"data":{"checkHealth":null},"errors":[{"message":"secret health detail"}]}`)
		default:
			t.Fatalf("unexpected query")
		}
	}))
	defer server.Close()

	connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "", time.Hour, 10, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("optional failures should not fail sync: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected partial snapshot")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeService, 2)
	assertSkyWalkingDiagnostic(t, snapshot, "skywalking_service_details", 2, 1)
	assertSkyWalkingDiagnostic(t, snapshot, "skywalking_global_topology", 1, 1)
	assertSkyWalkingDiagnostic(t, snapshot, "skywalking_alarms", 1, 1)
	assertSkyWalkingHealthDiagnostic(t, snapshot, false, false, http.StatusNotFound)
	if strings.Contains(fmt.Sprint(snapshot), "secret backend detail") || strings.Contains(fmt.Sprint(snapshot), "secret topology detail") || strings.Contains(fmt.Sprint(snapshot), "secret alarm detail") || strings.Contains(fmt.Sprint(snapshot), "secret health module detail") || strings.Contains(fmt.Sprint(snapshot), "secret health detail") {
		t.Fatalf("snapshot leaked GraphQL error content: %#v", snapshot)
	}
}

func TestSkyWalkingConnectorMarksEndpointLimitAsPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleSkyWalkingHealth(w, r, http.StatusOK, "") {
			return
		}
		request := decodeSkyWalkingRequest(t, r)
		switch {
		case strings.Contains(request.Query, "MoniCheckCatalog"):
			fmt.Fprint(w, `{"data":{"listServices":[{"id":"checkout-id","name":"checkout","normal":true}],"getTimeInfo":{"timezone":"+0000","currentTimestamp":1710000000000}}}`)
		case strings.Contains(request.Query, "MoniCheckServiceDetails"):
			fmt.Fprint(w, `{"data":{"listInstances":[{"id":"instance-1","name":"checkout-1","language":"JAVA"}],"findEndpoint":[{"id":"endpoint-1","name":"GET /one"},{"id":"endpoint-2","name":"GET /two"}]}}`)
		case strings.Contains(request.Query, "MoniCheckTopology"):
			fmt.Fprint(w, `{"data":{"getGlobalTopology":{"nodes":[],"calls":[]}}}`)
		case strings.Contains(request.Query, "MoniCheckAlarms"):
			fmt.Fprint(w, `{"data":{"getAlarm":{"msgs":[]}}}`)
		default:
			t.Fatalf("unexpected query")
		}
	}))
	defer server.Close()

	connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "", time.Hour, 2, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("endpoint limit should make snapshot partial")
	}
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Metadata[model.MetadataAPMEndpointDiscoveryTruncated] != "true" {
			t.Fatalf("expected truncation metadata: %#v", resource)
		}
	}
}

func TestSkyWalkingConnectorMarksAlarmLimitAsPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleSkyWalkingHealth(w, r, http.StatusOK, "") {
			return
		}
		request := decodeSkyWalkingRequest(t, r)
		switch {
		case strings.Contains(request.Query, "MoniCheckCatalog"):
			fmt.Fprint(w, `{"data":{"listServices":[{"id":"checkout-id","name":"checkout","normal":true}],"getTimeInfo":{"timezone":"+0000","currentTimestamp":1710000000000}}}`)
		case strings.Contains(request.Query, "MoniCheckServiceDetails"):
			fmt.Fprint(w, `{"data":{"listInstances":[],"findEndpoint":[]}}`)
		case strings.Contains(request.Query, "MoniCheckTopology"):
			fmt.Fprint(w, `{"data":{"getGlobalTopology":{"nodes":[],"calls":[]}}}`)
		case strings.Contains(request.Query, "MoniCheckAlarms"):
			if request.Variables["pageNum"] != float64(1) || request.Variables["pageSize"] != float64(2) {
				t.Fatalf("unexpected alarm pagination: %#v", request.Variables)
			}
			fmt.Fprint(w, `{"data":{"getAlarm":{"msgs":[{"id":"alarm-1","name":"checkout","message":"one","startTime":1709990000000,"scope":"Service","tags":[]},{"id":"alarm-2","name":"checkout","message":"two","startTime":1709991000000,"scope":"Service","tags":[]}]}}}`)
		default:
			t.Fatalf("unexpected query")
		}
	}))
	defer server.Close()

	connector, err := NewSkyWalkingConnectorWithGovernanceOptions(server.URL, "", time.Hour, 10, 2, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("alarm limit should make snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeAlert, 2)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Metadata[model.MetadataAPMAlarmDiscoveryTruncated] != "true" {
			t.Fatalf("expected alarm truncation metadata: %#v", resource)
		}
	}
}

func TestSkyWalkingConnectorRequiresServiceCatalogWithoutLeakingErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"listServices":null},"errors":[{"message":"secret database address"}]}`)
	}))
	defer server.Close()
	connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "", time.Hour, 10, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	_, err = connector.Sync(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret database address") {
		t.Fatalf("expected redacted catalog failure, got %v", err)
	}
}

func TestSkyWalkingConnectorReportsExplicitOAPUnhealthy(t *testing.T) {
	const secret = "secret unhealthy storage detail"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleSkyWalkingHealth(w, r, http.StatusServiceUnavailable, secret) {
			return
		}
		request := decodeSkyWalkingRequest(t, r)
		switch {
		case strings.Contains(request.Query, "MoniCheckCatalog"):
			fmt.Fprint(w, `{"data":{"listServices":[],"getTimeInfo":{"timezone":"+0000","currentTimestamp":1710000000000}}}`)
		case strings.Contains(request.Query, "MoniCheckTopology"):
			fmt.Fprint(w, `{"data":{"getGlobalTopology":{"nodes":[],"calls":[]}}}`)
		case strings.Contains(request.Query, "MoniCheckAlarms"):
			fmt.Fprint(w, `{"data":{"getAlarm":{"msgs":[]}}}`)
		default:
			t.Fatalf("unexpected query: %s", request.Query)
		}
	}))
	defer server.Close()

	connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "", time.Hour, 10, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("explicit unhealthy response remains evaluable: %#v", snapshot.Diagnostics)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	assertSkyWalkingHealthDiagnostic(t, snapshot, true, false, http.StatusServiceUnavailable)
	if strings.Contains(fmt.Sprint(snapshot), secret) {
		t.Fatalf("snapshot leaked health response body: %#v", snapshot)
	}
}

func TestSkyWalkingConnectorTreatsUnavailableHealthAsUnevaluable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleSkyWalkingHealth(w, r, http.StatusNotFound, "secret disabled module detail") {
			return
		}
		request := decodeSkyWalkingRequest(t, r)
		switch {
		case strings.Contains(request.Query, "MoniCheckCatalog"):
			fmt.Fprint(w, `{"data":{"listServices":[],"getTimeInfo":{"timezone":"+0000","currentTimestamp":1710000000000}}}`)
		case strings.Contains(request.Query, "MoniCheckTopology"):
			fmt.Fprint(w, `{"data":{"getGlobalTopology":{"nodes":[],"calls":[]}}}`)
		case strings.Contains(request.Query, "MoniCheckAlarms"):
			fmt.Fprint(w, `{"data":{"getAlarm":{"msgs":[]}}}`)
		case strings.Contains(request.Query, "MoniCheckHealth"):
			fmt.Fprint(w, `{"data":{"checkHealth":null},"errors":[{"message":"secret health graphql detail"}]}`)
		default:
			t.Fatalf("unexpected query: %s", request.Query)
		}
	}))
	defer server.Close()

	connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "", time.Hour, 10, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("unavailable health endpoint should make snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 0)
	assertSkyWalkingHealthDiagnostic(t, snapshot, false, false, http.StatusNotFound)
	if strings.Contains(fmt.Sprint(snapshot), "secret disabled module detail") || strings.Contains(fmt.Sprint(snapshot), "secret health graphql detail") {
		t.Fatalf("snapshot leaked health response body: %#v", snapshot)
	}
}

func TestSkyWalkingConnectorFallsBackToGraphQLHealth(t *testing.T) {
	for _, test := range []struct {
		name    string
		score   int
		healthy bool
	}{
		{name: "healthy", score: 0, healthy: true},
		{name: "degraded", score: 2, healthy: false},
		{name: "not started", score: -1, healthy: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if handleSkyWalkingHealth(w, r, http.StatusNotFound, "secret http health detail") {
					return
				}
				request := decodeSkyWalkingRequest(t, r)
				switch {
				case strings.Contains(request.Query, "MoniCheckCatalog"):
					fmt.Fprint(w, `{"data":{"listServices":[],"getTimeInfo":{"timezone":"+0000","currentTimestamp":1710000000000}}}`)
				case strings.Contains(request.Query, "MoniCheckTopology"):
					fmt.Fprint(w, `{"data":{"getGlobalTopology":{"nodes":[],"calls":[]}}}`)
				case strings.Contains(request.Query, "MoniCheckAlarms"):
					fmt.Fprint(w, `{"data":{"getAlarm":{"msgs":[]}}}`)
				case strings.Contains(request.Query, "MoniCheckHealth"):
					fmt.Fprintf(w, `{"data":{"checkHealth":{"score":%d}}}`, test.score)
				default:
					t.Fatalf("unexpected query: %s", request.Query)
				}
			}))
			defer server.Close()

			connector, err := NewSkyWalkingConnectorWithOptions(server.URL, "", time.Hour, 10, HTTPOptions{MaxRetries: -1})
			if err != nil {
				t.Fatalf("new connector: %v", err)
			}
			snapshot, err := connector.Sync(context.Background())
			if err != nil {
				t.Fatalf("sync: %v", err)
			}
			if snapshot.Partial {
				t.Fatalf("GraphQL fallback should be evaluable: %#v", snapshot.Diagnostics)
			}
			assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
			runtime := findSkyWalkingRuntime(snapshot)
			if runtime.Metadata[model.MetadataSkyWalkingHealthSource] != "graphql" ||
				runtime.Metadata[model.MetadataSkyWalkingHealthScore] != strconv.Itoa(test.score) ||
				runtime.Metadata[model.MetadataSkyWalkingHealthy] != strconv.FormatBool(test.healthy) {
				t.Fatalf("unexpected GraphQL health runtime: %#v", runtime)
			}
			diagnostic := findSkyWalkingDiagnostic(snapshot, "skywalking_oap_health")
			if diagnostic.Metadata["source"] != "graphql" ||
				diagnostic.Metadata["score"] != strconv.Itoa(test.score) ||
				diagnostic.Metadata["status_code"] != strconv.Itoa(http.StatusNotFound) {
				t.Fatalf("unexpected GraphQL health diagnostic: %#v", diagnostic)
			}
			if strings.Contains(fmt.Sprint(snapshot), "secret http health detail") {
				t.Fatalf("snapshot leaked HTTP health response body: %#v", snapshot)
			}
		})
	}
}

func TestSkyWalkingDurationUsesServerTimezone(t *testing.T) {
	duration := skyWalkingDuration(1710000000000, "+0800", time.Hour)
	if duration["step"] != "MINUTE" || duration["start"] != "2024-03-09 2300" || duration["end"] != "2024-03-10 0000" {
		t.Fatalf("unexpected duration: %#v", duration)
	}
}

func handleSkyWalkingHealth(w http.ResponseWriter, r *http.Request, status int, body string) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/healthcheck" {
		return false
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
	return true
}

func decodeSkyWalkingRequest(t *testing.T, r *http.Request) skyWalkingGraphQLRequest {
	t.Helper()
	var request skyWalkingGraphQLRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatalf("decode GraphQL request: %v", err)
	}
	return request
}

func assertSkyWalkingDuration(t *testing.T, request skyWalkingGraphQLRequest) {
	t.Helper()
	duration, ok := request.Variables["duration"].(map[string]any)
	if !ok || duration["start"] == "" || duration["end"] == "" || duration["step"] != "MINUTE" {
		t.Fatalf("expected bounded minute duration, got %#v", request.Variables["duration"])
	}
}

func assertSkyWalkingDiagnostic(t *testing.T, snapshot Snapshot, id string, total int, failed int) {
	t.Helper()
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID != id {
			continue
		}
		if diagnostic.Metadata["item_count"] != fmt.Sprintf("%d", total) ||
			diagnostic.Metadata["failed_count"] != fmt.Sprintf("%d", failed) {
			t.Fatalf("unexpected %s diagnostic: %#v", id, diagnostic)
		}
		return
	}
	t.Fatalf("missing %s diagnostic: %#v", id, snapshot.Diagnostics)
}

func assertSkyWalkingHealthDiagnostic(t *testing.T, snapshot Snapshot, available bool, healthy bool, statusCode int) {
	t.Helper()
	diagnostic := findSkyWalkingDiagnostic(snapshot, "skywalking_oap_health")
	if diagnostic.Metadata["available"] != strconv.FormatBool(available) ||
		diagnostic.Metadata["status_code"] != strconv.Itoa(statusCode) {
		t.Fatalf("unexpected SkyWalking health diagnostic: %#v", diagnostic)
	}
	if available && diagnostic.Metadata["healthy"] != strconv.FormatBool(healthy) {
		t.Fatalf("unexpected SkyWalking health state: %#v", diagnostic)
	}
	if available && diagnostic.Metadata["source"] != "http" {
		t.Fatalf("expected HTTP health source: %#v", diagnostic)
	}
	if !available && diagnostic.Metadata["healthy"] != "" {
		t.Fatalf("unavailable health must remain unevaluable: %#v", diagnostic)
	}
}

func findSkyWalkingRuntime(snapshot Snapshot) model.Resource {
	for _, resource := range snapshot.Resources {
		if resource.Metadata[model.MetadataSkyWalkingRuntime] == "true" {
			return resource
		}
	}
	return model.Resource{}
}

func findSkyWalkingDiagnostic(snapshot Snapshot, id string) model.Diagnostic {
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID == id {
			return diagnostic
		}
	}
	return model.Diagnostic{}
}
