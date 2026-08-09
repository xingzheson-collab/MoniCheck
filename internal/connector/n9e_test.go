package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestN9EConnectorUsesOfficialAggregateRuleEndpointByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("expected bearer authentication, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case n9eDefaultRulePath:
			_, _ = w.Write([]byte(`{"dat":[{"id":1,"group_id":12,"name":"APIUnavailable","datasource_ids":[7],"notify_rule_ids":[401,999],"rule_config":{"queries":[{"prom_ql":"up == 0"}]}},{"id":2,"group_id":12,"name":"DatabaseUnavailable","datasource_ids":[7],"rule_config":{"queries":[{"prom_ql":"mysql_up == 0"}]}}]}`))
		case n9eDatasourceBriefPath:
			_, _ = w.Write([]byte(`{"dat":[{"id":7,"name":"prod-prometheus","plugin_type":"prometheus","category":"timeseries","cluster_name":"prod","status":"enabled","http":{"url":"https://prometheus.example"}},{"id":99,"name":"retired-prometheus","plugin_type":"prometheus","status":"disabled"}]}`))
		case n9eCurrentEventsPath:
			page, _ := strconv.Atoi(r.URL.Query().Get("p"))
			if r.URL.Query().Get("limit") != strconv.Itoa(n9eEventPageSize) {
				t.Fatalf("expected event page size %d, got %q", n9eEventPageSize, r.URL.Query().Get("limit"))
			}
			if page == 1 {
				_, _ = w.Write([]byte(`{"dat":{"list":[{"id":501,"hash":"event-501","rule_id":1,"rule_name":"APIUnavailable","group_id":12,"datasource_id":7,"severity":1,"first_trigger_time":1710000000,"last_eval_time":1710000300,"trigger_value":"0","tags":["service=api","team=platform","slo=api-availability","objective=99.9"],"annotations":{"summary":"API is unavailable"}}],"total":2}}`))
			} else {
				_, _ = w.Write([]byte(`{"dat":{"list":[{"id":502,"hash":"event-502","rule_id":2,"rule_name":"DatabaseUnavailable","severity":2,"trigger_time":1710000400,"tags_map":{"service":"database"}}],"total":2}}`))
			}
		case n9eAlertMutesPath:
			_, _ = w.Write([]byte(`{"dat":[{"id":301,"group_id":12,"cause":"database maintenance","note":"change CHG-42","datasource_ids":[7],"tags":[{"key":"service","func":"==","value":"database"},{"key":"instance","func":"=~","value":"db-.*"}],"btime":1700000000,"etime":4102444800,"disabled":0,"activated":1,"mute_time_type":0,"create_by":"platform","update_at":1710000500},{"id":302,"cause":"old periodic mute","datasource_ids":[0],"tags":[],"disabled":1,"mute_time_type":1,"periodic_mutes":[{"enable_stime":"00:00","enable_etime":"23:59","enable_days_of_week":"0 1 2 3 4 5 6"}]}]}`))
		case n9eNotifyRulesPath:
			_, _ = w.Write([]byte(`{"dat":[{"id":401,"name":"platform-oncall","description":"primary notification flow","enable":true,"user_group_ids":[11],"pipeline_configs":[{"pipeline_id":5,"enable":true}],"notify_configs":[{"channel_id":21,"channel_ident":"email","template_id":31,"params":{"user_ids":[99],"address":"secret@example.com"},"severities":[1,2],"time_ranges":[{"start":"00:00","end":"23:59","week":[1,2,3,4,5]}],"label_keys":[{"key":"service","func":"==","value":"api"}]},{"channel_id":22,"channel_ident":"webhook","template_id":32,"params":{"token":"super-secret-token","url":"http://secret.example/hook"},"severities":[1]}],"create_at":1700000000,"update_at":1710000600}]}`))
		case "/api/n9e/busi-groups":
			if r.URL.Query().Get("all") != "true" || r.URL.Query().Get("limit") != "10000" {
				t.Fatalf("expected all visible N9E business groups, got query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"dat":[{"id":12,"name":"payments-platform","label_enable":1,"label_value":"team=payments"}]}`))
		case n9eAlertSubscribesPath:
			_, _ = w.Write([]byte(`{"dat":[{"id":601,"name":"API critical escalation","group_id":12,"disabled":0,"prod":"metric","cate":"prometheus","datasource_ids":[7],"severities":[1],"for_duration":300,"tags":[{"key":"tenant","func":"==","value":"secret-tenant"}],"rule_ids":[1],"notify_rule_ids":[401],"notify_version":1,"note":"primary escalation"},{"id":602,"name":"global fallback subscription","group_id":12,"disabled":0,"datasource_ids":[0],"severities":[1,2,3],"rule_ids":[],"notify_rule_ids":[],"notify_version":1}]}`))
		case n9eHistoryEventsPath:
			if r.URL.Query().Get("hours") != strconv.Itoa(n9eHistoryWindowHours) || r.URL.Query().Get("limit") != strconv.Itoa(n9eEventPageSize) || r.URL.Query().Get("p") != "1" {
				t.Fatalf("expected bounded N9E history query, got %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"dat":{"list":[{"id":701,"hash":"history-secret-fingerprint","rule_id":1,"rule_name":"APIUnavailable","group_id":12,"severity":1,"is_recovered":1,"first_trigger_time":1710000000,"recover_time":1710000120,"notify_cur_number":2,"notify_recovered":0,"notify_rule_ids":[401],"tags":["tenant=secret-history-tenant"],"trigger_value":"secret-trigger-value"},{"id":702,"hash":"history-702","rule_id":1,"rule_name":"APIUnavailable","group_id":12,"severity":2,"is_recovered":1,"trigger_time":1710000300,"recover_time":1710000600,"notify_cur_number":1,"notify_recovered":1,"notify_rule_ids":[402,401]},{"id":703,"hash":"history-703","rule_id":1,"rule_name":"APIUnavailable","group_id":12,"severity":1,"is_recovered":0,"trigger_time":1710000900,"recover_time":0,"notify_cur_number":0,"notify_rule_ids":[401]}],"total":3}}`))
		default:
			t.Fatalf("unexpected n9e path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewN9EConnector(server.URL, "test-key", "")
	if err != nil {
		t.Fatalf("new n9e connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync n9e connector: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeAlert, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeSilence, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeNotificationPolicy, 4)
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	if len(snapshot.Diagnostics) != 7 {
		t.Fatalf("expected seven optional discovery diagnostics, got %#v", snapshot.Diagnostics)
	}
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.Status != model.ExecutionStatusSucceeded {
			t.Fatalf("expected successful optional discovery diagnostic, got %#v", diagnostic)
		}
	}
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIUnavailable", model.ResourceTypeMetric, "up")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIUnavailable", model.ResourceTypeDatasource, "prod-prometheus")
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeAlert, "APIUnavailable", model.ResourceTypeAlertRule, "APIUnavailable")
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeAlert, "DatabaseUnavailable", model.ResourceTypeAlertRule, "DatabaseUnavailable")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeSilence, "database maintenance", model.ResourceTypeDatasource, "prod-prometheus")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIUnavailable", model.ResourceTypeNotificationPolicy, "platform-oncall")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIUnavailable", model.ResourceTypeNotificationPolicy, "notify-rule-999")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, "platform-oncall", model.ResourceTypeReceiver, "email")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIUnavailable", model.ResourceTypeNotificationPolicy, "API critical escalation")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, "API critical escalation", model.ResourceTypeNotificationPolicy, "platform-oncall")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, "API critical escalation", model.ResourceTypeDatasource, "prod-prometheus")
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeInstance {
			if resource.Metadata[model.MetadataN9ERuntime] != "true" ||
				resource.Metadata[model.MetadataN9ERuleDiscoveryAvailable] != "true" ||
				resource.Metadata[model.MetadataN9ERuleCount] != "2" ||
				resource.Metadata[model.MetadataN9ECurrentAlertDiscoveryAvailable] != "true" ||
				resource.Metadata[model.MetadataN9ECurrentAlertEventCount] != "2" ||
				resource.Metadata[model.MetadataN9ECurrentAlertEventTotal] != "2" ||
				resource.Metadata[model.MetadataN9ECurrentAlertEventsTruncated] != "false" ||
				resource.Metadata[model.MetadataN9EHistoryDiscoveryAvailable] != "true" ||
				resource.Metadata[model.MetadataN9EHistoryEventCount] != "3" ||
				resource.Metadata[model.MetadataN9EHistoryEventTotal] != "3" ||
				resource.Metadata[model.MetadataN9EHistoryEventsTruncated] != "false" ||
				resource.Metadata[model.MetadataN9EHistoryWindowHours] != "24" {
				t.Fatalf("expected privacy-safe N9E runtime coverage, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeDatasource && resource.Name == "retired-prometheus" && resource.Status != model.ResourceStatusDeprecated {
			t.Fatalf("expected disabled discovered datasource to be deprecated, got %s", resource.Status)
		}
		if resource.Type == model.ResourceTypeDatasource && resource.Name == "prod-prometheus" && resource.Metadata[model.MetadataDatasourceURL] != "https://prometheus.example" {
			t.Fatalf("expected discovered datasource metadata, got %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeAlert && resource.Name == "APIUnavailable" {
			if resource.Metadata[model.MetadataAlertState] != "active" || resource.Metadata[model.MetadataStartsAt] != "2024-03-09T16:00:00Z" || resource.Labels["service"] != "api" {
				t.Fatalf("expected current event state, timestamp, and labels, got %#v %#v", resource.Metadata, resource.Labels)
			}
			if resource.Metadata["project"] != "payments-platform" || resource.Metadata["business_group"] != "payments-platform" {
				t.Fatalf("expected N9E business group project enrichment, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeSilence && resource.Name == "database maintenance" {
			if resource.Metadata[model.MetadataSilenceState] != "active" || resource.Metadata[model.MetadataSilenceComment] != "change CHG-42" || resource.Metadata[model.MetadataSilenceMatcherCount] != "2" || resource.Metadata[model.MetadataSilenceRegexCount] != "1" {
				t.Fatalf("expected active N9E mute metadata, got %#v", resource.Metadata)
			}
			if resource.Metadata["project"] != "payments-platform" || resource.Metadata["business_group_label_binding"] != "true" {
				t.Fatalf("expected mute business group enrichment, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeSilence && resource.Name == "old periodic mute" && resource.Status != model.ResourceStatusDeprecated {
			t.Fatalf("expected disabled N9E mute to be deprecated, got %s", resource.Status)
		}
		if resource.Type == model.ResourceTypeNotificationPolicy && resource.Name == "platform-oncall" {
			if resource.Metadata[model.MetadataPolicyRouteCount] != "2" || resource.Metadata["pipeline_count"] != "1" || resource.Metadata["user_group_count"] != "1" {
				t.Fatalf("expected N9E notification policy counts, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeNotificationPolicy && resource.Name == "API critical escalation" {
			if resource.Metadata["policy_kind"] != "alert_subscription" || resource.Metadata["project"] != "payments-platform" || resource.Metadata["subscription_rule_filter_count"] != "1" || resource.Metadata["subscription_tag_matcher_count"] != "1" || resource.Metadata[model.MetadataPolicyRouteCount] != "1" {
				t.Fatalf("expected N9E alert subscription topology metadata, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeAlertRule && resource.Name == "APIUnavailable" {
			if resource.Metadata[model.MetadataSLORule] != "true" || resource.Metadata[model.MetadataSLOName] != "api-availability" || resource.Metadata[model.MetadataSLOObjective] != "99.9" {
				t.Fatalf("expected current event SLO labels to be normalized after merge, got %#v", resource.Metadata)
			}
			if resource.Metadata["history_observed"] != "true" || resource.Metadata["history_window_hours"] != "24" || resource.Metadata["history_event_count"] != "3" || resource.Metadata["history_recovered_count"] != "2" || resource.Metadata["history_unrecovered_count"] != "1" || resource.Metadata["history_short_lived_count"] != "2" || resource.Metadata["history_notification_count"] != "3" || resource.Metadata["history_average_duration_seconds"] != "210" || resource.Metadata["history_unrecovered_ratio"] != "0.3333" || resource.Metadata["history_notifications_per_event"] != "1.0000" || resource.Metadata["history_recovery_notification_observed_count"] != "2" || resource.Metadata["history_recovery_notification_disabled_count"] != "1" || resource.Metadata["history_recovery_notification_enabled_count"] != "1" || resource.Metadata["history_recovery_notification_all_disabled"] != "false" || resource.Metadata["history_severity_variant_count"] != "2" || resource.Metadata["history_notification_route_observed_count"] != "3" || resource.Metadata["history_notification_route_variant_count"] != "2" {
				t.Fatalf("expected N9E historical alert aggregation, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeAlertRule && resource.Name == "DatabaseUnavailable" {
			if resource.Metadata["history_observed"] != "true" || resource.Metadata["history_window_hours"] != "24" || resource.Metadata["history_event_count"] != "0" || resource.Metadata["history_notification_count"] != "0" || resource.Metadata["history_events_truncated"] != "false" {
				t.Fatalf("expected zero-event N9E history baseline, got %#v", resource.Metadata)
			}
		}
		encodedMetadata, err := json.Marshal(resource.Metadata)
		if err != nil {
			t.Fatalf("marshal resource metadata: %v", err)
		}
		for _, secret := range []string{"secret@example.com", "super-secret-token", "secret.example", "secret-tenant", "history-secret-fingerprint", "secret-history-tenant", "secret-trigger-value"} {
			if strings.Contains(string(encodedMetadata), secret) {
				t.Fatalf("expected notification params to be discarded, found %q in %#v", secret, resource.Metadata)
			}
		}
	}
}

func TestN9EConnectorKeepsRuleSyncWhenDatasourceBriefIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom/rules" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":1,"name":"AlwaysUp","prom_ql":"up"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	connector, err := NewN9EConnector(server.URL, "", "/custom/rules")
	if err != nil {
		t.Fatalf("new n9e connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("expected optional datasource failure not to block rules: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeInstance {
			if resource.Metadata[model.MetadataN9ECurrentAlertDiscoveryAvailable] != "false" ||
				resource.Metadata[model.MetadataN9EHistoryDiscoveryAvailable] != "false" {
				t.Fatalf("expected unavailable event discovery coverage, got %#v", resource.Metadata)
			}
		}
		if resource.Type == model.ResourceTypeAlertRule && resource.Metadata["history_observed"] != "" {
			t.Fatalf("history endpoint failure must not create an observed baseline, got %#v", resource.Metadata)
		}
	}
	if len(snapshot.Diagnostics) != 7 {
		t.Fatalf("expected optional discovery diagnostics, got %#v", snapshot.Diagnostics)
	}
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.Status != model.ExecutionStatusWarning || diagnostic.Metadata["optional"] != "true" {
			t.Fatalf("expected unavailable optional endpoint warning, got %#v", diagnostic)
		}
	}
}

func TestN9EHistoricalEventsAreCappedAndMarkedTruncated(t *testing.T) {
	const historyEventLimit = 1500
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != n9eHistoryEventsPath {
			http.NotFound(w, r)
			return
		}
		requests++
		if r.URL.Query().Get("hours") != "6" {
			t.Fatalf("expected custom history window, got %q", r.URL.RawQuery)
		}
		expectedPageSize := n9eEventPageSize
		if requests == 2 {
			expectedPageSize = historyEventLimit - n9eEventPageSize
		}
		if r.URL.Query().Get("limit") != strconv.Itoa(expectedPageSize) {
			t.Fatalf("expected bounded page size %d, got %q", expectedPageSize, r.URL.RawQuery)
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("p"))
		rows := make([]map[string]any, expectedPageSize)
		for index := range rows {
			rows[index] = map[string]any{"id": (page-1)*n9eEventPageSize + index + 1, "rule_id": 1, "rule_name": "NoisyRule"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"dat": map[string]any{"list": rows, "total": historyEventLimit + 50}})
	}))
	defer server.Close()

	connector, err := NewN9EConnectorWithGovernanceOptions(server.URL, "", 6, historyEventLimit, HTTPOptions{})
	if err != nil {
		t.Fatalf("new n9e connector: %v", err)
	}
	payload, ok := connector.fetchHistoricalEvents(context.Background())
	if !ok {
		t.Fatal("expected historical event fetch to succeed")
	}
	root := payload.(map[string]any)
	if got := len(root["list"].([]any)); got != historyEventLimit {
		t.Fatalf("expected history cap %d, got %d", historyEventLimit, got)
	}
	if root["window_hours"] != 6 || root["truncated"] != true || requests != 2 {
		t.Fatalf("expected truncated history after bounded pages, payload=%#v requests=%d", root["truncated"], requests)
	}
}

func TestN9ESnapshotFromOfficialRulePayload(t *testing.T) {
	payload := []byte(`{
		"dat": [
			{
				"id": 101,
				"group_id": 12,
				"name": "APIHighLatency",
				"cate": "prometheus",
				"datasource_ids": [7, 8],
				"rule_config": {"queries": [{"prom_ql": "histogram_quantile(0.99, rate(api_latency_seconds_bucket[5m])) > 1"}]},
				"prom_for_duration": 300,
				"disabled": 0
			},
			{
				"id": 102,
				"group_id": 12,
				"name": "WorkerQueueBacklog",
				"datasource_ids": "[9,10]",
				"rule_config": "{\"queries\":[{\"prom_ql\":\"worker_jobs_queued > 100\"}]}",
				"disabled": 1
			}
		]
	}`)

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	snapshot, err := n9eSnapshotFromPayload(decoded, "http://n9e.example", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("snapshot from payload: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 4)
	for _, datasource := range []string{"7", "8", "9", "10"} {
		assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, map[string]string{"7": "APIHighLatency", "8": "APIHighLatency", "9": "WorkerQueueBacklog", "10": "WorkerQueueBacklog"}[datasource], model.ResourceTypeDatasource, datasource)
	}
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "WorkerQueueBacklog", model.ResourceTypeMetric, "worker_jobs_queued")

	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeAlertRule {
			continue
		}
		switch resource.Name {
		case "APIHighLatency":
			if resource.Metadata[model.MetadataAlertFor] != "300" || resource.Metadata[model.MetadataEnabled] != "true" || resource.Metadata["datasource_count"] != "2" {
				t.Fatalf("expected native duration, enabled state, and datasource count, got %#v", resource.Metadata)
			}
		case "WorkerQueueBacklog":
			if resource.Status != model.ResourceStatusDeprecated || resource.Metadata[model.MetadataPromQL] != "worker_jobs_queued > 100" {
				t.Fatalf("expected JSON string config and disabled state to be mapped, got status=%s metadata=%#v", resource.Status, resource.Metadata)
			}
		}
	}
}

func TestN9ESnapshotFromPayload(t *testing.T) {
	payload := []byte(`{
		"dat": {
			"list": [
				{
					"id": 42,
					"name": "APIHighErrorRate",
					"promql": "sum(rate(http_requests_total[5m])) > 10",
					"severity": "warning",
					"team": "platform",
					"owner_name": "sre-oncall",
					"datasource_id": 7,
					"datasource_name": "prod-prometheus",
					"cluster": "prod-a",
					"group_name": "api",
					"duration": "5m",
					"runbook_url": "https://runbook.example/api-high-error-rate",
					"annotations": {"summary": "API has high 5xx rate"},
					"created_at": "2024-01-02T03:04:05Z",
					"update_time": 1710123456,
					"enable": 1
				},
				{
					"id": 43,
					"name": "LegacyAlert",
					"expr": "legacy_errors_total > 0",
					"disabled": true
				}
			]
		}
	}`)

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	snapshot, err := n9eSnapshotFromPayload(decoded, "http://n9e.example", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("snapshot from payload: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 1)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, model.ResourceTypeMetric)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIHighErrorRate", model.ResourceTypeDatasource, "prod-prometheus")

	var foundDisabled bool
	var foundAnnotation bool
	var foundMetadata bool
	var foundDatasource bool
	var foundQueryLength bool
	var foundTimestamps bool
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeDatasource && resource.Name == "prod-prometheus" {
			foundDatasource = resource.Metadata[model.MetadataDatasourceUID] == "7" &&
				resource.Metadata[model.MetadataDatasourceType] == "prometheus" &&
				resource.Metadata["datasource_id"] == "7" &&
				resource.Metadata["datasource_name"] == "prod-prometheus" &&
				resource.Metadata["created_at"] == "2024-01-02T03:04:05Z" &&
				resource.Metadata[model.MetadataUpdatedAt] == "2024-03-11T02:17:36Z"
		}
		if resource.Type != model.ResourceTypeAlertRule {
			continue
		}
		if resource.Name == "LegacyAlert" && resource.Status == model.ResourceStatusDeprecated {
			foundDisabled = true
		}
		if resource.Name == "APIHighErrorRate" && resource.Metadata["annotation.summary"] == "API has high 5xx rate" {
			foundAnnotation = true
		}
		if resource.Name == "APIHighErrorRate" {
			foundQueryLength = resource.Metadata[model.MetadataQueryLength] != ""
			foundTimestamps = resource.Metadata["created_at"] == "2024-01-02T03:04:05Z" &&
				resource.Metadata[model.MetadataUpdatedAt] == "2024-03-11T02:17:36Z" &&
				resource.CreatedAt.Format(time.RFC3339) == "2024-01-02T03:04:05Z" &&
				resource.UpdatedAt.Format(time.RFC3339) == "2024-03-11T02:17:36Z"
			foundMetadata = resource.Labels["severity"] == "warning" &&
				resource.Labels["team"] == "platform" &&
				resource.Labels[model.MetadataOwner] == "sre-oncall" &&
				resource.Metadata["datasource_id"] == "7" &&
				resource.Metadata["datasource_name"] == "prod-prometheus" &&
				resource.Metadata["cluster"] == "prod-a" &&
				resource.Metadata[model.MetadataOwner] == "sre-oncall" &&
				resource.Metadata["group_name"] == "api" &&
				resource.Metadata[model.MetadataRuleGroup] == "api" &&
				resource.Metadata["for"] == "5m" &&
				resource.Metadata["runbook_url"] == "https://runbook.example/api-high-error-rate"
		}
	}
	if !foundDisabled {
		t.Fatalf("expected disabled alert to be marked deprecated")
	}
	if !foundAnnotation {
		t.Fatalf("expected annotations to be mapped")
	}
	if !foundMetadata {
		t.Fatalf("expected n9e rule metadata and inline labels to be mapped")
	}
	if !foundDatasource {
		t.Fatalf("expected n9e datasource resource metadata to be mapped")
	}
	if !foundQueryLength {
		t.Fatalf("expected n9e query length metadata to be mapped")
	}
	if !foundTimestamps {
		t.Fatalf("expected n9e rule timestamps to be mapped")
	}
}

func TestN9ESnapshotFromPayloadSupportsFlexibleRuleShapes(t *testing.T) {
	payload := []byte(`{
		"data": {
			"items": [
				{
					"ident": "direct-promql",
					"rule_name": "DirectPromQL",
					"prom_ql": "sum(rate(worker_jobs_total[1m])) by (queue) > 100",
					"datasourceId": "prom-main",
					"tags": [
						"team=workers",
						{"key": "service", "value": "job-runner"}
					],
					"enable": true
				},
				{
					"uuid": "nested-query",
					"title": "NestedQuery",
					"queries": [
						{"promQl": "histogram_quantile(0.99, rate(api_latency_seconds_bucket[5m])) > 1"}
					],
					"labels": [
						{"name": "severity", "value": "critical"}
					],
					"enable": true
				}
			]
		}
	}`)

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	snapshot, err := n9eSnapshotFromPayload(decoded, "http://n9e.example", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("snapshot from payload: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 1)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "DirectPromQL", model.ResourceTypeMetric, "worker_jobs_total")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "DirectPromQL", model.ResourceTypeDatasource, "prom-main")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "NestedQuery", model.ResourceTypeMetric, "api_latency_seconds_bucket")

	var foundDirectLabels bool
	var foundNestedSeverity bool
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeAlertRule {
			continue
		}
		if resource.Name == "DirectPromQL" {
			foundDirectLabels = resource.Labels["team"] == "workers" &&
				resource.Labels["service"] == "job-runner" &&
				resource.Metadata[model.MetadataPromQL] == "sum(rate(worker_jobs_total[1m])) by (queue) > 100"
		}
		if resource.Name == "NestedQuery" {
			foundNestedSeverity = resource.Labels["severity"] == "critical" &&
				resource.Metadata[model.MetadataPromQL] == "histogram_quantile(0.99, rate(api_latency_seconds_bucket[5m])) > 1"
		}
	}
	if !foundDirectLabels {
		t.Fatalf("expected direct prom_ql rule labels and query to be mapped")
	}
	if !foundNestedSeverity {
		t.Fatalf("expected nested query and array labels to be mapped")
	}
}

func TestN9ESnapshotFromPayloadMapsRecordingRuleOutput(t *testing.T) {
	payload := []byte(`{
		"data": [
			{
				"id": "recording-1",
				"cate": "recording",
				"record": "job:http_requests:rate5m",
				"queries": [
					{"expr": "sum(rate(http_requests_total[5m])) by (job)"}
				],
				"datasource_name": "prod-prometheus",
				"enable": true
			}
		]
	}`)

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	snapshot, err := n9eSnapshotFromPayload(decoded, "http://n9e.example", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("snapshot from payload: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeRecordingRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 1)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeRecordingRule, "job:http_requests:rate5m", model.ResourceTypeMetric, "http_requests_total")
	assertRelationshipByName(t, snapshot, model.RelationshipProduces, model.ResourceTypeRecordingRule, "job:http_requests:rate5m", model.ResourceTypeMetric, "job:http_requests:rate5m")
	assertRelationshipByName(t, snapshot, model.RelationshipProduces, model.ResourceTypeMetric, "http_requests_total", model.ResourceTypeMetric, "job:http_requests:rate5m")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeRecordingRule, "job:http_requests:rate5m", model.ResourceTypeDatasource, "prod-prometheus")

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeRecordingRule && resource.Name == "job:http_requests:rate5m" {
			if resource.Metadata[model.MetadataRecordingRuleOutput] != "job:http_requests:rate5m" {
				t.Fatalf("expected recording rule output metadata, got %#v", resource.Metadata)
			}
			return
		}
	}
	t.Fatalf("expected recording rule resource")
}
