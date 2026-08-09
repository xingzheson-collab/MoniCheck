package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestAlertmanagerConnectorSyncWithOptionalEnrichment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/alerts":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v2/status":
			_, _ = w.Write([]byte(`{"cluster":{"name":"private-cluster","status":"ready","peers":[{"name":"am-a","address":"10.0.0.1:9094"},{"name":"am-b","address":"10.0.0.2:9094"}]},"versionInfo":{"version":"0.28.1"},"uptime":"2026-07-25T00:00:00Z","config":{"original":"route:\n  receiver: default\nreceivers:\n- name: default\n"}}`))
		case "/api/v2/silences":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewAlertmanagerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if snapshot.Partial {
		t.Fatal("expected successful optional enrichment to produce a complete snapshot")
	}
	if len(snapshot.Diagnostics) != 2 {
		t.Fatalf("expected two optional endpoint diagnostics, got %#v", snapshot.Diagnostics)
	}
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.Status != model.ExecutionStatusSucceeded {
			t.Fatalf("expected successful optional endpoint diagnostic, got %#v", diagnostic)
		}
	}
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeNotificationPolicy, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeInstance, model.ResourceTypeNotificationPolicy)
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeInstance {
			continue
		}
		if resource.Metadata[model.MetadataAlertmanagerRuntime] != "true" ||
			resource.Metadata[model.MetadataAlertmanagerClusterStatus] != "ready" ||
			resource.Metadata[model.MetadataAlertmanagerClusterEnabled] != "true" ||
			resource.Metadata[model.MetadataAlertmanagerClusterPeerCount] != "2" ||
			resource.Metadata[model.MetadataAlertmanagerVersion] != "0.28.1" ||
			resource.Metadata[model.MetadataAlertmanagerStartedAt] != "2026-07-25T00:00:00Z" {
			t.Fatalf("unexpected Alertmanager runtime metadata: %#v", resource.Metadata)
		}
		for key, value := range resource.Metadata {
			if strings.Contains(value, "private-cluster") || strings.Contains(value, "am-a") || strings.Contains(value, "10.0.0.1") {
				t.Fatalf("Alertmanager peer identity leaked through metadata %q=%q", key, value)
			}
		}
	}
}

func TestAlertmanagerConnectorContinuesWhenOptionalEndpointsAreUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/alerts" {
			_, _ = w.Write([]byte(`[{"labels":{"alertname":"APIHighErrorRate"},"fingerprint":"alert-1","status":{"state":"active"}}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	connector, err := NewAlertmanagerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync with unavailable optional endpoints: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected unavailable optional endpoints to mark snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeAlert, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	if len(snapshot.Diagnostics) != 2 {
		t.Fatalf("expected two optional endpoint diagnostics, got %#v", snapshot.Diagnostics)
	}
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.Status != model.ExecutionStatusWarning || diagnostic.Metadata["error"] == "" {
			t.Fatalf("expected optional endpoint warning with error context, got %#v", diagnostic)
		}
	}
}

func TestAlertmanagerConnectorRequiresAlertDiscovery(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	connector, err := NewAlertmanagerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatal("expected alert discovery failure to fail sync")
	}
}

func TestAlertmanagerConnectorUsesBasicAuthForPrivateIngress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "alert-reader" || password != "alert-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/alerts", "/api/v2/silences":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v2/status":
			_, _ = w.Write([]byte(`{"cluster":{"status":"ready","peers":[]},"versionInfo":{"version":"0.28.1"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	alertmanager, err := NewAlertmanagerConnectorWithOptions(server.URL, HTTPOptions{Username: "alert-reader", Password: "alert-password"})
	if err != nil {
		t.Fatalf("new authenticated connector: %v", err)
	}
	if _, err := alertmanager.Sync(context.Background()); err != nil {
		t.Fatalf("sync through Basic Auth ingress: %v", err)
	}
}

func TestAlertmanagerSnapshotFromAlerts(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	alerts := []alertmanagerAlert{
		{
			Labels: map[string]string{
				"alertname": "APIHighErrorRate",
				"service":   "api",
				"severity":  "warning",
			},
			Annotations: map[string]string{
				"summary": "API has high 5xx rate",
			},
			StartsAt:     now.Add(-time.Hour),
			UpdatedAt:    now.Add(-time.Minute),
			GeneratorURL: "http://prometheus/graph?g0.expr=...",
			Fingerprint:  "am-fingerprint-1",
			Status: alertmanagerAlertStatus{
				State:      "active",
				SilencedBy: []string{"silence-1"},
			},
			Receivers: []alertmanagerAlertReceiver{
				{Name: "pagerduty"},
				{Name: "slack-platform"},
				{Name: "pagerduty"},
			},
		},
	}

	config := `
route:
  receiver: pagerduty
  routes:
  - matchers:
    - service="api"
    receiver: slack-platform
    mute_time_intervals: [maintenance]
    active_time_intervals: [missing-window]
receivers:
- name: pagerduty
  pagerduty_configs:
  - routing_key: redacted
- name: slack-platform
  slack_configs:
  - channel: '#platform'
- name: blackhole
inhibit_rules:
- source_matchers:
  - severity="critical"
  target_matchers:
  - severity=~".*"
  equal: [alertname]
time_intervals:
- name: maintenance
  time_intervals:
  - weekdays: [monday:friday]
- name: unused-window
  time_intervals:
  - weekdays: [saturday]
`
	silences := []alertmanagerSilence{
		{
			ID:        "silence-1",
			StartsAt:  now.Add(-time.Hour),
			EndsAt:    now.Add(24 * time.Hour),
			CreatedBy: "platform",
			Comment:   "maintenance",
			Status:    alertmanagerSilenceStatus{State: "active"},
			Matchers: []alertmanagerMatcher{
				{Name: "service", Value: "api", IsEqual: true},
				{Name: "severity", Value: "warning|critical", IsRegex: true, IsEqual: true},
			},
		},
	}
	snapshot := alertmanagerSnapshotFromAlertsConfigAndSilences(alerts, config, silences, "http://alertmanager.example", now)

	assertResourceCount(t, snapshot, model.ResourceTypeAlert, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeSilence, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 3)
	assertResourceCount(t, snapshot, model.ResourceTypeNotificationPolicy, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeInhibitionRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTimeInterval, 3)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeAlert, model.ResourceTypeAlertRule)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeAlert, model.ResourceTypeSilence)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeAlert, model.ResourceTypeReceiver)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, model.ResourceTypeReceiver)
	assertRelationship(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, model.ResourceTypeTimeInterval)

	var foundAlert bool
	var foundRuleLabels bool
	var foundReceiver bool
	var foundSilence bool
	var foundPolicy bool
	var foundInhibitionRule bool
	var foundDeclaredInterval bool
	var foundUndefinedInterval bool
	for _, resource := range snapshot.Resources {
		switch resource.Type {
		case model.ResourceTypeAlert:
			foundAlert = resource.Name == "APIHighErrorRate" &&
				resource.Source.ExternalID == "alert:am-fingerprint-1" &&
				resource.Metadata[model.MetadataAlertState] == "active" &&
				resource.Metadata[model.MetadataFingerprint] == "am-fingerprint-1" &&
				resource.Metadata[model.MetadataUpdatedAt] == now.Add(-time.Minute).Format(time.RFC3339) &&
				resource.Metadata[model.MetadataReceiverNames] == "pagerduty,slack-platform" &&
				resource.Metadata["annotation.summary"] == "API has high 5xx rate"
		case model.ResourceTypeAlertRule:
			foundRuleLabels = resource.Name == "APIHighErrorRate" &&
				resource.Labels["alertname"] == "APIHighErrorRate" &&
				resource.Labels["severity"] == "warning" &&
				resource.Labels["service"] == "api"
		case model.ResourceTypeReceiver:
			if resource.Name == "pagerduty" &&
				resource.Metadata["declared"] == "true" &&
				resource.Metadata["referenced_by_route"] == "true" &&
				resource.Metadata[model.MetadataReceiverIntegrations] == "pagerduty" &&
				resource.Metadata["seen_in_alerts"] == "true" {
				foundReceiver = true
			}
		case model.ResourceTypeSilence:
			foundSilence = resource.Name == "service=api,severity=~warning|critical" &&
				resource.Metadata[model.MetadataSilenceID] == "silence-1" &&
				resource.Metadata[model.MetadataSilenceState] == "active" &&
				resource.Metadata[model.MetadataSilenceCreatedBy] == "platform" &&
				resource.Metadata[model.MetadataSilenceComment] == "maintenance" &&
				resource.Metadata[model.MetadataSilenceMatchers] == "service=api,severity=~warning|critical" &&
				resource.Metadata[model.MetadataSilenceMatcherCount] == "2" &&
				resource.Metadata[model.MetadataSilencePositiveCount] == "2" &&
				resource.Metadata[model.MetadataSilenceNegativeCount] == "0" &&
				resource.Metadata[model.MetadataSilenceRegexCount] == "1" &&
				resource.Metadata[model.MetadataSilenceMatcherDetails] == `[{"name":"service","value":"api","is_regex":false,"is_equal":true},{"name":"severity","value":"warning|critical","is_regex":true,"is_equal":true}]`
		case model.ResourceTypeNotificationPolicy:
			foundPolicy = resource.Metadata[model.MetadataPolicyDefaultReceiver] == "pagerduty" &&
				resource.Metadata[model.MetadataPolicyRouteCount] == "2" &&
				resource.Metadata[model.MetadataPolicyMaxDepth] == "2" &&
				resource.Metadata[model.MetadataPolicyCatchAllRouteCount] == "0" &&
				resource.Metadata[model.MetadataPolicyShadowedRouteCount] == "0"
		case model.ResourceTypeInhibitionRule:
			foundInhibitionRule = resource.Metadata[model.MetadataInhibitionSourceMatcherCount] == "1" &&
				resource.Metadata[model.MetadataInhibitionTargetMatcherCount] == "1" &&
				resource.Metadata[model.MetadataInhibitionTargetRegexCount] == "1" &&
				resource.Metadata[model.MetadataInhibitionTargetBroadCount] == "1" &&
				resource.Metadata[model.MetadataInhibitionEqualLabelCount] == "1"
		case model.ResourceTypeTimeInterval:
			if resource.Name == "maintenance" && resource.Metadata[model.MetadataTimeIntervalDeclared] == "true" && resource.Metadata[model.MetadataTimeIntervalSpecCount] == "1" && resource.Metadata[model.MetadataTimeIntervalMuteRefCount] == "1" {
				foundDeclaredInterval = true
			}
			if resource.Name == "missing-window" && resource.Metadata[model.MetadataTimeIntervalDeclared] == "false" && resource.Metadata[model.MetadataTimeIntervalActiveRefCount] == "1" {
				foundUndefinedInterval = true
			}
		}
	}
	if !foundAlert {
		t.Fatalf("expected alert resource metadata to be mapped")
	}
	if !foundRuleLabels {
		t.Fatalf("expected alertmanager alert rule labels to include runtime alert labels")
	}
	if !foundReceiver {
		t.Fatalf("expected alertmanager receiver metadata to be mapped")
	}
	if !foundSilence {
		t.Fatalf("expected alertmanager silence metadata to be mapped")
	}
	if !foundPolicy {
		t.Fatalf("expected alertmanager notification policy metadata to be mapped")
	}
	if !foundInhibitionRule {
		t.Fatalf("expected alertmanager inhibition rule metadata to be mapped")
	}
	if !foundDeclaredInterval || !foundUndefinedInterval {
		t.Fatalf("expected declared and undefined Alertmanager time intervals to be mapped")
	}
}

func TestAlertmanagerNotificationTimingStats(t *testing.T) {
	config := `route:
  receiver: default
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 9m
  group_by: [alertname]
  routes:
    - receiver: pager
      repeat_interval: 2m
      group_by: ['...']
    - receiver: email
      group_interval: invalid
`
	stats, ok := alertmanagerRoutingPolicyStats(config)
	if !ok || stats.invalidTimingCount != 2 || stats.roundedRepeatCount != 1 || stats.ungroupedRouteCount != 1 {
		t.Fatalf("unexpected Alertmanager timing stats: %#v, ok=%t", stats, ok)
	}
	resource := alertmanagerResource(model.ResourceTypeNotificationPolicy, "default", "http://alertmanager.test", "notification-policy:default", time.Now().UTC())
	applyRoutingPolicyMetadata(&resource, stats)
	if resource.Metadata[model.MetadataPolicyInvalidTimingCount] != "2" || resource.Metadata[model.MetadataPolicyRoundedRepeatCount] != "1" || resource.Metadata[model.MetadataPolicyUngroupedRouteCount] != "1" {
		t.Fatalf("unexpected Alertmanager timing metadata: %#v", resource.Metadata)
	}
}

func TestAlertmanagerInsecureReceiverEndpointsAreCountedWithoutLeakingURLs(t *testing.T) {
	config := `route:
  receiver: platform
receivers:
  - name: platform
    webhook_configs:
      - url: http://secret.example/hook
      - url: https://secure.example/hook
    slack_configs:
      - api_url: http://secret.example/slack
        text: "see http://docs.example/runbook"
`
	counts := alertmanagerReceiverInsecureEndpointCounts(config)
	if counts["platform"] != 2 {
		t.Fatalf("unexpected Alertmanager insecure endpoint counts: %#v", counts)
	}
	snapshot := alertmanagerSnapshotFromAlertsAndConfig(nil, config, "http://alertmanager.test", time.Now().UTC())
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeReceiver || resource.Name != "platform" {
			continue
		}
		if resource.Metadata[model.MetadataReceiverInsecureEndpointCount] != "2" {
			t.Fatalf("unexpected receiver endpoint metadata: %#v", resource.Metadata)
		}
		for key, value := range resource.Metadata {
			if strings.Contains(value, "secret.example") || strings.Contains(value, "docs.example") {
				t.Fatalf("Alertmanager endpoint leaked through metadata %q=%q", key, value)
			}
		}
		return
	}
	t.Fatal("expected platform receiver")
}

func TestAlertmanagerConfigReceivers(t *testing.T) {
	config := `
route:
  receiver: "default-team"
  routes:
  - receiver: 'payments-team'
receivers:
- name: default-team
  email_configs:
  - to: default@example.com
- name: payments-team
  slack_configs:
  - channel: '#payments'
- name: blackhole
`
	declared, routed, integrations := alertmanagerConfigReceivers(config)
	if !declared["default-team"] || !declared["payments-team"] || !declared["blackhole"] {
		t.Fatalf("expected declared receivers, got %#v", declared)
	}
	if !routed["default-team"] || !routed["payments-team"] || routed["blackhole"] {
		t.Fatalf("expected routed receivers only, got %#v", routed)
	}
	if len(integrations["default-team"]) != 1 || integrations["default-team"][0] != "email" || len(integrations["payments-team"]) != 1 || integrations["payments-team"][0] != "slack" {
		t.Fatalf("expected receiver integrations, got %#v", integrations)
	}
}

func TestAlertmanagerRoutingPolicyStats(t *testing.T) {
	config := `route:
  receiver: default
  routes:
    - receiver: platform
      routes:
        - receiver: pagerduty
receivers:
  - name: default`
	stats, ok := alertmanagerRoutingPolicyStats(config)
	if !ok || stats.defaultReceiver != "default" || stats.routeCount != 3 || stats.maxDepth != 3 || stats.catchAllRouteCount != 2 {
		t.Fatalf("unexpected routing policy stats: %#v, found=%t", stats, ok)
	}
}

func TestAlertmanagerRoutingPolicyStatsAllowsRootReceiverAfterRoutes(t *testing.T) {
	config := `route:
  routes:
    - receiver: platform
  receiver: default
receivers:
  - name: default`
	stats, ok := alertmanagerRoutingPolicyStats(config)
	if !ok || stats.defaultReceiver != "default" || stats.routeCount != 2 || stats.maxDepth != 2 || stats.catchAllRouteCount != 1 {
		t.Fatalf("unexpected reordered routing policy stats: %#v, found=%t", stats, ok)
	}
}

func TestAlertmanagerRoutingPolicyRiskStats(t *testing.T) {
	config := `route:
  receiver: default
  routes:
    - receiver: catch-all
    - receiver: platform
      matchers:
        - team="platform"
      routes:
        - receiver: pagerduty
          matchers:
            - severity="critical"
    - receiver: audit
      matchers:
        - team="audit"
receivers:
  - name: default`
	stats, ok := alertmanagerRoutingPolicyStats(config)
	if !ok || stats.routeCount != 5 || stats.catchAllRouteCount != 1 || stats.shadowedRouteCount != 3 {
		t.Fatalf("unexpected shadowed routing policy stats: %#v, found=%t", stats, ok)
	}

	continueConfig := `route:
  receiver: default
  routes:
    - receiver: fanout
      continue: true
    - receiver: platform
      continue: true
      matchers:
        - team="platform"
      mute_time_intervals: [maintenance]
    - receiver: fallback
      matchers:
        - severity="critical"`
	stats, ok = alertmanagerRoutingPolicyStats(continueConfig)
	if !ok || stats.continueRouteCount != 2 || stats.catchAllContinueCount != 1 || stats.shadowedRouteCount != 0 || stats.timeIntervalRouteCount != 1 {
		t.Fatalf("unexpected fanout routing policy stats: %#v, found=%t", stats, ok)
	}
}

func TestAlertmanagerInhibitionRules(t *testing.T) {
	config := `inhibit_rules:
  - source_matchers: ['severity="critical"', 'cluster=~"prod-.+"']
    target_matchers: ['severity=~".*"']
    equal: [cluster, alertname, cluster]
  - source_match_re:
      namespace: .+
    target_match:
      severity: warning`
	rules := alertmanagerInhibitionRules(config)
	if len(rules) != 2 {
		t.Fatalf("expected two inhibition rules, got %#v", rules)
	}
	if rules[0].sourceMatcherCount != 2 || rules[0].sourceRegexCount != 1 || rules[0].sourceBroadCount != 0 || rules[0].targetBroadCount != 1 || rules[0].equalLabelCount != 2 {
		t.Fatalf("unexpected modern inhibition rule: %#v", rules[0])
	}
	if rules[1].sourceMatcherCount != 1 || rules[1].sourceRegexCount != 1 || rules[1].sourceBroadCount != 1 || rules[1].targetMatcherCount != 1 || rules[1].equalLabelCount != 0 {
		t.Fatalf("unexpected deprecated inhibition rule: %#v", rules[1])
	}
	resource := alertmanagerResource(model.ResourceTypeInhibitionRule, rules[0].name, "http://alertmanager.test", rules[0].externalID, time.Now().UTC())
	applyInhibitionRuleMetadata(&resource, rules[0])
	for key, value := range resource.Metadata {
		if strings.Contains(value, "critical") || strings.Contains(value, "prod-") || strings.Contains(value, ".*") {
			t.Fatalf("inhibition matcher value leaked through metadata %q=%q", key, value)
		}
	}
}
