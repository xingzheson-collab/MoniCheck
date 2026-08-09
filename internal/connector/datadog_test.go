package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestDatadogConnectorMapsGovernanceMetadataWithoutSensitivePayloads(t *testing.T) {
	t.Parallel()
	var monitorCalls, serviceCalls, notificationRuleCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DD-API-KEY") != "api-secret" || r.Header.Get("DD-APPLICATION-KEY") != "app-secret" {
			t.Fatalf("missing Datadog authentication headers")
		}
		switch r.URL.Path {
		case "/api/v1/monitor":
			monitorCalls++
			if r.URL.Query().Get("page") != "0" || r.URL.Query().Get("page_size") != "100" ||
				r.URL.Query().Get("with_downtimes") != "true" {
				t.Fatalf("unexpected monitor query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{
				"id":42,"name":"Checkout availability","type":"metric alert","overall_state":"No Data",
				"priority":1,"query":"avg(last_5m):secret.metric{customer:private} < 1",
				"message":"notify @pagerduty-private https://runbook.private.example",
				"tags":["service:checkout","team:payments","customer:private","env:prod","routing:private-routing-secret"],
				"created":"2026-01-01T00:00:00Z","modified":"2026-01-02T00:00:00Z",
				"restricted_roles":["private-role-id"],"matching_downtimes":[{"id":"private-downtime"}],
				"assets":[{"category":"runbook","url":"https://private.example/runbook"}],
				"options":{"notify_no_data":true,"no_data_timeframe":10,"renotify_interval":30,"renotify_occurrences":3,
					"thresholds":{"critical":80,"critical_recovery":73.123456}}
			}]`))
		case "/api/v2/services/definitions":
			serviceCalls++
			if r.URL.Query().Get("page[number]") != "0" || r.URL.Query().Get("page[size]") != "100" {
				t.Fatalf("unexpected service query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":[{
				"id":"checkout","attributes":{"schema":{"dd-service":"checkout","team":"payments",
				"lifecycle":"production","application":"commerce","tier":"1",
				"contacts":[{"type":"slack","contact":"private-channel"}],
				"links":[{"type":"runbook","url":"https://private.example/service-runbook"}],
				"integrations":{"pagerduty":{"service-url":"private"}}}}}]}`))
		case "/api/v2/monitor/notification_rule":
			notificationRuleCalls++
			if r.URL.Query().Get("page") != "0" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("unexpected notification rule query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":[{
				"id":"private-notification-rule-id","attributes":{"name":"Checkout routing",
				"filter":{"tags":["service:checkout","routing:private-routing-secret"]},"recipients":["private-notification-recipient"]}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	item, err := NewDatadogConnectorWithOptions(server.URL, HTTPOptions{
		Headers: map[string]string{
			"DD-API-KEY":         "api-secret",
			"DD-APPLICATION-KEY": "app-secret",
		},
		MaxRetries: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if item.ID() != datadogSystem || item.Name() != "Datadog Connector" ||
		snapshot.Partial || monitorCalls != 1 || serviceCalls != 1 || notificationRuleCalls != 1 ||
		len(snapshot.Resources) != 3 || len(snapshot.Relationships) != 2 || len(snapshot.Diagnostics) != 2 {
		t.Fatalf("unexpected snapshot %#v calls=%d/%d/%d", snapshot, monitorCalls, serviceCalls, notificationRuleCalls)
	}
	var monitor, service, notificationPolicy model.Resource
	for _, resource := range snapshot.Resources {
		switch resource.Type {
		case model.ResourceTypeAlertRule:
			monitor = resource
		case model.ResourceTypeService:
			service = resource
		case model.ResourceTypeNotificationPolicy:
			notificationPolicy = resource
		}
	}
	if monitor.Source.System != datadogSystem ||
		monitor.Metadata[model.MetadataDatadogOverallState] != "No Data" ||
		monitor.Metadata[model.MetadataDatadogRunbookConfigured] != "true" ||
		monitor.Metadata[model.MetadataDatadogRenotifyInterval] != "30" ||
		monitor.Metadata[model.MetadataDatadogNoDataNotificationEvaluable] != "true" ||
		monitor.Metadata[model.MetadataDatadogNoDataNotificationConfigured] != "true" ||
		monitor.Metadata[model.MetadataDatadogDirectNotificationConfigured] != "true" ||
		monitor.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] != "true" ||
		monitor.Metadata[model.MetadataDatadogNotificationCoverageConfigured] != "true" ||
		monitor.Metadata[model.MetadataDatadogNotificationRuleMatchedCount] != "1" ||
		monitor.Metadata[model.MetadataDatadogCriticalRecoveryEvaluable] != "true" ||
		monitor.Metadata[model.MetadataDatadogCriticalRecoveryConfigured] != "true" ||
		monitor.Labels[model.MetadataService] != "checkout" ||
		monitor.Labels["customer"] != "" {
		t.Fatalf("unexpected monitor %#v", monitor)
	}
	if service.Metadata[model.MetadataDatadogTeamDeclared] != "true" ||
		service.Metadata[model.MetadataDatadogRunbookConfigured] != "true" ||
		service.Labels["team"] != "payments" {
		t.Fatalf("unexpected service %#v", service)
	}
	if notificationPolicy.Metadata[model.MetadataDatadogNotificationRule] != "true" ||
		notificationPolicy.Metadata[model.MetadataDatadogNotificationRecipientCount] != "1" ||
		notificationPolicy.Metadata[model.MetadataDatadogNotificationFilterTagCount] != "2" ||
		notificationPolicy.Metadata[model.MetadataDatadogNotificationScopeDeclared] != "false" ||
		notificationPolicy.Metadata[model.MetadataDatadogConditionalRecipientsDeclared] != "false" ||
		notificationPolicy.Metadata[model.MetadataDatadogNotificationConditionCount] != "0" ||
		notificationPolicy.Metadata[model.MetadataDatadogNotificationFallbackRecipientCount] != "0" {
		t.Fatalf("unexpected notification policy %#v", notificationPolicy)
	}
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"api-secret", "app-secret", "secret.metric", "customer:private",
		"pagerduty-private", "private.example", "private-role-id", "private-downtime",
		"private-channel", `"service-url":"private"`,
		"private-notification-rule-id", "private-notification-recipient",
		"private-routing-secret", "73.123456",
	} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, serialized)
		}
	}
}

func TestDatadogConditionalNotificationCoverage(t *testing.T) {
	tests := []struct {
		name       string
		match      datadogNotificationRuleMatch
		tags       []string
		configured bool
		evaluable  bool
	}{
		{
			name:       "direct recipients",
			match:      datadogNotificationRuleMatch{DirectRecipientCount: 1},
			configured: true,
			evaluable:  true,
		},
		{
			name: "alert transition",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{Conditions: []datadogConditionalRecipientCondition{
					{Scope: "transition_type:is_alert", Recipients: []string{"private-alert-recipient"}},
				}},
			},
			configured: true,
			evaluable:  true,
		},
		{
			name: "warning transition does not cover alert",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{Conditions: []datadogConditionalRecipientCondition{
					{Scope: "transition_type:is_warning", Recipients: []string{"private-warning-recipient"}},
				}},
			},
			evaluable: true,
		},
		{
			name: "matching tag condition",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{Conditions: []datadogConditionalRecipientCondition{
					{Scope: "env:prod", Recipients: []string{"private-tag-recipient"}},
				}},
			},
			tags:       []string{"service:checkout", "env:prod"},
			configured: true,
			evaluable:  true,
		},
		{
			name: "non matching tag condition",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{Conditions: []datadogConditionalRecipientCondition{
					{Scope: "env:prod", Recipients: []string{"private-tag-recipient"}},
				}},
			},
			tags:      []string{"env:stage"},
			evaluable: true,
		},
		{
			name: "fallback recipients",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{
					FallbackRecipients: []string{"private-fallback-recipient"},
				},
			},
			configured: true,
			evaluable:  true,
		},
		{
			name: "future transition remains unknown",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{Conditions: []datadogConditionalRecipientCondition{
					{Scope: "transition_type:is_future", Recipients: []string{"private-future-recipient"}},
				}},
			},
		},
		{
			name: "boolean tag scope remains unknown",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: true,
				ConditionalRecipients: datadogConditionalRecipients{Conditions: []datadogConditionalRecipientCondition{
					{Scope: "env:prod AND service:checkout", Recipients: []string{"private-complex-recipient"}},
				}},
			},
		},
		{
			name: "malformed conditional recipients",
			match: datadogNotificationRuleMatch{
				ConditionalDeclared:  true,
				ConditionalEvaluable: false,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configured, evaluable := test.match.notificationCoverage(test.tags)
			if configured != test.configured || evaluable != test.evaluable {
				t.Fatalf("got configured/evaluable %v/%v, want %v/%v", configured, evaluable, test.configured, test.evaluable)
			}
		})
	}
}

func TestDatadogConditionalNotificationRuleMetadataIsPrivacySafe(t *testing.T) {
	var rule datadogNotificationRule
	rule.ID = "private-conditional-rule-id"
	rule.Attributes.Name = "Conditional routing"
	rule.Attributes.Filter = json.RawMessage(`{"tags":["service:checkout"]}`)
	rule.Attributes.ConditionalRecipients = json.RawMessage(`{
		"conditions":[{"scope":"transition_type:is_alert","recipients":["private-alert-recipient"]}],
		"fallback_recipients":["private-fallback-recipient"]
	}`)
	connector := &DatadogConnector{baseURL: "https://api.datadoghq.com"}
	match := connector.notificationRuleMatch(rule, time.Now().UTC())
	if !match.FilterSimple || !match.ConditionalDeclared || !match.ConditionalEvaluable ||
		!match.HasPotentialCoverage ||
		match.Resource.Metadata[model.MetadataDatadogNotificationConditionCount] != "1" ||
		match.Resource.Metadata[model.MetadataDatadogNotificationFallbackRecipientCount] != "1" {
		t.Fatalf("unexpected conditional rule %#v", match)
	}
	serialized, err := json.Marshal(match.Resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"private-conditional-rule-id", "transition_type:is_alert",
		"private-alert-recipient", "private-fallback-recipient", "service:checkout",
	} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("resource leaked %q: %s", secret, serialized)
		}
	}
}

func TestDatadogCriticalRecoveryThresholdNormalization(t *testing.T) {
	tests := []struct {
		name        string
		monitorType string
		thresholds  string
		evaluable   bool
		configured  bool
	}{
		{name: "missing thresholds", monitorType: "metric alert", evaluable: true},
		{name: "critical recovery", monitorType: "metric alert", thresholds: `{"critical":80,"critical_recovery":0}`, evaluable: true, configured: true},
		{name: "dynamic critical recovery", monitorType: "metric alert", thresholds: `{"critical_recovery_query":"query1"}`, evaluable: true, configured: true},
		{name: "empty dynamic critical recovery", monitorType: "metric alert", thresholds: `{"critical_recovery_query":" "}`, evaluable: true},
		{name: "warning recovery only", monitorType: "metric alert", thresholds: `{"warning_recovery":70}`, evaluable: true},
		{name: "null critical recovery", monitorType: "metric alert", thresholds: `{"critical_recovery":null}`, evaluable: true},
		{name: "malformed critical recovery", monitorType: "metric alert", thresholds: `{"critical_recovery":"private-threshold"}`},
		{name: "non metric monitor", monitorType: "service check", thresholds: `{"critical_recovery":70}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var monitor datadogMonitor
			monitor.Type = test.monitorType
			monitor.Options.Thresholds = json.RawMessage(test.thresholds)
			evaluable, configured := datadogCriticalRecoveryThreshold(monitor)
			if evaluable != test.evaluable || configured != test.configured {
				t.Fatalf("got evaluable/configured %v/%v, want %v/%v", evaluable, configured, test.evaluable, test.configured)
			}
		})
	}
}

func TestDatadogNoDataNotificationNormalization(t *testing.T) {
	boolPtr := func(value bool) *bool { return &value }
	tests := []struct {
		name       string
		modern     string
		legacy     *bool
		evaluable  bool
		configured bool
	}{
		{name: "modern notify", modern: "show_and_notify_no_data", legacy: boolPtr(false), evaluable: true, configured: true},
		{name: "modern show only overrides legacy", modern: "show_no_data", legacy: boolPtr(true), evaluable: true, configured: false},
		{name: "modern resolve", modern: "resolve", evaluable: true, configured: false},
		{name: "legacy notify", legacy: boolPtr(true), evaluable: true, configured: true},
		{name: "legacy disabled", legacy: boolPtr(false), evaluable: true, configured: false},
		{name: "absent", evaluable: false, configured: false},
		{name: "future enum", modern: "future_mode", evaluable: false, configured: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var monitor datadogMonitor
			monitor.Options.OnMissingData = test.modern
			monitor.Options.NotifyNoData = test.legacy
			evaluable, configured := datadogNoDataNotification(monitor)
			if evaluable != test.evaluable || configured != test.configured {
				t.Fatalf("got evaluable/configured %v/%v, want %v/%v", evaluable, configured, test.evaluable, test.configured)
			}
		})
	}
}

func TestDatadogNotificationRuleCoverageSuppressesComplexScopeConclusions(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/monitor":
			_, _ = w.Write([]byte(`[
				{"id":1,"name":"Checkout","priority":1,"tags":["service:checkout"],"message":"no direct recipient"},
				{"id":2,"name":"Billing","priority":1,"tags":["service:billing"],"message":"no direct recipient"}
			]`))
		case "/api/v2/services/definitions":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/api/v2/monitor/notification_rule":
			_, _ = w.Write([]byte(`{"data":[
				{"id":"simple","attributes":{"name":"Checkout rule","filter":{"tags":["service:checkout"]},"recipients":["team"]}},
				{"id":"complex","attributes":{"name":"Complex rule","filter":{"scope":"service:billing AND env:prod"},"recipients":["team"]}}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	item, err := NewDatadogConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var checkout, billing model.Resource
	for _, resource := range snapshot.Resources {
		switch resource.Name {
		case "Checkout":
			checkout = resource
		case "Billing":
			billing = resource
		}
	}
	if checkout.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] != "true" ||
		checkout.Metadata[model.MetadataDatadogNotificationCoverageConfigured] != "true" ||
		checkout.Metadata[model.MetadataDatadogNotificationRuleMatchedCount] != "1" {
		t.Fatalf("unexpected simple-rule coverage %#v", checkout.Metadata)
	}
	if billing.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] != "false" ||
		billing.Metadata[model.MetadataDatadogNotificationCoverageConfigured] != "false" ||
		billing.Metadata[model.MetadataDatadogNotificationRuleMatchedCount] != "0" {
		t.Fatalf("complex scope should remain unevaluable %#v", billing.Metadata)
	}
}

func TestDatadogConditionalNotificationRulesRefineMonitorCoverage(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/monitor":
			_, _ = w.Write([]byte(`[
				{"id":1,"name":"Checkout","priority":1,"tags":["service:checkout"],"message":"no direct recipient"},
				{"id":2,"name":"Billing","priority":1,"tags":["service:billing"],"message":"no direct recipient"}
			]`))
		case "/api/v2/services/definitions":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/api/v2/monitor/notification_rule":
			_, _ = w.Write([]byte(`{"data":[
				{"id":"alert","attributes":{"name":"Checkout alerts","filter":{"tags":["service:checkout"]},
					"conditional_recipients":{"conditions":[{"scope":"transition_type:is_alert","recipients":["private-alert-recipient"]}]}}},
				{"id":"warning","attributes":{"name":"Billing warnings","filter":{"tags":["service:billing"]},
					"conditional_recipients":{"conditions":[{"scope":"transition_type:is_warning","recipients":["private-warning-recipient"]}]}}}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	item, err := NewDatadogConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var checkout, billing model.Resource
	for _, resource := range snapshot.Resources {
		switch resource.Name {
		case "Checkout":
			checkout = resource
		case "Billing":
			billing = resource
		}
	}
	if checkout.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] != "true" ||
		checkout.Metadata[model.MetadataDatadogNotificationCoverageConfigured] != "true" ||
		checkout.Metadata[model.MetadataDatadogNotificationRuleMatchedCount] != "1" {
		t.Fatalf("unexpected alert-transition coverage %#v", checkout.Metadata)
	}
	if billing.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] != "true" ||
		billing.Metadata[model.MetadataDatadogNotificationCoverageConfigured] != "false" ||
		billing.Metadata[model.MetadataDatadogNotificationRuleMatchedCount] != "0" {
		t.Fatalf("warning-only rule should leave alert coverage evaluable and absent %#v", billing.Metadata)
	}
	if len(snapshot.Relationships) != 1 {
		t.Fatalf("expected one conditional coverage relationship, got %#v", snapshot.Relationships)
	}
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"private-alert-recipient", "private-warning-recipient",
		"transition_type:is_alert", "transition_type:is_warning",
	} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, serialized)
		}
	}
}

func TestDatadogConnectorKeepsMonitorsWhenServiceCatalogFails(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/monitor" {
			_, _ = w.Write([]byte(`[{"id":7,"name":"Worker errors","overall_state":"OK","tags":[]}]`))
			return
		}
		http.Error(w, `{"errors":["private permission detail"]}`, http.StatusForbidden)
	}))
	defer server.Close()

	item, err := NewDatadogConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Partial || len(snapshot.Resources) != 1 || len(snapshot.Diagnostics) != 2 ||
		snapshot.Diagnostics[0].Status != model.ExecutionStatusWarning ||
		snapshot.Diagnostics[1].Status != model.ExecutionStatusWarning ||
		strings.Contains(snapshot.Diagnostics[0].Message, "private permission") ||
		strings.Contains(snapshot.Diagnostics[1].Message, "private permission") {
		t.Fatalf("unexpected partial snapshot %#v", snapshot)
	}
}

func TestDatadogConnectorRejectsURLUserinfo(t *testing.T) {
	t.Parallel()
	if _, err := NewDatadogConnectorWithOptions("https://reader:secret@datadoghq.com", HTTPOptions{}); err == nil {
		t.Fatal("expected URL userinfo to be rejected")
	}
}
