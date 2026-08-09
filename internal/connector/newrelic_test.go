package connector

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

type newRelicGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

func TestNewRelicConnectorMapsGovernanceWithoutSensitivePayloads(t *testing.T) {
	t.Parallel()
	entityCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("API-Key") != "user-secret" {
			t.Fatalf("missing New Relic API-Key header")
		}
		var request newRelicGraphQLRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.Contains(request.Query, "MoniCheckEntities"):
			entityCalls++
			if request.Variables["query"] != "accountId = 12345 AND type IN ('APPLICATION', 'SERVICE')" {
				t.Fatalf("unexpected entity query %#v", request.Variables)
			}
			if entityCalls == 1 {
				if request.Variables["cursor"] != nil {
					t.Fatalf("first cursor should be null: %#v", request.Variables)
				}
				writeNewRelicTestResponse(t, w, map[string]any{
					"actor": map[string]any{"entitySearch": map[string]any{"results": map[string]any{
						"nextCursor": "opaque-secret-cursor",
						"entities": []any{map[string]any{
							"guid": "private-guid-1", "name": "Checkout", "accountId": 12345,
							"domain": "APM", "type": "APPLICATION", "reporting": false, "alertSeverity": "CRITICAL",
							"tags": []any{
								map[string]any{"key": "team", "values": []string{"payments"}},
								map[string]any{"key": "customer", "values": []string{"private-customer"}},
								map[string]any{"key": "owner", "values": []string{"checkout-oncall", "secondary-private"}},
							},
						}},
					}}},
				})
				return
			}
			if request.Variables["cursor"] != "opaque-secret-cursor" {
				t.Fatalf("cursor was not replayed opaquely: %#v", request.Variables)
			}
			writeNewRelicTestResponse(t, w, map[string]any{
				"actor": map[string]any{"entitySearch": map[string]any{"results": map[string]any{
					"nextCursor": nil, "entities": []any{},
				}}},
			})
		case strings.Contains(request.Query, "MoniCheckPolicies"):
			if request.Variables["accountId"].(float64) != 12345 {
				t.Fatalf("unexpected policy account %#v", request.Variables)
			}
			writeNewRelicTestResponse(t, w, map[string]any{
				"actor": map[string]any{"account": map[string]any{"alerts": map[string]any{"policiesSearch": map[string]any{
					"nextCursor": nil,
					"policies": []any{map[string]any{
						"id": "private-policy-id", "name": "Private policy name", "incidentPreference": "per_condition",
					}},
				}}}},
			})
		case strings.Contains(request.Query, "MoniCheckConditions"):
			if !strings.Contains(request.Query, "titleTemplate") ||
				!strings.Contains(request.Query, "slideBy") ||
				!strings.Contains(request.Query, "evaluationDelay") ||
				!strings.Contains(request.Query, "fillOption") ||
				!strings.Contains(request.Query, "fillValue") ||
				!strings.Contains(request.Query, "threshold") ||
				!strings.Contains(request.Query, "... on AlertsNrqlBaselineCondition") ||
				!strings.Contains(request.Query, "baselineDirection") ||
				!strings.Contains(request.Query, "... on AlertsNrqlStaticCondition") ||
				!strings.Contains(request.Query, "valueFunction") ||
				!strings.Contains(request.Query, "closeViolationsOnExpiration") {
				t.Fatalf("condition query did not request the transient comparison fields: %s", request.Query)
			}
			writeNewRelicTestResponse(t, w, map[string]any{
				"actor": map[string]any{"account": map[string]any{"alerts": map[string]any{"nrqlConditionsSearch": map[string]any{
					"nextCursor": nil,
					"nrqlConditions": []any{map[string]any{
						"id": "private-condition-id", "name": "Checkout latency", "description": "private description",
						"titleTemplate": "{{conditionName}} private checkout title",
						"enabled":       true, "policyId": "private-policy-id", "runbookUrl": "https://private.example/runbook",
						"type": "STATIC", "valueFunction": "SINGLE_VALUE", "violationTimeLimitSeconds": 86400,
						"nrql":       map[string]any{"query": "SELECT privateSecret FROM Transaction WHERE customer='private-customer'"},
						"signal":     map[string]any{"aggregationWindow": 60, "aggregationMethod": "cadence", "aggregationDelay": 120, "aggregationTimer": 0, "evaluationDelay": 900, "fillOption": "static", "fillValue": 2468.13579, "slideBy": 30},
						"expiration": map[string]any{"expirationDuration": 9876, "closeViolationsOnExpiration": false, "openViolationOnExpiration": true},
						"terms": []any{map[string]any{
							"operator": "ABOVE", "threshold": 1234.56789, "thresholdDuration": 300, "priority": "CRITICAL", "thresholdOccurrences": "ALL",
						}},
					}},
				}}}},
			})
		default:
			t.Fatalf("unexpected GraphQL query %s", request.Query)
		}
	}))
	defer server.Close()

	item, err := NewNewRelicConnectorWithOptions(server.URL+"/graphql", 12345, HTTPOptions{
		Headers:    map[string]string{"API-Key": "user-secret"},
		MaxRetries: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if item.ID() != newRelicSystem || item.Name() != "New Relic Connector" ||
		snapshot.Partial || entityCalls != 2 || len(snapshot.Resources) != 2 ||
		len(snapshot.Diagnostics) != 2 {
		t.Fatalf("unexpected snapshot %#v", snapshot)
	}
	var service, condition model.Resource
	for _, resource := range snapshot.Resources {
		switch resource.Type {
		case model.ResourceTypeService:
			service = resource
		case model.ResourceTypeAlertRule:
			condition = resource
		}
	}
	if service.Metadata[model.MetadataNewRelicReporting] != "false" ||
		service.Metadata[model.MetadataNewRelicAlertSeverity] != "CRITICAL" ||
		service.Metadata[model.MetadataNewRelicOwnershipDeclared] != "true" ||
		service.Labels["team"] != "payments" || service.Labels[model.MetadataOwner] != "checkout-oncall" ||
		service.Labels["customer"] != "" {
		t.Fatalf("unexpected service %#v", service)
	}
	if condition.Metadata[model.MetadataNewRelicCriticalTermCount] != "1" ||
		condition.Metadata[model.MetadataNewRelicCriticalAtLeastOnceTermCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicInvalidThresholdValueCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicCriticalThresholdDurationMin] != "300" ||
		condition.Metadata[model.MetadataNewRelicCriticalThresholdDurationMax] != "300" ||
		condition.Metadata[model.MetadataNewRelicInvalidCriticalThresholdDurationCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicInvalidBaselineThresholdDurationCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicBaselineDirectionEvaluable] != "false" ||
		condition.Metadata[model.MetadataNewRelicBaselineDirectionInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicStaticValueFunctionEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicStaticValueFunctionInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicRunbookConfigured] != "true" ||
		condition.Metadata[model.MetadataNewRelicTitleTemplateConfigured] != "true" ||
		condition.Metadata[model.MetadataNewRelicQueryScopeEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicQueryScopeClausePresent] != "true" ||
		condition.Metadata[model.MetadataNewRelicQueryCompatibilityEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicQueryIncompatibleClauseCount] != "0" ||
		condition.Metadata[model.MetadataNewRelicAggregationMethod] != "CADENCE" ||
		condition.Metadata[model.MetadataNewRelicAggregationDelayEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicAggregationDelayInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicSlideByDeclared] != "true" ||
		condition.Metadata[model.MetadataNewRelicSlideBySeconds] != "30" ||
		condition.Metadata[model.MetadataNewRelicSlidingWindowEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicSlidingWindowInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicSlidingWindowOverlapFactor] != "2" ||
		condition.Metadata[model.MetadataNewRelicEventTimerWindowEvaluable] != "false" ||
		condition.Metadata[model.MetadataNewRelicEventTimerShorterThanWindow] != "false" ||
		condition.Metadata[model.MetadataNewRelicIncidentPreference] != "PER_CONDITION" ||
		condition.Metadata[model.MetadataNewRelicLossOfSignalEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicLossOfSignalConfigured] != "true" ||
		condition.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicLossOfSignalDurationShort] != "false" ||
		condition.Metadata[model.MetadataNewRelicLossOfSignalCloseEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicLossOfSignalCloseConfigured] != "false" ||
		condition.Metadata[model.MetadataNewRelicEvaluationDelayDeclared] != "true" ||
		condition.Metadata[model.MetadataNewRelicEvaluationDelaySeconds] != "900" ||
		condition.Metadata[model.MetadataNewRelicEvaluationDelayInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicGapFillOption] != "STATIC" ||
		condition.Metadata[model.MetadataNewRelicGapFillOptionEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicGapFillOptionInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicStaticGapFillValueEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicStaticGapFillValueInvalid] != "false" ||
		condition.Metadata[model.MetadataNewRelicStaticGapFillEvaluable] != "true" ||
		condition.Metadata[model.MetadataNewRelicStaticGapFillCriticalBreachCount] != "1" ||
		condition.Metadata[model.MetadataNewRelicQueryLength] == "0" {
		t.Fatalf("unexpected condition %#v", condition)
	}
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"user-secret", "private-guid-1", "12345", "opaque-secret-cursor",
		"private-policy-id", "Private policy name", "private-condition-id",
		"private description", "private checkout title", "privateSecret", "private-customer",
		"private.example", "secondary-private", "9876", "2468.13579", "1234.56789",
	} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, serialized)
		}
	}
}

func TestNewRelicThresholdValueValidity(t *testing.T) {
	zero := 0.0
	positive := 42.5
	negative := -0.1
	nan := math.NaN()
	positiveInf := math.Inf(1)
	negativeInf := math.Inf(-1)
	tests := []struct {
		name    string
		value   *float64
		invalid bool
	}{
		{name: "missing", invalid: true},
		{name: "zero", value: &zero},
		{name: "positive", value: &positive},
		{name: "negative", value: &negative, invalid: true},
		{name: "nan", value: &nan, invalid: true},
		{name: "positive infinity", value: &positiveInf, invalid: true},
		{name: "negative infinity", value: &negativeInf, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := newRelicThresholdValueInvalid(test.value); got != test.invalid {
				t.Fatalf("invalid=%t want=%t", got, test.invalid)
			}
		})
	}

	var condition newRelicCondition
	if err := json.Unmarshal([]byte(`{"id":"private-threshold","enabled":true,"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":987654.321,"thresholdDuration":300,"thresholdOccurrences":"ALL"},{"priority":"WARNING","operator":"ABOVE","threshold":-1,"thresholdDuration":300,"thresholdOccurrences":"ALL"}]}`), &condition); err != nil {
		t.Fatal(err)
	}
	resource := (&NewRelicConnector{accountID: 1}).conditionResource(condition, newRelicPolicy{}, time.Time{})
	if resource.Metadata[model.MetadataNewRelicInvalidThresholdValueCount] != "1" {
		t.Fatalf("unexpected invalid threshold value count: %#v", resource.Metadata)
	}
	serialized, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "987654.321") {
		t.Fatalf("raw threshold value leaked into persisted resource: %s", serialized)
	}
}

func TestNewRelicQueryScope(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		evaluable   bool
		scopeClause bool
	}{
		{name: "unscoped", query: `SELECT count(*) FROM Transaction`, evaluable: true},
		{name: "where", query: `SELECT count(*) FROM Transaction WHERE appName = 'checkout'`, evaluable: true, scopeClause: true},
		{name: "facet", query: `SELECT count(*) FROM Transaction FACET appName`, evaluable: true, scopeClause: true},
		{name: "filter where only", query: `SELECT filter(count(*), WHERE result = 'FAILED') FROM SyntheticCheck`, evaluable: true},
		{name: "nested query", query: `SELECT max(value) FROM (SELECT average(duration) AS value FROM Transaction WHERE appName = 'checkout')`},
		{name: "malformed", query: `SELECT count(*) FROM Transaction WHERE appName = 'checkout`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluable, scopeClause := newRelicQueryScope(test.query)
			if evaluable != test.evaluable || scopeClause != test.scopeClause {
				t.Fatalf("got evaluable=%t scopeClause=%t, want evaluable=%t scopeClause=%t", evaluable, scopeClause, test.evaluable, test.scopeClause)
			}
		})
	}
}

func TestNewRelicInvalidBaselineThresholdDurationCount(t *testing.T) {
	tests := []struct {
		name      string
		typ       string
		durations []int
		want      int
	}{
		{name: "static ignored", typ: "STATIC", durations: []int{30, 121, 7200}},
		{name: "minimum", typ: "BASELINE", durations: []int{120}},
		{name: "maximum", typ: "BASELINE", durations: []int{3600}},
		{name: "valid warning and critical", typ: "baseline", durations: []int{180, 300}},
		{name: "below minimum", typ: "BASELINE", durations: []int{119}, want: 1},
		{name: "above maximum", typ: "BASELINE", durations: []int{3601}, want: 1},
		{name: "not minute multiple", typ: "BASELINE", durations: []int{121}, want: 1},
		{name: "all invalid", typ: "BASELINE", durations: []int{0, 119, 121, 3601}, want: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var condition newRelicCondition
			condition.Type = test.typ
			for _, duration := range test.durations {
				condition.Terms = append(condition.Terms, struct {
					Operator             string   `json:"operator"`
					Threshold            *float64 `json:"threshold"`
					ThresholdDuration    int      `json:"thresholdDuration"`
					Priority             string   `json:"priority"`
					ThresholdOccurrences string   `json:"thresholdOccurrences"`
				}{ThresholdDuration: duration})
			}
			if got := newRelicInvalidBaselineThresholdDurationCount(condition); got != test.want {
				t.Fatalf("got %d invalid baseline duration(s), want %d", got, test.want)
			}
		})
	}
}

func TestNewRelicBaselineDirectionValidity(t *testing.T) {
	tests := []struct {
		name      string
		typ       string
		direction string
		evaluable bool
		invalid   bool
	}{
		{name: "static ignored", typ: "STATIC", direction: "PRIVATE_DIRECTION"},
		{name: "upper", typ: "BASELINE", direction: "UPPER_ONLY", evaluable: true},
		{name: "lower normalized", typ: "baseline", direction: " lower_only ", evaluable: true},
		{name: "both", typ: "BASELINE", direction: "UPPER_AND_LOWER", evaluable: true},
		{name: "missing", typ: "BASELINE", evaluable: true, invalid: true},
		{name: "unknown", typ: "BASELINE", direction: "PRIVATE_DIRECTION", evaluable: true, invalid: true},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{
				ID:                test.name,
				Name:              test.name,
				Enabled:           true,
				Type:              test.typ,
				BaselineDirection: test.direction,
			}
			evaluable, invalid := newRelicBaselineDirectionValidity(condition)
			if evaluable != test.evaluable || invalid != test.invalid {
				t.Fatalf("got evaluable=%t invalid=%t, want evaluable=%t invalid=%t", evaluable, invalid, test.evaluable, test.invalid)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicBaselineDirectionEvaluable] != strconv.FormatBool(test.evaluable) ||
				resource.Metadata[model.MetadataNewRelicBaselineDirectionInvalid] != strconv.FormatBool(test.invalid) {
				t.Fatalf("unexpected baseline direction metadata: %#v", resource.Metadata)
			}
			serialized, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), "PRIVATE_DIRECTION") {
				t.Fatalf("resource leaked transient baseline direction: %s", serialized)
			}
		})
	}
}

func TestNewRelicStaticValueFunctionValidity(t *testing.T) {
	tests := []struct {
		name          string
		typ           string
		valueFunction string
		evaluable     bool
		invalid       bool
	}{
		{name: "baseline ignored", typ: "BASELINE", valueFunction: "PRIVATE_FUNCTION"},
		{name: "single value", typ: "STATIC", valueFunction: "SINGLE_VALUE", evaluable: true},
		{name: "sum normalized", typ: "static", valueFunction: " sum ", evaluable: true},
		{name: "missing", typ: "STATIC", evaluable: true, invalid: true},
		{name: "unknown", typ: "STATIC", valueFunction: "PRIVATE_FUNCTION", evaluable: true, invalid: true},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{
				ID:            test.name,
				Name:          test.name,
				Enabled:       true,
				Type:          test.typ,
				ValueFunction: test.valueFunction,
			}
			evaluable, invalid := newRelicStaticValueFunctionValidity(condition)
			if evaluable != test.evaluable || invalid != test.invalid {
				t.Fatalf("got evaluable=%t invalid=%t, want evaluable=%t invalid=%t", evaluable, invalid, test.evaluable, test.invalid)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicStaticValueFunctionEvaluable] != strconv.FormatBool(test.evaluable) ||
				resource.Metadata[model.MetadataNewRelicStaticValueFunctionInvalid] != strconv.FormatBool(test.invalid) {
				t.Fatalf("unexpected static value-function metadata: %#v", resource.Metadata)
			}
			serialized, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), "PRIVATE_FUNCTION") {
				t.Fatalf("resource leaked transient static value function: %s", serialized)
			}
		})
	}
}

func TestNewRelicQueryAlertCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		evaluable    bool
		incompatible int
	}{
		{name: "compatible", query: `SELECT count(*) FROM Transaction WHERE appName = 'checkout'`, evaluable: true},
		{name: "incompatible", query: `SELECT count(*) FROM Transaction SINCE 1 hour AGO TIMESERIES 1 minute LIMIT 10`, evaluable: true, incompatible: 3},
		{name: "quoted and function local", query: `SELECT filter(count(*), WHERE note = 'LIMIT') FROM Transaction`, evaluable: true},
		{name: "nested query", query: `SELECT max(value) FROM (SELECT average(duration) AS value FROM Transaction SINCE 1 hour AGO)`},
		{name: "malformed", query: `SELECT count(*) FROM Transaction WHERE appName = 'checkout`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluable, incompatible := newRelicQueryAlertCompatibility(test.query)
			if evaluable != test.evaluable || incompatible != test.incompatible {
				t.Fatalf("got evaluable=%t incompatible=%d, want evaluable=%t incompatible=%d", evaluable, incompatible, test.evaluable, test.incompatible)
			}
		})
	}
}

func TestNewRelicAggregationDelayValidity(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		delay     int
		evaluable bool
		invalid   bool
	}{
		{name: "event flow minimum", method: "event_flow", delay: 0, evaluable: true},
		{name: "event flow maximum", method: "EVENT_FLOW", delay: 1200, evaluable: true},
		{name: "event flow below minimum", method: "EVENT_FLOW", delay: -1, evaluable: true, invalid: true},
		{name: "event flow above maximum", method: "EVENT_FLOW", delay: 1201, evaluable: true, invalid: true},
		{name: "cadence minimum", method: "cadence", delay: 0, evaluable: true},
		{name: "cadence maximum", method: "CADENCE", delay: 3600, evaluable: true},
		{name: "cadence below minimum", method: "CADENCE", delay: -1, evaluable: true, invalid: true},
		{name: "cadence above maximum", method: "CADENCE", delay: 3601, evaluable: true, invalid: true},
		{name: "event timer", method: "EVENT_TIMER", delay: 1201},
		{name: "unknown method", method: "future_method", delay: 1201},
		{name: "missing method", delay: 1201},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{}
			condition.Signal.AggregationMethod = test.method
			condition.Signal.AggregationDelay = test.delay
			evaluable, invalid := newRelicAggregationDelayValidity(condition)
			if evaluable != test.evaluable || invalid != test.invalid {
				t.Fatalf("got evaluable=%t invalid=%t, want evaluable=%t invalid=%t", evaluable, invalid, test.evaluable, test.invalid)
			}
		})
	}
}

func TestNewRelicEventTimerWindowOrder(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		timer     int
		window    int
		evaluable bool
		shorter   bool
	}{
		{name: "shorter", method: "event_timer", timer: 30, window: 60, evaluable: true, shorter: true},
		{name: "equal", method: "EVENT_TIMER", timer: 60, window: 60, evaluable: true},
		{name: "longer", method: "EVENT_TIMER", timer: 90, window: 60, evaluable: true},
		{name: "minimums", method: "EVENT_TIMER", timer: 5, window: 30, evaluable: true, shorter: true},
		{name: "maximums", method: "EVENT_TIMER", timer: 1200, window: 21600, evaluable: true, shorter: true},
		{name: "invalid timer low", method: "EVENT_TIMER", timer: 4, window: 60},
		{name: "invalid timer high", method: "EVENT_TIMER", timer: 1201, window: 60},
		{name: "invalid window low", method: "EVENT_TIMER", timer: 30, window: 29},
		{name: "invalid window high", method: "EVENT_TIMER", timer: 30, window: 21601},
		{name: "event flow", method: "EVENT_FLOW", timer: 30, window: 60},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{}
			condition.Signal.AggregationMethod = test.method
			condition.Signal.AggregationTimer = test.timer
			condition.Signal.AggregationWindow = test.window
			evaluable, shorter := newRelicEventTimerWindowOrder(condition)
			if evaluable != test.evaluable || shorter != test.shorter {
				t.Fatalf("got evaluable=%t shorter=%t, want evaluable=%t shorter=%t", evaluable, shorter, test.evaluable, test.shorter)
			}
		})
	}
}

func TestNewRelicEvaluationDelay(t *testing.T) {
	tests := []struct {
		name     string
		delay    *int
		declared bool
		seconds  int
		invalid  bool
	}{
		{name: "absent"},
		{name: "disabled zero", delay: newRelicIntPointer(0), declared: true},
		{name: "minimum enabled", delay: newRelicIntPointer(1), declared: true, seconds: 1},
		{name: "maximum enabled", delay: newRelicIntPointer(7200), declared: true, seconds: 7200},
		{name: "negative invalid", delay: newRelicIntPointer(-1), declared: true, seconds: -1, invalid: true},
		{name: "above maximum invalid", delay: newRelicIntPointer(7201), declared: true, seconds: 7201, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{}
			condition.Signal.EvaluationDelay = test.delay
			declared, seconds, invalid := newRelicEvaluationDelay(condition)
			if declared != test.declared || seconds != test.seconds || invalid != test.invalid {
				t.Fatalf("got declared=%t seconds=%d invalid=%t, want declared=%t seconds=%d invalid=%t", declared, seconds, invalid, test.declared, test.seconds, test.invalid)
			}
		})
	}
}

func TestNewRelicGapFillOptionNormalization(t *testing.T) {
	tests := []struct {
		name      string
		option    string
		want      string
		evaluable string
		invalid   string
	}{
		{name: "absent", evaluable: "true", invalid: "true"},
		{name: "none", option: " none ", want: "NONE", evaluable: "true", invalid: "false"},
		{name: "static", option: "static", want: "STATIC", evaluable: "true", invalid: "false"},
		{name: "last value", option: "last_value", want: "LAST_VALUE", evaluable: "true", invalid: "false"},
		{name: "unknown remains transient", option: "PRIVATE_GAP_MODE_6427", evaluable: "true", invalid: "true"},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{ID: test.name, Name: test.name, Enabled: true}
			condition.Signal.FillOption = test.option
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if got := resource.Metadata[model.MetadataNewRelicGapFillOption]; got != test.want ||
				resource.Metadata[model.MetadataNewRelicGapFillOptionEvaluable] != test.evaluable ||
				resource.Metadata[model.MetadataNewRelicGapFillOptionInvalid] != test.invalid {
				t.Fatalf("unexpected gap-fill option metadata: %#v", resource.Metadata)
			}
			serialized, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), "PRIVATE_GAP_MODE_6427") {
				t.Fatalf("resource leaked transient gap-fill option: %s", serialized)
			}
		})
	}
}

func TestNewRelicStaticGapFillCriticalBreaches(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		evaluable bool
		breaches  int
	}{
		{name: "above breach", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":5}]}`, evaluable: true, breaches: 1},
		{name: "above clear at equality", payload: `{"signal":{"fillOption":"STATIC","fillValue":5},"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":5}]}`, evaluable: true},
		{name: "above or equals breach", payload: `{"signal":{"fillOption":"STATIC","fillValue":5},"terms":[{"priority":"CRITICAL","operator":"ABOVE_OR_EQUALS","threshold":5}]}`, evaluable: true, breaches: 1},
		{name: "below breach", payload: `{"signal":{"fillOption":"STATIC","fillValue":4},"terms":[{"priority":"CRITICAL","operator":"BELOW","threshold":5}]}`, evaluable: true, breaches: 1},
		{name: "below or equals breach", payload: `{"signal":{"fillOption":"STATIC","fillValue":5},"terms":[{"priority":"CRITICAL","operator":"BELOW_OR_EQUALS","threshold":5}]}`, evaluable: true, breaches: 1},
		{name: "equals breach", payload: `{"signal":{"fillOption":"STATIC","fillValue":5},"terms":[{"priority":"CRITICAL","operator":"EQUALS","threshold":5}]}`, evaluable: true, breaches: 1},
		{name: "legacy equal spelling suppressed", payload: `{"signal":{"fillOption":"STATIC","fillValue":5},"terms":[{"priority":"CRITICAL","operator":"EQUAL","threshold":5}]}`},
		{name: "not equals breach", payload: `{"signal":{"fillOption":"STATIC","fillValue":6},"terms":[{"priority":"CRITICAL","operator":"NOT_EQUALS","threshold":5}]}`, evaluable: true, breaches: 1},
		{name: "warning ignored with critical clear", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"WARNING","operator":"ABOVE","threshold":5},{"priority":"CRITICAL","operator":"BELOW","threshold":5}]}`, evaluable: true},
		{name: "none", payload: `{"signal":{"fillOption":"NONE","fillValue":10},"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":5}]}`},
		{name: "missing fill value", payload: `{"signal":{"fillOption":"STATIC"},"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":5}]}`},
		{name: "no critical term", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"WARNING","operator":"ABOVE","threshold":5}]}`},
		{name: "missing threshold", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"CRITICAL","operator":"ABOVE"}]}`},
		{name: "negative threshold", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":-1}]}`},
		{name: "unknown operator", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"CRITICAL","operator":"FUTURE","threshold":5}]}`},
		{name: "partial critical contract suppressed", payload: `{"signal":{"fillOption":"STATIC","fillValue":10},"terms":[{"priority":"CRITICAL","operator":"ABOVE","threshold":5},{"priority":"CRITICAL","operator":"ABOVE"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var condition newRelicCondition
			if err := json.Unmarshal([]byte(test.payload), &condition); err != nil {
				t.Fatal(err)
			}
			evaluable, breaches := newRelicStaticGapFillCriticalBreaches(condition)
			if evaluable != test.evaluable || breaches != test.breaches {
				t.Fatalf("got evaluable=%t breaches=%d, want evaluable=%t breaches=%d", evaluable, breaches, test.evaluable, test.breaches)
			}
		})
	}
}

func TestNewRelicStaticGapFillValueValidity(t *testing.T) {
	tests := []struct {
		name      string
		option    string
		value     *float64
		evaluable bool
		invalid   bool
	}{
		{name: "none ignored", option: "NONE", value: newRelicFloatPointer(1)},
		{name: "last value ignored", option: "LAST_VALUE", value: newRelicFloatPointer(1)},
		{name: "unknown option owned by option rule", option: "PRIVATE", value: newRelicFloatPointer(1)},
		{name: "static missing", option: "STATIC", evaluable: true, invalid: true},
		{name: "static zero", option: "STATIC", value: newRelicFloatPointer(0), evaluable: true},
		{name: "static negative arbitrary value", option: " static ", value: newRelicFloatPointer(-5), evaluable: true},
		{name: "static positive", option: "STATIC", value: newRelicFloatPointer(42.5), evaluable: true},
		{name: "static nan", option: "STATIC", value: newRelicFloatPointer(math.NaN()), evaluable: true, invalid: true},
		{name: "static positive infinity", option: "STATIC", value: newRelicFloatPointer(math.Inf(1)), evaluable: true, invalid: true},
		{name: "static negative infinity", option: "STATIC", value: newRelicFloatPointer(math.Inf(-1)), evaluable: true, invalid: true},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{ID: test.name, Name: test.name, Enabled: true}
			condition.Signal.FillOption = test.option
			condition.Signal.FillValue = test.value
			evaluable, invalid := newRelicStaticGapFillValueValidity(condition)
			if evaluable != test.evaluable || invalid != test.invalid {
				t.Fatalf("got evaluable=%t invalid=%t, want evaluable=%t invalid=%t", evaluable, invalid, test.evaluable, test.invalid)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicStaticGapFillValueEvaluable] != strconv.FormatBool(test.evaluable) ||
				resource.Metadata[model.MetadataNewRelicStaticGapFillValueInvalid] != strconv.FormatBool(test.invalid) {
				t.Fatalf("unexpected static gap-fill value metadata: %#v", resource.Metadata)
			}
		})
	}
}

func TestNewRelicSlidingWindowValidity(t *testing.T) {
	tests := []struct {
		name      string
		window    int
		slideBy   *int
		declared  bool
		evaluable bool
		invalid   bool
		factor    int
	}{
		{name: "not configured", window: 60},
		{name: "zero", window: 60, slideBy: newRelicIntPointer(0), declared: true, evaluable: true, invalid: true},
		{name: "negative", window: 60, slideBy: newRelicIntPointer(-30), declared: true, evaluable: true, invalid: true},
		{name: "equal window", window: 60, slideBy: newRelicIntPointer(60), declared: true, evaluable: true, invalid: true},
		{name: "above window", window: 60, slideBy: newRelicIntPointer(90), declared: true, evaluable: true, invalid: true},
		{name: "not divisor", window: 60, slideBy: newRelicIntPointer(40), declared: true, evaluable: true, invalid: true},
		{name: "valid divisor", window: 60, slideBy: newRelicIntPointer(30), declared: true, evaluable: true, factor: 2},
		{name: "higher overlap", window: 60, slideBy: newRelicIntPointer(15), declared: true, evaluable: true, factor: 4},
		{name: "minimum window valid divisor", window: 30, slideBy: newRelicIntPointer(15), declared: true, evaluable: true, factor: 2},
		{name: "invalid window low", window: 29, slideBy: newRelicIntPointer(10), declared: true},
		{name: "invalid window high", window: 21601, slideBy: newRelicIntPointer(30), declared: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{}
			condition.Signal.AggregationWindow = test.window
			condition.Signal.SlideBy = test.slideBy
			declared, evaluable, invalid, factor := newRelicSlidingWindowValidity(condition)
			if declared != test.declared || evaluable != test.evaluable || invalid != test.invalid || factor != test.factor {
				t.Fatalf("got declared=%t evaluable=%t invalid=%t factor=%d, want declared=%t evaluable=%t invalid=%t factor=%d", declared, evaluable, invalid, factor, test.declared, test.evaluable, test.invalid, test.factor)
			}
		})
	}
}

func newRelicIntPointer(value int) *int {
	return &value
}

func newRelicFloatPointer(value float64) *float64 {
	return &value
}

func TestNewRelicCriticalThresholdDurationMetadata(t *testing.T) {
	tests := []struct {
		name         string
		termsJSON    string
		critical     string
		minSeconds   string
		maxSeconds   string
		invalidCount string
	}{
		{name: "below minimum", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":29}]`, critical: "1", minSeconds: "29", maxSeconds: "29", invalidCount: "1"},
		{name: "minimum", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":30}]`, critical: "1", minSeconds: "30", maxSeconds: "30", invalidCount: "0"},
		{name: "maximum", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":7200}]`, critical: "1", minSeconds: "7200", maxSeconds: "7200", invalidCount: "0"},
		{name: "above maximum", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":7201}]`, critical: "1", minSeconds: "7201", maxSeconds: "7201", invalidCount: "1"},
		{name: "warning does not pollute critical range", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":30},{"priority":"WARNING","thresholdDuration":9000}]`, critical: "1", minSeconds: "30", maxSeconds: "30", invalidCount: "0"},
		{name: "missing critical duration", termsJSON: `[{"priority":"CRITICAL"}]`, critical: "1", minSeconds: "0", maxSeconds: "0", invalidCount: "1"},
		{name: "no critical term", termsJSON: `[{"priority":"WARNING","thresholdDuration":300}]`, critical: "0", minSeconds: "0", maxSeconds: "0", invalidCount: "0"},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{ID: test.name, Name: test.name, Enabled: true}
			if err := json.Unmarshal([]byte(test.termsJSON), &condition.Terms); err != nil {
				t.Fatal(err)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicCriticalTermCount] != test.critical ||
				resource.Metadata[model.MetadataNewRelicCriticalThresholdDurationMin] != test.minSeconds ||
				resource.Metadata[model.MetadataNewRelicCriticalThresholdDurationMax] != test.maxSeconds ||
				resource.Metadata[model.MetadataNewRelicInvalidCriticalThresholdDurationCount] != test.invalidCount {
				t.Fatalf("unexpected critical duration metadata: %#v", resource.Metadata)
			}
		})
	}
}

func TestNewRelicThresholdPriorityCountMetadata(t *testing.T) {
	tests := []struct {
		name        string
		termsJSON   string
		termCount   string
		critical    string
		warning     string
		atLeastOnce string
		invalid     string
	}{
		{name: "none", termsJSON: `[]`, termCount: "0", critical: "0", warning: "0", atLeastOnce: "0", invalid: "true"},
		{name: "one critical all", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":300,"thresholdOccurrences":"ALL"}]`, termCount: "1", critical: "1", warning: "0", atLeastOnce: "0", invalid: "false"},
		{name: "one critical at least once", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":300,"thresholdOccurrences":"AT_LEAST_ONCE"}]`, termCount: "1", critical: "1", warning: "0", atLeastOnce: "1", invalid: "false"},
		{name: "normalized critical at least once", termsJSON: `[{"priority":"critical","thresholdDuration":300,"thresholdOccurrences":"at_least_once"}]`, termCount: "1", critical: "1", warning: "0", atLeastOnce: "1", invalid: "false"},
		{name: "warning at least once", termsJSON: `[{"priority":"warning","thresholdDuration":300,"thresholdOccurrences":"AT_LEAST_ONCE"}]`, termCount: "1", critical: "0", warning: "1", atLeastOnce: "0", invalid: "false"},
		{name: "one each", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":300,"thresholdOccurrences":"ALL"},{"priority":"WARNING","thresholdDuration":300,"thresholdOccurrences":"AT_LEAST_ONCE"}]`, termCount: "2", critical: "1", warning: "1", atLeastOnce: "0", invalid: "false"},
		{name: "duplicate critical", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":300,"thresholdOccurrences":"AT_LEAST_ONCE"},{"priority":"critical","thresholdDuration":600,"thresholdOccurrences":"ALL"}]`, termCount: "2", critical: "2", warning: "0", atLeastOnce: "1", invalid: "true"},
		{name: "duplicate warning", termsJSON: `[{"priority":"WARNING","thresholdDuration":300},{"priority":"warning","thresholdDuration":600}]`, termCount: "2", critical: "0", warning: "2", atLeastOnce: "0", invalid: "true"},
		{name: "three thresholds", termsJSON: `[{"priority":"CRITICAL","thresholdDuration":300},{"priority":"WARNING","thresholdDuration":300},{"priority":"WARNING","thresholdDuration":600}]`, termCount: "3", critical: "1", warning: "2", atLeastOnce: "0", invalid: "true"},
		{name: "unknown priority", termsJSON: `[{"priority":"PRIVATE","thresholdDuration":300,"thresholdOccurrences":"AT_LEAST_ONCE"}]`, termCount: "1", critical: "0", warning: "0", atLeastOnce: "0", invalid: "true"},
		{name: "missing priority", termsJSON: `[{"thresholdDuration":300,"thresholdOccurrences":"AT_LEAST_ONCE"}]`, termCount: "1", critical: "0", warning: "0", atLeastOnce: "0", invalid: "true"},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{ID: test.name, Name: test.name, Enabled: true}
			if err := json.Unmarshal([]byte(test.termsJSON), &condition.Terms); err != nil {
				t.Fatal(err)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicTermCount] != test.termCount ||
				resource.Metadata[model.MetadataNewRelicCriticalTermCount] != test.critical ||
				resource.Metadata[model.MetadataNewRelicWarningTermCount] != test.warning ||
				resource.Metadata[model.MetadataNewRelicCriticalAtLeastOnceTermCount] != test.atLeastOnce ||
				resource.Metadata[model.MetadataNewRelicThresholdPriorityCountInvalid] != test.invalid {
				t.Fatalf("unexpected threshold priority metadata: %#v", resource.Metadata)
			}
		})
	}
}

func TestNewRelicThresholdTermSemanticsMetadata(t *testing.T) {
	tests := []struct {
		name              string
		termsJSON         string
		invalidOperators  string
		invalidOccurrence string
	}{
		{name: "all supported operators", termsJSON: `[{"operator":"ABOVE","thresholdOccurrences":"ALL"},{"operator":"ABOVE_OR_EQUALS","thresholdOccurrences":"AT_LEAST_ONCE"},{"operator":"BELOW","thresholdOccurrences":"ALL"},{"operator":"BELOW_OR_EQUALS","thresholdOccurrences":"AT_LEAST_ONCE"},{"operator":"EQUALS","thresholdOccurrences":"ALL"},{"operator":"NOT_EQUALS","thresholdOccurrences":"AT_LEAST_ONCE"}]`, invalidOperators: "0", invalidOccurrence: "0"},
		{name: "normalized supported values", termsJSON: `[{"operator":" below ","thresholdOccurrences":" at_least_once "}]`, invalidOperators: "0", invalidOccurrence: "0"},
		{name: "missing values", termsJSON: `[{"priority":"CRITICAL"}]`, invalidOperators: "1", invalidOccurrence: "1"},
		{name: "unknown operator", termsJSON: `[{"operator":"PRIVATE_OPERATOR_4819","thresholdOccurrences":"ALL"}]`, invalidOperators: "1", invalidOccurrence: "0"},
		{name: "unknown occurrence", termsJSON: `[{"operator":"ABOVE","thresholdOccurrences":"PRIVATE_OCCURRENCE_7312"}]`, invalidOperators: "0", invalidOccurrence: "1"},
		{name: "mixed invalid", termsJSON: `[{"operator":"PRIVATE_OPERATOR_4819","thresholdOccurrences":"ALL"},{"operator":"BELOW","thresholdOccurrences":"PRIVATE_OCCURRENCE_7312"}]`, invalidOperators: "1", invalidOccurrence: "1"},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := newRelicCondition{ID: test.name, Name: test.name, Enabled: true}
			if err := json.Unmarshal([]byte(test.termsJSON), &condition.Terms); err != nil {
				t.Fatal(err)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicInvalidThresholdOperatorCount] != test.invalidOperators ||
				resource.Metadata[model.MetadataNewRelicInvalidThresholdOccurrenceCount] != test.invalidOccurrence {
				t.Fatalf("unexpected threshold semantics metadata: %#v", resource.Metadata)
			}
			serialized, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), "PRIVATE_OPERATOR_4819") ||
				strings.Contains(string(serialized), "PRIVATE_OCCURRENCE_7312") {
				t.Fatalf("resource leaked transient threshold semantics: %s", serialized)
			}
		})
	}
}

func TestNewRelicLossOfSignalDurationMetadata(t *testing.T) {
	tests := []struct {
		name       string
		expiration string
		configured string
		invalid    string
		short      string
		closeEval  string
		closeSet   string
	}{
		{name: "absent", expiration: `null`, configured: "false", invalid: "false", short: "false", closeEval: "false", closeSet: "false"},
		{name: "duration absent", expiration: `{}`, configured: "false", invalid: "false", short: "false", closeEval: "false", closeSet: "false"},
		{name: "zero owned by missing rule", expiration: `{"expirationDuration":0,"openViolationOnExpiration":true}`, configured: "false", invalid: "false", short: "false", closeEval: "false", closeSet: "false"},
		{name: "one second", expiration: `{"expirationDuration":1,"openViolationOnExpiration":true}`, configured: "true", invalid: "true", short: "false", closeEval: "false", closeSet: "false"},
		{name: "below minimum", expiration: `{"expirationDuration":29,"openViolationOnExpiration":true}`, configured: "true", invalid: "true", short: "false", closeEval: "false", closeSet: "false"},
		{name: "minimum is short", expiration: `{"expirationDuration":30,"openViolationOnExpiration":true}`, configured: "true", invalid: "false", short: "true", closeEval: "false", closeSet: "false"},
		{name: "below recommendation", expiration: `{"expirationDuration":179,"openViolationOnExpiration":true}`, configured: "true", invalid: "false", short: "true", closeEval: "false", closeSet: "false"},
		{name: "recommendation boundary", expiration: `{"expirationDuration":180,"openViolationOnExpiration":true}`, configured: "true", invalid: "false", short: "false", closeEval: "false", closeSet: "false"},
		{name: "maximum", expiration: `{"expirationDuration":172800,"openViolationOnExpiration":true}`, configured: "true", invalid: "false", short: "false", closeEval: "false", closeSet: "false"},
		{name: "above maximum", expiration: `{"expirationDuration":172801,"openViolationOnExpiration":true}`, configured: "true", invalid: "true", short: "false", closeEval: "false", closeSet: "false"},
		{name: "open disabled invalid", expiration: `{"expirationDuration":29,"openViolationOnExpiration":false}`, configured: "false", invalid: "true", short: "false", closeEval: "false", closeSet: "false"},
		{name: "open disabled short", expiration: `{"expirationDuration":30,"openViolationOnExpiration":false}`, configured: "false", invalid: "false", short: "true", closeEval: "false", closeSet: "false"},
		{name: "close explicitly disabled", expiration: `{"expirationDuration":180,"openViolationOnExpiration":true,"closeViolationsOnExpiration":false}`, configured: "true", invalid: "false", short: "false", closeEval: "true", closeSet: "false"},
		{name: "close enabled", expiration: `{"expirationDuration":180,"openViolationOnExpiration":true,"closeViolationsOnExpiration":true}`, configured: "true", invalid: "false", short: "false", closeEval: "true", closeSet: "true"},
		{name: "close enabled without open", expiration: `{"expirationDuration":180,"openViolationOnExpiration":false,"closeViolationsOnExpiration":true}`, configured: "false", invalid: "false", short: "false", closeEval: "true", closeSet: "true"},
	}
	item := &NewRelicConnector{accountID: 1}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var condition newRelicCondition
			payload := `{"id":"condition","name":"condition","enabled":true,"expiration":` + test.expiration + `}`
			if err := json.Unmarshal([]byte(payload), &condition); err != nil {
				t.Fatal(err)
			}
			resource := item.conditionResource(condition, newRelicPolicy{}, time.Time{})
			if resource.Metadata[model.MetadataNewRelicLossOfSignalConfigured] != test.configured ||
				resource.Metadata[model.MetadataNewRelicLossOfSignalDurationInvalid] != test.invalid ||
				resource.Metadata[model.MetadataNewRelicLossOfSignalDurationShort] != test.short ||
				resource.Metadata[model.MetadataNewRelicLossOfSignalCloseEvaluable] != test.closeEval ||
				resource.Metadata[model.MetadataNewRelicLossOfSignalCloseConfigured] != test.closeSet {
				t.Fatalf("unexpected Loss of Signal metadata: %#v", resource.Metadata)
			}
		})
	}
}

func TestNewRelicConnectorKeepsEntitiesWhenAlertDiscoveryFails(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request newRelicGraphQLRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(request.Query, "MoniCheckEntities") {
			writeNewRelicTestResponse(t, w, map[string]any{
				"actor": map[string]any{"entitySearch": map[string]any{"results": map[string]any{
					"nextCursor": nil,
					"entities": []any{map[string]any{
						"guid": "entity-1", "name": "Worker", "accountId": 7,
						"domain": "APM", "type": "APPLICATION", "reporting": true,
					}},
				}}},
			})
			return
		}
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"private permission detail"}]}`))
	}))
	defer server.Close()

	item, err := NewNewRelicConnectorWithOptions(server.URL, 7, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := item.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Partial || len(snapshot.Resources) != 1 || len(snapshot.Diagnostics) != 2 {
		t.Fatalf("unexpected partial snapshot %#v", snapshot)
	}
	serialized, _ := json.Marshal(snapshot)
	if strings.Contains(string(serialized), "private permission detail") {
		t.Fatalf("partial snapshot leaked GraphQL error: %s", serialized)
	}
}

func TestNewRelicConnectorRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	if _, err := NewNewRelicConnectorWithOptions("https://reader:secret@api.newrelic.com/graphql", 1, HTTPOptions{}); err == nil {
		t.Fatal("expected URL userinfo rejection")
	}
	if _, err := NewNewRelicConnectorWithOptions("https://api.newrelic.com/graphql", 0, HTTPOptions{}); err == nil {
		t.Fatal("expected account id validation")
	}
}

func TestNewRelicConnectorRejectsNonProgressingEntityCursor(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeNewRelicTestResponse(t, w, map[string]any{
			"actor": map[string]any{"entitySearch": map[string]any{"results": map[string]any{
				"nextCursor": "same-cursor", "entities": []any{},
			}}},
		})
	}))
	defer server.Close()

	item, err := NewNewRelicConnectorWithOptions(server.URL, 1, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = item.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cursor did not advance") {
		t.Fatalf("expected cursor progress error, got %v", err)
	}
}

func TestNewRelicConnectorEnforcesEntityResourceLimit(t *testing.T) {
	entities := make([]any, maxNewRelicEntityCount+1)
	for index := range entities {
		entities[index] = map[string]any{
			"guid": "entity-" + strconv.Itoa(index),
			"name": "Service " + strconv.Itoa(index),
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeNewRelicTestResponse(t, w, map[string]any{
			"actor": map[string]any{"entitySearch": map[string]any{"results": map[string]any{
				"nextCursor": nil, "entities": entities,
			}}},
		})
	}))
	defer server.Close()

	item, err := NewNewRelicConnectorWithOptions(server.URL, 1, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = item.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "50000-resource safety limit") {
		t.Fatalf("expected entity limit error, got %v", err)
	}
}

func TestNewRelicConnectorEnforcesResponseSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxNewRelicResponseSize+1)))
	}))
	defer server.Close()

	item, err := NewNewRelicConnectorWithOptions(server.URL, 1, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = item.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("expected response size error, got %v", err)
	}
}

func writeNewRelicTestResponse(t *testing.T, w http.ResponseWriter, data map[string]any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
		t.Fatal(err)
	}
}
