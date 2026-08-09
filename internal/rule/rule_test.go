package rule

import (
	"os"
	"path/filepath"
	"testing"

	"monicheck/internal/model"
)

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{
		"rules": [
			{
				"id": "custom.unused_metric",
				"scope": ["Metric"],
				"condition": {"expression": "type == \"Metric\" AND used_by == 0"}
			}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load file: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Severity != model.SeverityWarning {
		t.Fatalf("expected default warning severity, got %s", rules[0].Severity)
	}
	if rules[0].FindingType != "RuleViolation" {
		t.Fatalf("expected default finding type, got %s", rules[0].FindingType)
	}
}

func TestSaveFile(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "rules.json")
	yamlPath := filepath.Join(dir, "rules.yaml")
	rules := []Rule{
		{
			ID:          "custom.unused_metric",
			Type:        TypeLifecycle,
			Scope:       []model.ResourceType{model.ResourceTypeMetric},
			Condition:   Condition{Expression: `type == "Metric" AND used_by == 0`},
			Severity:    model.SeverityWarning,
			FindingType: "CustomUnusedMetric",
		},
	}

	if err := SaveFile(jsonPath, rules); err != nil {
		t.Fatalf("save json: %v", err)
	}
	loadedJSON, err := LoadFile(jsonPath)
	if err != nil {
		t.Fatalf("load json: %v", err)
	}
	if len(loadedJSON) != 1 || loadedJSON[0].ID != "custom.unused_metric" {
		t.Fatalf("unexpected json rules %#v", loadedJSON)
	}

	if err := SaveFile(yamlPath, rules); err != nil {
		t.Fatalf("save yaml: %v", err)
	}
	loadedYAML, err := LoadFile(yamlPath)
	if err != nil {
		t.Fatalf("load yaml: %v", err)
	}
	if len(loadedYAML) != 1 || loadedYAML[0].ID != "custom.unused_metric" {
		t.Fatalf("unexpected yaml rules %#v", loadedYAML)
	}

	if err := SaveFile(jsonPath, nil); err != nil {
		t.Fatalf("save empty json: %v", err)
	}
	emptyRules, err := LoadFile(jsonPath)
	if err != nil {
		t.Fatalf("load empty json: %v", err)
	}
	if len(emptyRules) != 0 {
		t.Fatalf("expected empty rules, got %#v", emptyRules)
	}
}

func TestLoadYAMLFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(`rules:
  - id: custom.unused_metric
    name: Custom Unused Metric
    version: 0.2.0
    type: LIFECYCLE
    scope: [Metric]
    condition:
      expression: type == "Metric" AND used_by == 0
    severity: CRITICAL
    finding_type: CustomUnusedMetric
    metadata:
      owner: platform
`), 0o600); err != nil {
		t.Fatalf("write yaml rules: %v", err)
	}

	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load yaml file: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "custom.unused_metric" {
		t.Fatalf("expected rule id custom.unused_metric, got %s", rules[0].ID)
	}
	if rules[0].Version != "0.2.0" {
		t.Fatalf("expected version 0.2.0, got %s", rules[0].Version)
	}
	if len(rules[0].Scope) != 1 || rules[0].Scope[0] != model.ResourceTypeMetric {
		t.Fatalf("expected metric scope, got %#v", rules[0].Scope)
	}
	if rules[0].Condition.Expression != `type == "Metric" AND used_by == 0` {
		t.Fatalf("unexpected condition %q", rules[0].Condition.Expression)
	}
	if rules[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", rules[0].Severity)
	}
	if rules[0].Metadata["owner"] != "platform" {
		t.Fatalf("expected metadata owner platform, got %#v", rules[0].Metadata)
	}
}

func TestValidateRules(t *testing.T) {
	issues := ValidateRules([]Rule{
		{
			ID:        "invalid.rule",
			Type:      Type("UNKNOWN"),
			Scope:     []model.ResourceType{model.ResourceType("Unknown")},
			Severity:  model.Severity("BAD"),
			Condition: Condition{Expression: `labels["team"] =~ "["`},
		},
		{
			ID:        "invalid.rule",
			Condition: Condition{Expression: `unknown_field == "x"`},
		},
	})
	if len(issues) < 5 {
		t.Fatalf("expected validation issues, got %#v", issues)
	}
}

func TestValidateRulesAcceptsTraceOperationScope(t *testing.T) {
	issues := ValidateRules([]Rule{
		{
			ID:        "trace.operation.dynamic",
			Type:      TypeQuality,
			Scope:     []model.ResourceType{model.ResourceTypeTraceOperation},
			Severity:  model.SeverityWarning,
			Condition: Condition{Expression: `metadata["trace_operation"] =~ ".*/[0-9]{4,}.*"`},
		},
		{
			ID:        "alertmanager.silence.comment",
			Type:      TypeLifecycle,
			Scope:     []model.ResourceType{model.ResourceTypeSilence},
			Severity:  model.SeverityWarning,
			Condition: Condition{Expression: `metadata["silence_comment"] == ""`},
		},
	})
	if len(issues) != 0 {
		t.Fatalf("expected trace operation rule to validate, got %#v", issues)
	}
}

func TestValidateRulesAcceptsQueryDependencyScopes(t *testing.T) {
	for _, resourceType := range []model.ResourceType{
		model.ResourceTypeLogStream,
		model.ResourceTypeTraceService,
		model.ResourceTypeTable,
	} {
		rules := []Rule{{
			ID:        "query-dependency-" + string(resourceType),
			Name:      "Query dependency",
			Type:      TypeQuality,
			Scope:     []model.ResourceType{resourceType},
			Condition: Condition{Expression: `status == "ACTIVE"`},
			Severity:  model.SeverityInfo,
		}}
		if issues := ValidateRules(rules); len(issues) != 0 {
			t.Fatalf("expected %s scope to be valid, got %#v", resourceType, issues)
		}
	}
}
