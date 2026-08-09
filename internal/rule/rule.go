package rule

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"monicheck/internal/model"
)

type Type string

const (
	TypeResource     Type = "RESOURCE"
	TypeRelationship Type = "RELATIONSHIP"
	TypeCost         Type = "COST"
	TypeQuality      Type = "QUALITY"
	TypeLifecycle    Type = "LIFECYCLE"
)

type Condition struct {
	Expression string `json:"expression"`
}

type Rule struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Version        string               `json:"version"`
	Type           Type                 `json:"type"`
	Scope          []model.ResourceType `json:"scope"`
	Condition      Condition            `json:"condition"`
	Severity       model.Severity       `json:"severity"`
	FindingType    string               `json:"finding_type,omitempty"`
	Recommendation string               `json:"recommendation,omitempty"`
	Metadata       map[string]string    `json:"metadata,omitempty"`
}

func LoadFile(path string) ([]Rule, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return parseYAML(data)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		if rawRules, ok := raw["rules"]; ok {
			var rules []Rule
			if err := json.Unmarshal(rawRules, &rules); err != nil {
				return nil, err
			}
			return Normalize(rules)
		}
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return Normalize(rules)
}

func SaveFile(path string, rules []Rule) error {
	if path == "" {
		return fmt.Errorf("rule path is empty")
	}
	normalized, err := Normalize(rules)
	if err != nil {
		return err
	}
	var data []byte
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		data = marshalYAML(normalized)
	default:
		data, err = json.MarshalIndent(struct {
			Rules []Rule `json:"rules"`
		}{Rules: normalized}, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func parseYAML(data []byte) ([]Rule, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	rules := make([]Rule, 0)
	var current *Rule
	section := ""

	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "rules:" {
			continue
		}
		if current != nil && section == "scope" && strings.HasPrefix(trimmed, "- ") {
			current.Scope = append(current.Scope, model.ResourceType(unquoteYAML(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))))
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if current != nil {
				rules = append(rules, *current)
			}
			current = &Rule{}
			section = ""
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if rest != "" {
				if err := applyYAMLField(current, &section, rest); err != nil {
					return nil, err
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		if err := applyYAMLField(current, &section, trimmed); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		rules = append(rules, *current)
	}
	return Normalize(rules)
}

func applyYAMLField(target *Rule, section *string, line string) error {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return fmt.Errorf("invalid yaml rule line %q", line)
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if value == "" {
		*section = key
		if key == "metadata" && target.Metadata == nil {
			target.Metadata = map[string]string{}
		}
		return nil
	}
	value = unquoteYAML(value)

	switch *section {
	case "condition":
		if key == "expression" {
			target.Condition.Expression = value
			return nil
		}
	case "metadata":
		if target.Metadata == nil {
			target.Metadata = map[string]string{}
		}
		target.Metadata[key] = value
		return nil
	}

	*section = ""
	switch key {
	case "id":
		target.ID = value
	case "name":
		target.Name = value
	case "version":
		target.Version = value
	case "type":
		target.Type = Type(value)
	case "scope":
		target.Scope = parseYAMLScope(value)
	case "condition":
		target.Condition.Expression = value
	case "severity":
		target.Severity = model.Severity(value)
	case "finding_type":
		target.FindingType = value
	case "recommendation":
		target.Recommendation = value
	default:
		if target.Metadata == nil {
			target.Metadata = map[string]string{}
		}
		target.Metadata[key] = value
	}
	return nil
}

func parseYAMLScope(value string) []model.ResourceType {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	parts := strings.Split(value, ",")
	scope := make([]model.ResourceType, 0, len(parts))
	for _, part := range parts {
		part = unquoteYAML(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		scope = append(scope, model.ResourceType(part))
	}
	return scope
}

func unquoteYAML(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return value
	}
	if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}

func marshalYAML(rules []Rule) []byte {
	var builder strings.Builder
	builder.WriteString("rules:\n")
	for _, item := range rules {
		builder.WriteString("  - id: ")
		builder.WriteString(yamlValue(item.ID))
		builder.WriteByte('\n')
		builder.WriteString("    name: ")
		builder.WriteString(yamlValue(item.Name))
		builder.WriteByte('\n')
		builder.WriteString("    version: ")
		builder.WriteString(yamlValue(item.Version))
		builder.WriteByte('\n')
		builder.WriteString("    type: ")
		builder.WriteString(string(item.Type))
		builder.WriteByte('\n')
		builder.WriteString("    scope: [")
		for i, resourceType := range item.Scope {
			if i > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(string(resourceType))
		}
		builder.WriteString("]\n")
		builder.WriteString("    condition:\n")
		builder.WriteString("      expression: ")
		builder.WriteString(yamlValue(item.Condition.Expression))
		builder.WriteByte('\n')
		builder.WriteString("    severity: ")
		builder.WriteString(string(item.Severity))
		builder.WriteByte('\n')
		builder.WriteString("    finding_type: ")
		builder.WriteString(yamlValue(item.FindingType))
		builder.WriteByte('\n')
		if item.Recommendation != "" {
			builder.WriteString("    recommendation: ")
			builder.WriteString(yamlValue(item.Recommendation))
			builder.WriteByte('\n')
		}
		if len(item.Metadata) > 0 {
			builder.WriteString("    metadata:\n")
			keys := make([]string, 0, len(item.Metadata))
			for key := range item.Metadata {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				builder.WriteString("      ")
				builder.WriteString(key)
				builder.WriteString(": ")
				builder.WriteString(yamlValue(item.Metadata[key]))
				builder.WriteByte('\n')
			}
		}
	}
	return []byte(builder.String())
}

func yamlValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, ":#[]{}\",'") || strings.Contains(value, " AND ") || strings.Contains(value, " OR ") {
		encoded, err := json.Marshal(value)
		if err == nil {
			return string(encoded)
		}
	}
	return value
}

func Normalize(rules []Rule) ([]Rule, error) {
	normalized := append([]Rule(nil), rules...)
	sort.SliceStable(normalized, func(i, j int) bool {
		return normalized[i].ID < normalized[j].ID
	})
	for i := range normalized {
		if normalized[i].ID == "" {
			return nil, fmt.Errorf("rule at index %d is missing id", i)
		}
		if normalized[i].Name == "" {
			normalized[i].Name = normalized[i].ID
		}
		if normalized[i].Version == "" {
			normalized[i].Version = "0.1.0"
		}
		if normalized[i].Type == "" {
			normalized[i].Type = TypeQuality
		}
		if normalized[i].Severity == "" {
			normalized[i].Severity = model.SeverityWarning
		}
		if normalized[i].FindingType == "" {
			normalized[i].FindingType = "RuleViolation"
		}
		if normalized[i].Condition.Expression == "" {
			return nil, fmt.Errorf("rule %s is missing condition expression", normalized[i].ID)
		}
	}
	if issues := ValidateRules(normalized); len(issues) > 0 {
		return nil, fmt.Errorf("invalid rule %s: %s", issues[0].RuleID, issues[0].Message)
	}
	return normalized, nil
}

type ValidationIssue struct {
	RuleID  string `json:"rule_id,omitempty"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

func ValidateRules(rules []Rule) []ValidationIssue {
	issues := make([]ValidationIssue, 0)
	seen := make(map[string]bool)
	for i, item := range rules {
		ruleID := item.ID
		if ruleID == "" {
			ruleID = fmt.Sprintf("index:%d", i)
			issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "id", Message: "id is required"})
		} else if seen[item.ID] {
			issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "id", Message: "id must be unique"})
		}
		seen[item.ID] = true
		if item.Type != "" && !validRuleType(item.Type) {
			issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "type", Message: "unsupported rule type"})
		}
		if item.Severity != "" && !validSeverity(item.Severity) {
			issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "severity", Message: "unsupported severity"})
		}
		for _, resourceType := range item.Scope {
			if !validResourceType(resourceType) {
				issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "scope", Message: fmt.Sprintf("unsupported resource type %q", resourceType)})
			}
		}
		if strings.TrimSpace(item.Condition.Expression) == "" {
			issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "condition.expression", Message: "expression is required"})
			continue
		}
		if err := ValidateExpression(item.Condition.Expression); err != nil {
			issues = append(issues, ValidationIssue{RuleID: ruleID, Field: "condition.expression", Message: err.Error()})
		}
	}
	return issues
}

func validRuleType(ruleType Type) bool {
	switch ruleType {
	case TypeResource, TypeRelationship, TypeCost, TypeQuality, TypeLifecycle:
		return true
	default:
		return false
	}
}

func validSeverity(severity model.Severity) bool {
	switch severity {
	case model.SeverityInfo, model.SeverityWarning, model.SeverityCritical:
		return true
	default:
		return false
	}
}

func validResourceType(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeMetric,
		model.ResourceTypeMetricLabel,
		model.ResourceTypeTSDB,
		model.ResourceTypeService,
		model.ResourceTypeDashboard,
		model.ResourceTypeFolder,
		model.ResourceTypePanel,
		model.ResourceTypeDatasource,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeSilence,
		model.ResourceTypeReceiver,
		model.ResourceTypeNotificationPolicy,
		model.ResourceTypeInhibitionRule,
		model.ResourceTypeTimeInterval,
		model.ResourceTypeNotificationTemplate,
		model.ResourceTypeProcessor,
		model.ResourceTypePipeline,
		model.ResourceTypeExtension,
		model.ResourceTypeTelemetryConnector,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
		model.ResourceTypeExporter,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeLogLabel,
		model.ResourceTypeLogLabelValue,
		model.ResourceTypeTraceTag,
		model.ResourceTypeTraceTagValue,
		model.ResourceTypeTraceOperation,
		model.ResourceTypeLogStream,
		model.ResourceTypeTraceService,
		model.ResourceTypeTable,
		model.ResourceTypeScrapeClass:
		return true
	default:
		return false
	}
}

func Category(ruleType Type) model.FindingCategory {
	switch ruleType {
	case TypeCost:
		return model.FindingCategoryCost
	case TypeLifecycle:
		return model.FindingCategoryLifecycle
	case TypeRelationship:
		return model.FindingCategoryReliability
	case TypeResource:
		return model.FindingCategoryConfiguration
	default:
		return model.FindingCategoryQuality
	}
}
