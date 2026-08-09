package rule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
)

var comparisonOperators = []string{">=", "<=", "!=", "==", "=~", "!~", ">", "<"}

type Evaluation struct {
	RuleID     string
	ResourceID string
	Matched    bool
	Reason     string
}

func Evaluate(rule Rule, resource model.Resource, resourceGraph *graph.Graph) (Evaluation, error) {
	matched, err := evalExpression(rule.Condition.Expression, resource, resourceGraph)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{
		RuleID:     rule.ID,
		ResourceID: resource.ID,
		Matched:    matched,
		Reason:     fmt.Sprintf("%s matched %q", resource.Name, rule.Condition.Expression),
	}, nil
}

func InScope(rule Rule, resource model.Resource) bool {
	if len(rule.Scope) == 0 {
		return true
	}
	for _, resourceType := range rule.Scope {
		if resource.Type == resourceType {
			return true
		}
	}
	return false
}

func evalExpression(expression string, resource model.Resource, resourceGraph *graph.Graph) (bool, error) {
	expression = trimOuterParens(strings.TrimSpace(expression))
	if expression == "" {
		return false, fmt.Errorf("empty expression")
	}
	if strings.HasPrefix(expression, "NOT ") {
		matched, err := evalExpression(strings.TrimSpace(strings.TrimPrefix(expression, "NOT ")), resource, resourceGraph)
		return !matched, err
	}
	if parts := splitLogical(expression, " OR "); len(parts) > 1 {
		for _, part := range parts {
			matched, err := evalExpression(part, resource, resourceGraph)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	}
	if parts := splitLogical(expression, " AND "); len(parts) > 1 {
		for _, part := range parts {
			matched, err := evalExpression(part, resource, resourceGraph)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	}
	return evalComparison(expression, resource, resourceGraph)
}

func ValidateExpression(expression string) error {
	expression = trimOuterParens(strings.TrimSpace(expression))
	if expression == "" {
		return fmt.Errorf("empty expression")
	}
	if strings.HasPrefix(expression, "NOT ") {
		return ValidateExpression(strings.TrimSpace(strings.TrimPrefix(expression, "NOT ")))
	}
	if parts := splitLogical(expression, " OR "); len(parts) > 1 {
		for _, part := range parts {
			if err := ValidateExpression(part); err != nil {
				return err
			}
		}
		return nil
	}
	if parts := splitLogical(expression, " AND "); len(parts) > 1 {
		for _, part := range parts {
			if err := ValidateExpression(part); err != nil {
				return err
			}
		}
		return nil
	}
	for _, operator := range comparisonOperators {
		if left, right, ok := cutOperator(expression, operator); ok {
			if !supportedField(strings.TrimSpace(left)) {
				return fmt.Errorf("unsupported rule field %q", strings.TrimSpace(left))
			}
			if operator == "=~" || operator == "!~" {
				if _, err := regexp.Compile(literalValue(strings.TrimSpace(right))); err != nil {
					return fmt.Errorf("invalid regex %q: %w", literalValue(strings.TrimSpace(right)), err)
				}
			}
			return nil
		}
	}
	if !supportedField(expression) {
		return fmt.Errorf("unsupported rule field %q", strings.TrimSpace(expression))
	}
	return nil
}

func evalComparison(expression string, resource model.Resource, resourceGraph *graph.Graph) (bool, error) {
	for _, operator := range comparisonOperators {
		if left, right, ok := cutOperator(expression, operator); ok {
			actual, err := valueFor(strings.TrimSpace(left), resource, resourceGraph)
			if err != nil {
				return false, err
			}
			expected := literalValue(strings.TrimSpace(right))
			return compare(actual, expected, operator), nil
		}
	}
	value, err := valueFor(expression, resource, resourceGraph)
	if err != nil {
		return false, err
	}
	return truthy(value), nil
}

func valueFor(path string, resource model.Resource, resourceGraph *graph.Graph) (string, error) {
	path = strings.TrimSpace(path)
	switch path {
	case "id":
		return resource.ID, nil
	case "type":
		return string(resource.Type), nil
	case "name":
		return resource.Name, nil
	case "uid":
		return resource.UID, nil
	case "status":
		return string(resource.Status), nil
	case "source.system":
		return resource.Source.System, nil
	case "source.cluster":
		return resource.Source.Cluster, nil
	case "source.instance":
		return resource.Source.Instance, nil
	case "source.external_id":
		return resource.Source.ExternalID, nil
	case "incoming_edges":
		return strconv.Itoa(len(resourceGraph.Incoming(resource.ID))), nil
	case "outgoing_edges":
		return strconv.Itoa(len(resourceGraph.Outgoing(resource.ID))), nil
	case "used_by":
		return strconv.Itoa(usedByCount(resource.ID, resourceGraph)), nil
	case "output_used_by":
		return strconv.Itoa(outputUsedByCount(resource.ID, resourceGraph)), nil
	case "datasource_used_by":
		return strconv.Itoa(datasourceUsedByCount(resource.ID, resourceGraph)), nil
	case "service_impact_resources":
		return strconv.Itoa(serviceImpactResourceCount(resource.ID, resourceGraph)), nil
	case "available_observability_signals":
		return strconv.Itoa(observabilitySignalCount(resourceGraph.Resources())), nil
	case "service_observability_signals":
		return strconv.Itoa(observabilitySignalCount(serviceImpactResources(resource.ID, resourceGraph))), nil
	case "available_slo_rules":
		return strconv.Itoa(sloRuleCount(resourceGraph.Resources())), nil
	case "service_metric_resources":
		return strconv.Itoa(resourceTypeCount(serviceImpactResources(resource.ID, resourceGraph), model.ResourceTypeMetric)), nil
	case "service_slo_rules":
		return strconv.Itoa(sloRuleCount(serviceImpactResources(resource.ID, resourceGraph))), nil
	case "slo_group_alert_rules":
		return strconv.Itoa(sloGroupRuleCount(resource, resourceGraph, model.ResourceTypeAlertRule)), nil
	case "slo_group_recording_rules":
		return strconv.Itoa(sloGroupRuleCount(resource, resourceGraph, model.ResourceTypeRecordingRule)), nil
	case "slo_group_primary_recording":
		return strconv.FormatBool(primarySLORecordingRule(resource, resourceGraph)), nil
	case "slo_group_primary_rule":
		return strconv.FormatBool(primarySLOGroupRule(resource, resourceGraph)), nil
	case "slo_group_objective_values":
		return strconv.Itoa(sloGroupObjectives(resource, resourceGraph).RawCount), nil
	case "slo_group_invalid_objectives":
		return strconv.Itoa(sloGroupObjectives(resource, resourceGraph).InvalidCount), nil
	case "slo_group_objective_variants":
		return strconv.Itoa(sloGroupObjectives(resource, resourceGraph).VariantCount), nil
	case "slo_group_window_values":
		return strconv.Itoa(sloGroupWindows(resource, resourceGraph).RawCount), nil
	case "slo_group_invalid_windows":
		return strconv.Itoa(sloGroupWindows(resource, resourceGraph).InvalidCount), nil
	case "slo_group_window_variants":
		return strconv.Itoa(sloGroupWindows(resource, resourceGraph).VariantCount), nil
	case "slo_group_short_windows":
		return strconv.Itoa(sloGroupWindows(resource, resourceGraph).ShortCount), nil
	case "slo_group_long_windows":
		return strconv.Itoa(sloGroupWindows(resource, resourceGraph).LongCount), nil
	case "cardinality":
		return resource.Metadata[model.MetadataSeriesCount], nil
	}
	if key, ok := bracketKey(path, "labels"); ok {
		return resource.Labels[key], nil
	}
	if key, ok := bracketKey(path, "metadata"); ok {
		return resource.Metadata[key], nil
	}
	return "", fmt.Errorf("unsupported rule field %q", path)
}

func supportedField(path string) bool {
	path = strings.TrimSpace(path)
	switch path {
	case "id", "type", "name", "uid", "status",
		"source.system", "source.cluster", "source.instance", "source.external_id",
		"incoming_edges", "outgoing_edges", "used_by", "output_used_by", "datasource_used_by", "service_impact_resources",
		"available_observability_signals", "service_observability_signals", "available_slo_rules", "service_metric_resources", "service_slo_rules",
		"slo_group_alert_rules", "slo_group_recording_rules", "slo_group_primary_recording", "slo_group_primary_rule",
		"slo_group_objective_values", "slo_group_invalid_objectives", "slo_group_objective_variants",
		"slo_group_window_values", "slo_group_invalid_windows", "slo_group_window_variants", "slo_group_short_windows", "slo_group_long_windows", "cardinality":
		return true
	}
	if _, ok := bracketKey(path, "labels"); ok {
		return true
	}
	if _, ok := bracketKey(path, "metadata"); ok {
		return true
	}
	return false
}

func usedByCount(resourceID string, resourceGraph *graph.Graph) int {
	count := 0
	for _, relationship := range resourceGraph.Incoming(resourceID) {
		switch relationship.Type {
		case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
			count++
		}
	}
	return count
}

func outputUsedByCount(resourceID string, resourceGraph *graph.Graph) int {
	seen := make(map[string]bool)
	for _, relationship := range resourceGraph.Outgoing(resourceID) {
		if relationship.Type != model.RelationshipProduces {
			continue
		}
		output, ok := resourceGraph.Resource(relationship.ToID)
		if !ok || output.Type != model.ResourceTypeMetric || output.Status != model.ResourceStatusActive {
			continue
		}
		for _, incoming := range resourceGraph.Incoming(output.ID) {
			switch incoming.Type {
			case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
				seen[incoming.FromID] = true
			}
		}
	}
	return len(seen)
}

func datasourceUsedByCount(resourceID string, resourceGraph *graph.Graph) int {
	seen := make(map[string]bool)
	for _, relationship := range resourceGraph.Incoming(resourceID) {
		switch relationship.Type {
		case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
		default:
			continue
		}
		consumer, ok := resourceGraph.Resource(relationship.FromID)
		if !ok || consumer.Status != model.ResourceStatusActive {
			continue
		}
		switch consumer.Type {
		case model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule:
			seen[consumer.ID] = true
		}
	}
	return len(seen)
}

func serviceImpactResourceCount(resourceID string, resourceGraph *graph.Graph) int {
	return len(serviceImpactResources(resourceID, resourceGraph))
}

func serviceImpactResources(resourceID string, resourceGraph *graph.Graph) []model.Resource {
	seen := make(map[string]bool)
	resources := make([]model.Resource, 0)
	queue := make([]string, 0)
	for _, relationship := range resourceGraph.Incoming(resourceID) {
		if relationship.Type != model.RelationshipBelongsTo {
			continue
		}
		resource, ok := resourceGraph.Resource(relationship.FromID)
		if !ok || resource.Status != model.ResourceStatusActive || !isServiceImpactResource(resource.Type) {
			continue
		}
		seen[resource.ID] = true
		resources = append(resources, resource)
		queue = append(queue, resource.ID)
	}
	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		relationships := append([]model.Relationship{}, resourceGraph.Outgoing(currentID)...)
		relationships = append(relationships, resourceGraph.Incoming(currentID)...)
		for _, relationship := range relationships {
			var nextID string
			switch {
			case relationship.FromID == currentID && relationship.Type == model.RelationshipProduces:
				nextID = relationship.ToID
			case relationship.ToID == currentID && (relationship.Type == model.RelationshipUses || relationship.Type == model.RelationshipProduces):
				nextID = relationship.FromID
			default:
				continue
			}
			if seen[nextID] {
				continue
			}
			resource, ok := resourceGraph.Resource(nextID)
			if !ok || resource.Status != model.ResourceStatusActive || !isServiceImpactResource(resource.Type) {
				continue
			}
			seen[resource.ID] = true
			resources = append(resources, resource)
			queue = append(queue, resource.ID)
		}
	}
	return resources
}

func observabilitySignalCount(resources []model.Resource) int {
	signals := make(map[string]bool)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		switch resource.Type {
		case model.ResourceTypeMetric, model.ResourceTypeRecordingRule, model.ResourceTypeTarget, model.ResourceTypeJob, model.ResourceTypeExporter:
			signals["metrics"] = true
		case model.ResourceTypeDashboard, model.ResourceTypePanel:
			signals["dashboards"] = true
		case model.ResourceTypeAlert:
			signals["alerts"] = true
		case model.ResourceTypeAlertRule:
			if !disabledAlertRule(resource) {
				signals["alerts"] = true
			}
		case model.ResourceTypeLogStream:
			signals["logs"] = true
		case model.ResourceTypeTraceService, model.ResourceTypeTraceOperation:
			signals["traces"] = true
		}
	}
	return len(signals)
}

func disabledAlertRule(resource model.Resource) bool {
	enabled := strings.TrimSpace(strings.ToLower(resource.Metadata[model.MetadataEnabled]))
	if enabled == "false" || enabled == "0" || enabled == "no" {
		return true
	}
	disabled := strings.TrimSpace(strings.ToLower(resource.Metadata[model.MetadataDisabled]))
	return disabled == "true" || disabled == "1" || disabled == "yes"
}

func sloRuleCount(resources []model.Resource) int {
	count := 0
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive || resource.Metadata[model.MetadataSLORule] != "true" {
			continue
		}
		switch resource.Type {
		case model.ResourceTypeRecordingRule:
			count++
		case model.ResourceTypeAlertRule:
			if !disabledAlertRule(resource) {
				count++
			}
		}
	}
	return count
}

func resourceTypeCount(resources []model.Resource, resourceType model.ResourceType) int {
	count := 0
	for _, resource := range resources {
		if resource.Status == model.ResourceStatusActive && resource.Type == resourceType {
			count++
		}
	}
	return count
}

func sloGroupRuleCount(resource model.Resource, resourceGraph *graph.Graph, resourceType model.ResourceType) int {
	count := 0
	for _, member := range sloGroupResources(resource, resourceGraph) {
		if member.Type != resourceType {
			continue
		}
		if member.Type == model.ResourceTypeAlertRule && disabledAlertRule(member) {
			continue
		}
		count++
	}
	return count
}

func primarySLORecordingRule(resource model.Resource, resourceGraph *graph.Graph) bool {
	if resource.Type != model.ResourceTypeRecordingRule || resource.Status != model.ResourceStatusActive {
		return false
	}
	primaryID := ""
	for _, member := range sloGroupResources(resource, resourceGraph) {
		if member.Type != model.ResourceTypeRecordingRule {
			continue
		}
		if primaryID == "" || member.ID < primaryID {
			primaryID = member.ID
		}
	}
	return primaryID != "" && resource.ID == primaryID
}

func primarySLOGroupRule(resource model.Resource, resourceGraph *graph.Graph) bool {
	if resource.Status != model.ResourceStatusActive || (resource.Type != model.ResourceTypeAlertRule && resource.Type != model.ResourceTypeRecordingRule) {
		return false
	}
	primaryID := ""
	for _, member := range sloGroupResources(resource, resourceGraph) {
		if member.Type == model.ResourceTypeAlertRule && disabledAlertRule(member) {
			continue
		}
		if primaryID == "" || member.ID < primaryID {
			primaryID = member.ID
		}
	}
	return primaryID != "" && resource.ID == primaryID
}

type sloObjectiveStats struct {
	RawCount     int
	InvalidCount int
	VariantCount int
}

func sloGroupObjectives(resource model.Resource, resourceGraph *graph.Graph) sloObjectiveStats {
	rawValues := make(map[string]bool)
	invalidValues := make(map[string]bool)
	normalizedValues := make(map[string]bool)
	for _, member := range sloGroupResources(resource, resourceGraph) {
		if member.Type == model.ResourceTypeAlertRule && disabledAlertRule(member) {
			continue
		}
		raw := strings.TrimSpace(member.Metadata[model.MetadataSLOObjective])
		if raw == "" {
			continue
		}
		rawValues[raw] = true
		if normalized, ok := model.NormalizeSLOObjective(raw); ok {
			normalizedValues[normalized] = true
		} else {
			invalidValues[raw] = true
		}
	}
	return sloObjectiveStats{RawCount: len(rawValues), InvalidCount: len(invalidValues), VariantCount: len(normalizedValues)}
}

type sloWindowStats struct {
	RawCount     int
	InvalidCount int
	VariantCount int
	ShortCount   int
	LongCount    int
}

func sloGroupWindows(resource model.Resource, resourceGraph *graph.Graph) sloWindowStats {
	rawValues := make(map[string]bool)
	invalidValues := make(map[string]bool)
	validValues := make(map[string]time.Duration)
	for _, member := range sloGroupResources(resource, resourceGraph) {
		if member.Type == model.ResourceTypeAlertRule && disabledAlertRule(member) {
			continue
		}
		raw := strings.TrimSpace(member.Metadata[model.MetadataSLOWindow])
		if raw == "" {
			continue
		}
		rawValues[raw] = true
		if normalized, duration, ok := model.NormalizeSLOWindow(raw); ok {
			validValues[normalized] = duration
		} else {
			invalidValues[raw] = true
		}
	}
	stats := sloWindowStats{RawCount: len(rawValues), InvalidCount: len(invalidValues), VariantCount: len(validValues)}
	for _, duration := range validValues {
		if duration <= time.Hour {
			stats.ShortCount++
		}
		if duration >= 6*time.Hour {
			stats.LongCount++
		}
	}
	return stats
}

func sloGroupResources(resource model.Resource, resourceGraph *graph.Graph) []model.Resource {
	sloName := strings.TrimSpace(resource.Metadata[model.MetadataSLOName])
	if sloName == "" {
		return nil
	}
	result := make([]model.Resource, 0)
	for _, candidate := range resourceGraph.Resources() {
		if candidate.Status != model.ResourceStatusActive || candidate.Metadata[model.MetadataSLORule] != "true" ||
			!strings.EqualFold(strings.TrimSpace(candidate.Metadata[model.MetadataSLOName]), sloName) ||
			!strings.EqualFold(strings.TrimSpace(candidate.Source.System), strings.TrimSpace(resource.Source.System)) ||
			!strings.EqualFold(strings.TrimSpace(candidate.Source.Instance), strings.TrimSpace(resource.Source.Instance)) {
			continue
		}
		if candidate.Type == model.ResourceTypeAlertRule || candidate.Type == model.ResourceTypeRecordingRule {
			result = append(result, candidate)
		}
	}
	return result
}

func isServiceImpactResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypeFolder,
		model.ResourceTypePanel,
		model.ResourceTypeDatasource,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
		model.ResourceTypeExporter,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeTraceOperation:
		return true
	default:
		return false
	}
}

func bracketKey(path string, prefix string) (string, bool) {
	needle := prefix + "["
	if !strings.HasPrefix(path, needle) || !strings.HasSuffix(path, "]") {
		return "", false
	}
	key := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(path, needle), "]"))
	return literalValue(key), true
}

func cutOperator(expression string, operator string) (string, string, bool) {
	index := indexOutsideQuotes(expression, operator)
	if index < 0 {
		return "", "", false
	}
	return expression[:index], expression[index+len(operator):], true
}

func compare(actual string, expected string, operator string) bool {
	switch operator {
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	case "=~":
		return MatchesPattern(actual, expected)
	case "!~":
		return !MatchesPattern(actual, expected)
	case ">=", ">", "<=", "<":
		actualNumber, actualErr := strconv.ParseFloat(actual, 64)
		expectedNumber, expectedErr := strconv.ParseFloat(expected, 64)
		if actualErr != nil || expectedErr != nil {
			return false
		}
		switch operator {
		case ">=":
			return actualNumber >= expectedNumber
		case ">":
			return actualNumber > expectedNumber
		case "<=":
			return actualNumber <= expectedNumber
		case "<":
			return actualNumber < expectedNumber
		}
	}
	return false
}

func literalValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			unquoted, err := strconv.Unquote(value)
			if err == nil {
				return unquoted
			}
			return value[1 : len(value)-1]
		}
	}
	return value
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false":
		return false
	default:
		return true
	}
}

func splitLogical(expression string, separator string) []string {
	parts := make([]string, 0)
	depth := 0
	inQuote := rune(0)
	start := 0
	runes := []rune(expression)
	sep := []rune(separator)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if inQuote != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && hasRunesAt(runes, sep, i) {
			parts = append(parts, strings.TrimSpace(string(runes[start:i])))
			i += len(sep) - 1
			start = i + 1
		}
	}
	if len(parts) == 0 {
		return []string{expression}
	}
	parts = append(parts, strings.TrimSpace(string(runes[start:])))
	return parts
}

func trimOuterParens(expression string) string {
	for strings.HasPrefix(expression, "(") && strings.HasSuffix(expression, ")") {
		if matchingOuterParens(expression) {
			expression = strings.TrimSpace(expression[1 : len(expression)-1])
			continue
		}
		break
	}
	return expression
}

func matchingOuterParens(expression string) bool {
	depth := 0
	inQuote := rune(0)
	for i, ch := range expression {
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			continue
		}
		if ch == '(' {
			depth++
		}
		if ch == ')' {
			depth--
			if depth == 0 && i != len(expression)-1 {
				return false
			}
		}
	}
	return depth == 0
}

func indexOutsideQuotes(expression string, needle string) int {
	inQuote := rune(0)
	runes := []rune(expression)
	target := []rune(needle)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if inQuote != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			continue
		}
		if hasRunesAt(runes, target, i) {
			return i
		}
	}
	return -1
}

func hasRunesAt(values []rune, target []rune, index int) bool {
	if index+len(target) > len(values) {
		return false
	}
	for i := range target {
		if values[index+i] != target[i] {
			return false
		}
	}
	return true
}

func MatchesPattern(actual string, pattern string) bool {
	matched, err := regexp.MatchString(pattern, actual)
	return err == nil && matched
}
