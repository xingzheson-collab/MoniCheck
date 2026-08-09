package connector

import (
	"strconv"
	"strings"

	promLabels "github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

var promQLReservedWords = map[string]bool{
	"and": true, "bool": true, "by": true, "ignoring": true, "group_left": true,
	"group_right": true, "offset": true, "on": true, "or": true, "unless": true,
	"without": true,
	"sum":     true, "avg": true, "min": true, "max": true, "count": true,
	"count_values": true, "stddev": true, "stdvar": true, "topk": true, "bottomk": true,
	"quantile": true, "limitk": true, "limit_ratio": true,
	"abs": true, "absent": true, "absent_over_time": true, "ceil": true, "changes": true,
	"clamp": true, "clamp_max": true, "clamp_min": true, "day_of_month": true,
	"day_of_week": true, "day_of_year": true, "days_in_month": true, "delta": true,
	"deriv": true, "exp": true, "floor": true, "histogram_avg": true,
	"histogram_count": true, "histogram_fraction": true, "histogram_quantile": true,
	"histogram_sum": true, "holt_winters": true, "hour": true, "idelta": true,
	"increase": true, "irate": true, "label_join": true, "label_replace": true,
	"ln": true, "log2": true, "log10": true, "minute": true, "month": true,
	"predict_linear": true, "present_over_time": true, "rate": true, "resets": true,
	"round": true, "scalar": true, "sgn": true, "sort": true, "sort_desc": true,
	"sort_by_label": true, "sort_by_label_desc": true, "sqrt": true, "time": true,
	"timestamp": true, "vector": true, "year": true,
	"avg_over_time": true, "count_over_time": true, "last_over_time": true,
	"max_over_time": true, "min_over_time": true, "quantile_over_time": true,
	"stddev_over_time": true, "stdvar_over_time": true, "sum_over_time": true,
	"NaN": true, "Inf": true,
}

var promQLLabelListWords = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true, "group_left": true, "group_right": true,
}

func ExtractPromQLMetricNames(expression string) []string {
	metrics, err := extractPromQLMetricNamesOfficial(expression)
	if err == nil {
		return metrics
	}
	return extractPromQLMetricNamesLightweight(expression)
}

func extractPromQLMetricNamesOfficial(expression string) ([]string, error) {
	expr, err := parser.ParseExpr(expression)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	metrics := make([]string, 0)
	addMetric := func(metricName string) {
		if metricName == "" || seen[metricName] {
			return
		}
		seen[metricName] = true
		metrics = append(metrics, metricName)
	}
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		selector, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		addMetric(selector.Name)
		for _, matcher := range selector.LabelMatchers {
			if matcher.Name != "__name__" {
				continue
			}
			switch matcher.Type {
			case promLabels.MatchEqual:
				if isPromQLMetricName(matcher.Value) {
					addMetric(matcher.Value)
				}
			case promLabels.MatchRegexp:
				for _, metricName := range metricNamesFromNameMatcher("=~", matcher.Value) {
					addMetric(metricName)
				}
			}
		}
		return nil
	})
	return metrics, nil
}

func extractPromQLMetricNamesLightweight(expression string) []string {
	seen := make(map[string]bool)
	metrics := make([]string, 0)
	runes := []rune(expression)
	selectorDepth := 0
	labelListDepth := 0
	awaitingLabelList := false

	for i := 0; i < len(runes); {
		ch := runes[i]
		switch {
		case ch == '"' || ch == '\'' || ch == '`':
			i = skipPromQLString(runes, i)
			continue
		case ch == '{':
			if end := findPromQLSelectorEnd(runes, i); end > i {
				for _, metricName := range extractPromQLSelectorMetricNames(string(runes[i+1 : end])) {
					if !seen[metricName] {
						seen[metricName] = true
						metrics = append(metrics, metricName)
					}
				}
				i = end + 1
				continue
			}
			selectorDepth++
			i++
			continue
		case ch == '}':
			if selectorDepth > 0 {
				selectorDepth--
			}
			i++
			continue
		case ch == '(':
			if awaitingLabelList {
				labelListDepth++
				awaitingLabelList = false
			}
			i++
			continue
		case ch == ')':
			if labelListDepth > 0 {
				labelListDepth--
			}
			i++
			continue
		case isPromQLIdentifierStart(ch):
			start := i
			i++
			for i < len(runes) && isPromQLIdentifierPart(runes[i]) {
				i++
			}
			identifier := string(runes[start:i])
			if promQLLabelListWords[identifier] {
				awaitingLabelList = true
			}
			if shouldKeepPromQLIdentifier(runes, start, i, selectorDepth, labelListDepth, identifier) && !seen[identifier] {
				seen[identifier] = true
				metrics = append(metrics, identifier)
			}
			continue
		default:
			if !isPromQLSpace(ch) {
				awaitingLabelList = false
			}
			i++
		}
	}
	return metrics
}

func extractPromQLSelectorMetricNames(selector string) []string {
	runes := []rune(selector)
	metrics := make([]string, 0)
	seen := make(map[string]bool)
	for i := 0; i < len(runes); {
		if !isPromQLIdentifierStart(runes[i]) {
			i++
			continue
		}
		start := i
		i++
		for i < len(runes) && isPromQLIdentifierPart(runes[i]) {
			i++
		}
		if string(runes[start:i]) != "__name__" {
			continue
		}
		i = skipPromQLSpaces(runes, i)
		operator := ""
		for _, candidate := range []string{"=~", "!~", "!=", "="} {
			if hasRunesAt(runes, []rune(candidate), i) {
				operator = candidate
				i += len([]rune(candidate))
				break
			}
		}
		if operator == "" || operator == "!=" || operator == "!~" {
			continue
		}
		i = skipPromQLSpaces(runes, i)
		if i >= len(runes) || (runes[i] != '"' && runes[i] != '\'' && runes[i] != '`') {
			continue
		}
		value, next := readPromQLString(runes, i)
		i = next
		for _, metricName := range metricNamesFromNameMatcher(operator, value) {
			if seen[metricName] {
				continue
			}
			seen[metricName] = true
			metrics = append(metrics, metricName)
		}
	}
	return metrics
}

func metricNamesFromNameMatcher(operator string, value string) []string {
	if operator == "=" {
		if isPromQLMetricName(value) {
			return []string{value}
		}
		return nil
	}
	parts := strings.Split(value, "|")
	metrics := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(part), "$"), "^")
		if isPromQLMetricName(part) {
			metrics = append(metrics, part)
		}
	}
	return metrics
}

func shouldKeepPromQLIdentifier(runes []rune, start int, end int, selectorDepth int, labelListDepth int, identifier string) bool {
	if selectorDepth > 0 || labelListDepth > 0 || promQLReservedWords[identifier] {
		return false
	}
	if prev := previousPromQLNonSpace(runes, start); prev >= 0 && isPromQLDigit(runes[prev]) {
		return false
	}
	if next := nextPromQLNonSpace(runes, end); next >= 0 && runes[next] == '(' {
		return false
	}
	return strings.Trim(identifier, "_:") != ""
}

func skipPromQLString(runes []rune, start int) int {
	_, end := readPromQLString(runes, start)
	return end
}

func readPromQLString(runes []rune, start int) (string, int) {
	quote := runes[start]
	for i := start + 1; i < len(runes); i++ {
		if quote != '`' && runes[i] == '\\' {
			i++
			continue
		}
		if runes[i] == quote {
			raw := string(runes[start : i+1])
			if quote == '`' {
				return string(runes[start+1 : i]), i + 1
			}
			value, err := strconv.Unquote(raw)
			if err != nil {
				return string(runes[start+1 : i]), i + 1
			}
			return value, i + 1
		}
	}
	return string(runes[start+1:]), len(runes)
}

func findPromQLSelectorEnd(runes []rune, start int) int {
	for i := start + 1; i < len(runes); {
		switch runes[i] {
		case '"', '\'', '`':
			i = skipPromQLString(runes, i)
			continue
		case '}':
			return i
		default:
			i++
		}
	}
	return -1
}

func previousPromQLNonSpace(runes []rune, index int) int {
	for i := index - 1; i >= 0; i-- {
		if !isPromQLSpace(runes[i]) {
			return i
		}
	}
	return -1
}

func nextPromQLNonSpace(runes []rune, index int) int {
	for i := index; i < len(runes); i++ {
		if !isPromQLSpace(runes[i]) {
			return i
		}
	}
	return -1
}

func skipPromQLSpaces(runes []rune, index int) int {
	for index < len(runes) && isPromQLSpace(runes[index]) {
		index++
	}
	return index
}

func isPromQLIdentifierStart(ch rune) bool {
	return ch == '_' || ch == ':' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isPromQLIdentifierPart(ch rune) bool {
	return isPromQLIdentifierStart(ch) || isPromQLDigit(ch)
}

func isPromQLDigit(ch rune) bool {
	return ch >= '0' && ch <= '9'
}

func isPromQLSpace(ch rune) bool {
	return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t'
}

func isPromQLMetricName(value string) bool {
	if value == "" {
		return false
	}
	runes := []rune(value)
	if !isPromQLIdentifierStart(runes[0]) {
		return false
	}
	for _, ch := range runes[1:] {
		if !isPromQLIdentifierPart(ch) {
			return false
		}
	}
	return true
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
