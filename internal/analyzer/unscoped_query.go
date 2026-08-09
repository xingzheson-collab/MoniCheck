package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/prometheus/prometheus/promql/parser"

	"monicheck/internal/connector"
	"monicheck/internal/model"
)

const UnscopedQueryAnalyzerID = "builtin.unscoped_query"

type UnscopedQueryAnalyzer struct{}

func NewUnscopedQueryAnalyzer() *UnscopedQueryAnalyzer {
	return &UnscopedQueryAnalyzer{}
}

func (a *UnscopedQueryAnalyzer) ID() string {
	return UnscopedQueryAnalyzerID
}

func (a *UnscopedQueryAnalyzer) Name() string {
	return "Unscoped Query"
}

func (a *UnscopedQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnscopedQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *UnscopedQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		query := strings.TrimSpace(resource.Metadata[model.MetadataPromQL])
		if query == "" {
			continue
		}
		metricNames := unscopedQueryMetrics(query)
		if len(metricNames) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID, strings.Join(metricNames, ",")),
			Type:     "UnscopedQuery",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("PromQL references metric selector(s) without non-name label constraints: %s", strings.Join(metricNames, ", ")),
			},
			Recommendation: "为高流量 PromQL 增加 service、job、namespace、cluster 等必要标签约束；无法约束时优先使用 Recording Rule 预聚合，降低 TSDB 扫描成本。",
			Metadata: map[string]string{
				"analyzer_id":         a.ID(),
				"unscoped_metrics":    strings.Join(metricNames, ","),
				"unscoped_count":      fmt.Sprintf("%d", len(metricNames)),
				"query_resource_type": string(resource.Type),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func unscopedQueryMetrics(query string) []string {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return fallbackUnscopedQueryMetrics(query)
	}
	seen := make(map[string]bool)
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		selector, ok := node.(*parser.VectorSelector)
		if !ok || hasNonNameMatcher(selector) {
			return nil
		}
		name := strings.TrimSpace(selector.Name)
		if name == "" {
			name = metricNameFromMatchers(selector)
		}
		if name != "" {
			seen[name] = true
		}
		return nil
	})

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func fallbackUnscopedQueryMetrics(query string) []string {
	seen := make(map[string]bool)
	for _, metricName := range connector.ExtractPromQLMetricNames(query) {
		if !rawMetricHasNonNameMatcher(query, metricName) {
			seen[metricName] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func rawMetricHasNonNameMatcher(query string, metricName string) bool {
	for offset := 0; offset < len(query); {
		index := strings.Index(query[offset:], metricName)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(metricName)
		if !rawIdentifierBoundary(query, start, end) {
			offset = end
			continue
		}
		next := rawNextNonSpace(query, end)
		if next < 0 || query[next] != '{' {
			return false
		}
		close := strings.IndexByte(query[next:], '}')
		if close < 0 {
			return false
		}
		matcherBlock := query[next+1 : next+close]
		if rawMatcherBlockHasNonNameMatcher(matcherBlock) {
			return true
		}
		offset = next + close + 1
	}
	return false
}

func rawIdentifierBoundary(query string, start int, end int) bool {
	if start > 0 {
		previous := rune(query[start-1])
		if unicode.IsLetter(previous) || unicode.IsDigit(previous) || previous == '_' || previous == ':' {
			return false
		}
	}
	if end < len(query) {
		next := rune(query[end])
		if unicode.IsLetter(next) || unicode.IsDigit(next) || next == '_' || next == ':' {
			return false
		}
	}
	return true
}

func rawNextNonSpace(query string, start int) int {
	for i := start; i < len(query); i++ {
		if !unicode.IsSpace(rune(query[i])) {
			return i
		}
	}
	return -1
}

func rawMatcherBlockHasNonNameMatcher(block string) bool {
	for _, matcher := range strings.Split(block, ",") {
		name, _, ok := strings.Cut(matcher, "=")
		if !ok {
			name, _, ok = strings.Cut(matcher, "!")
			if !ok {
				continue
			}
		}
		name = strings.TrimSpace(strings.TrimSuffix(name, "!"))
		if name != "__name__" {
			return true
		}
	}
	return false
}

func hasNonNameMatcher(selector *parser.VectorSelector) bool {
	for _, matcher := range selector.LabelMatchers {
		if matcher != nil && matcher.Name != "__name__" {
			return true
		}
	}
	return false
}

func metricNameFromMatchers(selector *parser.VectorSelector) string {
	for _, matcher := range selector.LabelMatchers {
		if matcher == nil || matcher.Name != "__name__" {
			continue
		}
		return strings.TrimSpace(matcher.Value)
	}
	return ""
}
