package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

const UnscopedLogQueryAnalyzerID = "builtin.unscoped_log_query"

type UnscopedLogQueryAnalyzer struct{}

func NewUnscopedLogQueryAnalyzer() *UnscopedLogQueryAnalyzer {
	return &UnscopedLogQueryAnalyzer{}
}

func (a *UnscopedLogQueryAnalyzer) ID() string {
	return UnscopedLogQueryAnalyzerID
}

func (a *UnscopedLogQueryAnalyzer) Name() string {
	return "Unscoped Log Query"
}

func (a *UnscopedLogQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnscopedLogQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel}
}

func (a *UnscopedLogQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if !strings.Contains(strings.ToLower(resource.Metadata[model.MetadataQueryLanguage]), "logql") {
			continue
		}
		query := strings.TrimSpace(resource.Metadata[model.MetadataQuery])
		if query == "" {
			continue
		}
		selectors := unscopedLogSelectors(query)
		if len(selectors) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID, strings.Join(selectors, ",")),
			Type:     "UnscopedLogQuery",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("LogQL uses unscoped log selector(s): %s", strings.Join(selectors, ", ")),
			},
			Recommendation: "为 LogQL 增加 service、namespace、cluster、pod、app 等日志标签约束，避免 Loki 跨租户或大范围日志流扫描。",
			Metadata: map[string]string{
				"analyzer_id":        a.ID(),
				"unscoped_selectors": strings.Join(selectors, ","),
				"unscoped_count":     fmt.Sprintf("%d", len(selectors)),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func unscopedLogSelectors(query string) []string {
	seen := map[string]bool{}
	for _, selector := range logStreamSelectors(query) {
		if !logSelectorHasNonNameMatcher(selector) {
			seen[selector] = true
		}
	}
	selectors := make([]string, 0, len(seen))
	for selector := range seen {
		selectors = append(selectors, selector)
	}
	sort.Strings(selectors)
	return selectors
}

func logStreamSelectors(query string) []string {
	selectors := make([]string, 0)
	for index := 0; index < len(query); index++ {
		if query[index] != '{' {
			continue
		}
		end := logSelectorEnd(query, index+1)
		if end < 0 {
			continue
		}
		selectors = append(selectors, strings.TrimSpace(query[index:end+1]))
		index = end
	}
	return selectors
}

func logSelectorEnd(query string, start int) int {
	inQuote := false
	escaped := false
	for index := start; index < len(query); index++ {
		ch := query[index]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inQuote {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch == '}' && !inQuote {
			return index
		}
	}
	return -1
}

func logSelectorHasNonNameMatcher(selector string) bool {
	selector = strings.TrimSpace(selector)
	selector = strings.TrimPrefix(selector, "{")
	selector = strings.TrimSuffix(selector, "}")
	for _, matcher := range splitLogMatchers(selector) {
		name := logMatcherName(matcher)
		if name != "" && name != "__name__" {
			return true
		}
	}
	return false
}

func splitLogMatchers(value string) []string {
	parts := make([]string, 0)
	start := 0
	inQuote := false
	escaped := false
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inQuote {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch == ',' && !inQuote {
			parts = append(parts, value[start:index])
			start = index + 1
		}
	}
	parts = append(parts, value[start:])
	return parts
}

func logMatcherName(matcher string) string {
	matcher = strings.TrimSpace(matcher)
	for _, operator := range []string{"!~", "=~", "!=", "="} {
		if index := strings.Index(matcher, operator); index >= 0 {
			return strings.TrimSpace(matcher[:index])
		}
	}
	return ""
}
