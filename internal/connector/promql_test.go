package connector

import (
	"reflect"
	"testing"
)

func TestExtractPromQLMetricNames(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		expected   []string
	}{
		{
			name:       "rate with aggregation labels",
			expression: `sum by (job, method) (rate(http_requests_total{job="api", method!="GET"}[5m]))`,
			expected:   []string{"http_requests_total"},
		},
		{
			name:       "plain metric without underscore",
			expression: `up{job=~"node|api"} == 0`,
			expected:   []string{"up"},
		},
		{
			name:       "binary expression with vector matching",
			expression: `node_cpu_seconds_total{mode!="idle"} / on(instance) group_left(job) node_cpu_count`,
			expected:   []string{"node_cpu_seconds_total", "node_cpu_count"},
		},
		{
			name:       "label replace ignores string literals",
			expression: `label_replace(rate(http_requests_total[5m]), "service", "$1", "job", "(.*)")`,
			expected:   []string{"http_requests_total"},
		},
		{
			name:       "recording rule style metric",
			expression: `job:http_requests:rate5m / ignoring(code) job:http_requests:rate1h`,
			expected:   []string{"job:http_requests:rate5m", "job:http_requests:rate1h"},
		},
		{
			name:       "selector name matcher",
			expression: `sum({__name__="up", job="api"})`,
			expected:   []string{"up"},
		},
		{
			name:       "selector name regex alternatives",
			expression: `{__name__=~"http_requests_total|node_cpu_seconds_total", job=~"api|node"}`,
			expected:   []string{"http_requests_total", "node_cpu_seconds_total"},
		},
		{
			name:       "selector negative name matcher ignored",
			expression: `{__name__!="up", job="api"}`,
			expected:   []string{},
		},
		{
			name:       "label values are not metrics",
			expression: `sum by (job) ({job="http_requests_total", service="api"})`,
			expected:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractPromQLMetricNames(tt.expression)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("expected %#v, got %#v", tt.expected, got)
			}
		})
	}
}
