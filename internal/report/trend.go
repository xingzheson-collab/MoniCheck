package report

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const defaultTrendWindowDays = 30

type TrendReport struct {
	GeneratedAt time.Time     `json:"generated_at"`
	WindowDays  int           `json:"window_days"`
	Since       time.Time     `json:"since"`
	ExportCount int           `json:"export_count"`
	Series      []TrendSeries `json:"series"`
}

type TrendSeries struct {
	Type       string            `json:"type"`
	PointCount int               `json:"point_count"`
	First      *TrendPoint       `json:"first,omitempty"`
	Latest     *TrendPoint       `json:"latest,omitempty"`
	Delta      map[string]int    `json:"delta"`
	Points     []TrendPoint      `json:"points"`
	Direction  map[string]string `json:"direction"`
}

type TrendPoint struct {
	ReportID    string         `json:"report_id"`
	Type        string         `json:"type"`
	CreatedAt   time.Time      `json:"created_at"`
	GeneratedAt time.Time      `json:"generated_at"`
	Metrics     map[string]int `json:"metrics"`
}

func BuildTrend(ctx context.Context, store *storage.Store, rawTypes []string, windowDays int) (TrendReport, error) {
	if windowDays <= 0 {
		windowDays = defaultTrendWindowDays
	}
	now := time.Now().UTC()
	since := now.AddDate(0, 0, -windowDays)
	exports, err := store.ReportExports.List(ctx)
	if err != nil {
		return TrendReport{}, err
	}

	typeSet := reportTypeSet(rawTypes)
	pointsByType := map[string][]TrendPoint{}
	exportCount := 0
	for _, export := range exports {
		if export.Format != "json" || export.CreatedAt.Before(since) {
			continue
		}
		if len(typeSet) > 0 && !typeSet[export.Type] {
			continue
		}
		point, ok := trendPoint(export)
		if !ok {
			continue
		}
		pointsByType[point.Type] = append(pointsByType[point.Type], point)
		exportCount++
	}

	series := make([]TrendSeries, 0, len(pointsByType))
	for reportType, points := range pointsByType {
		sort.Slice(points, func(i, j int) bool {
			return points[i].CreatedAt.Before(points[j].CreatedAt)
		})
		item := TrendSeries{
			Type:       reportType,
			PointCount: len(points),
			Delta:      map[string]int{},
			Direction:  map[string]string{},
			Points:     points,
		}
		if len(points) > 0 {
			first := points[0]
			latest := points[len(points)-1]
			item.First = &first
			item.Latest = &latest
			item.Delta = metricDelta(first.Metrics, latest.Metrics)
			for key, value := range item.Delta {
				switch {
				case value > 0:
					item.Direction[key] = "up"
				case value < 0:
					item.Direction[key] = "down"
				default:
					item.Direction[key] = "flat"
				}
			}
		}
		series = append(series, item)
	}
	sort.Slice(series, func(i, j int) bool {
		return series[i].Type < series[j].Type
	})

	return TrendReport{
		GeneratedAt: now,
		WindowDays:  windowDays,
		Since:       since,
		ExportCount: exportCount,
		Series:      series,
	}, nil
}

func reportTypeSet(rawTypes []string) map[string]bool {
	result := map[string]bool{}
	for _, raw := range rawTypes {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				result[part] = true
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func trendPoint(export model.ReportExport) (TrendPoint, bool) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
		return TrendPoint{}, false
	}
	metrics := trendMetrics(payload)
	if len(metrics) == 0 {
		return TrendPoint{}, false
	}
	generatedAt := export.CreatedAt
	if parsed, ok := parsePayloadTime(payload["generated_at"]); ok {
		generatedAt = parsed
	}
	return TrendPoint{
		ReportID:    export.ID,
		Type:        export.Type,
		CreatedAt:   export.CreatedAt,
		GeneratedAt: generatedAt,
		Metrics:     metrics,
	}, true
}

func trendMetrics(payload map[string]any) map[string]int {
	candidates := []string{
		"resource_count",
		"finding_count",
		"open_finding_count",
		"critical_count",
		"warning_count",
		"info_count",
		"owned_resource_count",
		"unowned_resource_count",
		"service_count",
		"attributed_resource_count",
		"attributed_finding_count",
		"coverage_service_count",
		"coverage_percent",
		"coverage_missing_signals",
		"coverage_unknown_signals",
		"coverage_evaluable_signals",
		"coverage_evidence_completeness_percent",
		"tsdb_count",
		"tsdb_head_series",
		"tsdb_head_chunks",
		"tsdb_label_value_count",
		"tsdb_label_memory_bytes",
	}
	metrics := map[string]int{}
	for _, key := range candidates {
		if value, ok := intPayloadValue(payload[key]); ok {
			metrics[key] = value
		}
	}
	return metrics
}

func intPayloadValue(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func parsePayloadTime(value any) (time.Time, bool) {
	raw, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func metricDelta(first map[string]int, latest map[string]int) map[string]int {
	delta := map[string]int{}
	seen := map[string]bool{}
	for key, latestValue := range latest {
		delta[key] = latestValue - first[key]
		seen[key] = true
	}
	for key, firstValue := range first {
		if seen[key] {
			continue
		}
		delta[key] = -firstValue
	}
	return delta
}
