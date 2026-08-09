package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	LongSilenceAnalyzerID               = "builtin.long_silence"
	defaultLongSilenceDurationThreshold = 7 * 24 * time.Hour
)

type LongSilenceAnalyzer struct{}

func NewLongSilenceAnalyzer() *LongSilenceAnalyzer {
	return &LongSilenceAnalyzer{}
}

func (a *LongSilenceAnalyzer) ID() string {
	return LongSilenceAnalyzerID
}

func (a *LongSilenceAnalyzer) Name() string {
	return "Long Silence"
}

func (a *LongSilenceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *LongSilenceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeSilence}
}

func (a *LongSilenceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	silences, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeSilence})
	if err != nil {
		return nil, err
	}

	threshold := durationConfig(analysis.Config, "long_silence_duration_threshold", defaultLongSilenceDurationThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, silence := range silences {
		if !activeGovernedSilence(silence) {
			continue
		}
		startsAt, endsAt, ok := silenceWindow(silence)
		if !ok || endsAt.Before(now) {
			continue
		}
		duration := endsAt.Sub(startsAt)
		if duration <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), silence.ID),
			Type:     "LongSilence",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   silence.ID,
				Type: silence.Type,
				Name: silence.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s silence %q lasts %s, threshold is %s", silence.Source.System, silence.Name, duration.Round(time.Second), threshold),
			},
			Recommendation: "检查该静默是否仍然必要；长期静默通常应改为修正规则、调整路由、降低噪声或记录明确的维护窗口和过期时间。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"starts_at":   startsAt.Format(time.RFC3339),
				"ends_at":     endsAt.Format(time.RFC3339),
				"duration":    duration.Round(time.Second).String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func activeGovernedSilence(silence model.Resource) bool {
	if (silence.Source.System != "alertmanager" && silence.Source.System != "n9e") || silence.Status != model.ResourceStatusActive {
		return false
	}
	state := strings.ToLower(strings.TrimSpace(silence.Metadata[model.MetadataSilenceState]))
	return state == "active" || state == "pending"
}

func silenceWindow(silence model.Resource) (time.Time, time.Time, bool) {
	startsAt, err := time.Parse(time.RFC3339, strings.TrimSpace(silence.Metadata[model.MetadataStartsAt]))
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	endsAt, err := time.Parse(time.RFC3339, strings.TrimSpace(silence.Metadata[model.MetadataEndsAt]))
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	return startsAt, endsAt, true
}
