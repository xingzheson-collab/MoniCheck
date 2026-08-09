package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const SilenceWithoutCommentAnalyzerID = "builtin.silence_without_comment"

type SilenceWithoutCommentAnalyzer struct{}

func NewSilenceWithoutCommentAnalyzer() *SilenceWithoutCommentAnalyzer {
	return &SilenceWithoutCommentAnalyzer{}
}

func (a *SilenceWithoutCommentAnalyzer) ID() string      { return SilenceWithoutCommentAnalyzerID }
func (a *SilenceWithoutCommentAnalyzer) Name() string    { return "Silence Without Comment" }
func (a *SilenceWithoutCommentAnalyzer) Version() string { return "0.1.0" }
func (a *SilenceWithoutCommentAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeSilence}
}

func (a *SilenceWithoutCommentAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	silences, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeSilence})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, silence := range silences {
		if !activeGovernedSilence(silence) || strings.TrimSpace(silence.Metadata[model.MetadataSilenceComment]) != "" {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), silence.ID), Type: "SilenceWithoutComment",
			Severity: model.SeverityWarning, Category: model.FindingCategoryLifecycle,
			Resource:       model.ResourceRef{ID: silence.ID, Type: silence.Type, Name: silence.Name},
			Evidence:       []string{fmt.Sprintf("active %s silence %q has no operator comment", silence.Source.System, silence.Name)},
			Recommendation: "为静默补充维护窗口、关联变更、责任人和恢复条件；无法说明原因的静默应尽快复核或删除。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "silence_state": silence.Metadata[model.MetadataSilenceState], "created_by": silence.Metadata[model.MetadataSilenceCreatedBy]},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
