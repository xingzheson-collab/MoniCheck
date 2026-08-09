package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestLongSilenceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	longSilence := silenceResource("silence-long", now.Add(-time.Hour), now.Add(14*24*time.Hour), "active")
	longN9ESilence := silenceResource("n9e-silence-long", now.Add(-time.Hour), now.Add(14*24*time.Hour), "active")
	longN9ESilence.Source.System = "n9e"
	shortSilence := silenceResource("silence-short", now.Add(-time.Hour), now.Add(2*time.Hour), "active")
	expiredSilence := silenceResource("silence-expired", now.Add(-14*24*time.Hour), now.Add(-time.Hour), "expired")
	for _, resource := range []model.Resource{longSilence, longN9ESilence, shortSilence, expiredSilence} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert silence: %v", err)
		}
	}

	findings, err := NewLongSilenceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"long_silence_duration_threshold": "168h"},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected Alertmanager and N9E long silence findings, got %#v", findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
	}
	if !found[longSilence.ID] || !found[longN9ESilence.ID] {
		t.Fatalf("expected both long silence resources, got %#v", findings)
	}
}

func silenceResource(id string, startsAt time.Time, endsAt time.Time, state string) model.Resource {
	status := model.ResourceStatusActive
	if state == "expired" {
		status = model.ResourceStatusDeprecated
	}
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeSilence,
		Name:   id,
		Status: status,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataStartsAt:     startsAt.Format(time.RFC3339),
			model.MetadataEndsAt:       endsAt.Format(time.RFC3339),
			model.MetadataSilenceState: state,
		},
	}
}
