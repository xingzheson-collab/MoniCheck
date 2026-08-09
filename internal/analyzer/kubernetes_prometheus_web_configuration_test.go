package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusWebConfigurationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := kubernetesPrometheusWebResource("invalid", "Prometheus", "false", "false", "false")
	invalid.Metadata["prometheus_web_invalid_setting_count"] = "2"
	zero := kubernetesPrometheusWebResource("zero", "PrometheusAgent", "false", "false", "false")
	zero.Metadata["prometheus_web_max_connections_declared"] = "true"
	zero.Metadata["prometheus_web_max_connections_valid"] = "true"
	zero.Metadata["prometheus_web_max_connections"] = "0"
	plaintext := kubernetesPrometheusWebResource("plaintext", "Prometheus", "true", "true", "false")
	plaintext.Metadata["prometheus_external_url_valid"] = "true"
	plaintext.Metadata["prometheus_external_url_scheme"] = "http"
	plaintextAgent := kubernetesPrometheusWebResource("plaintext-agent", "PrometheusAgent", "false", "false", "true")
	plaintextAgent.Metadata["prometheus_external_url_valid"] = "true"
	plaintextAgent.Metadata["prometheus_external_url_scheme"] = "http"
	httpWithoutSensitiveAPI := kubernetesPrometheusWebResource("http-safe", "Prometheus", "false", "false", "false")
	httpWithoutSensitiveAPI.Metadata["prometheus_external_url_valid"] = "true"
	httpWithoutSensitiveAPI.Metadata["prometheus_external_url_scheme"] = "http"
	httpsSensitiveAPI := kubernetesPrometheusWebResource("https-safe", "Prometheus", "true", "true", "true")
	httpsSensitiveAPI.Metadata["prometheus_external_url_valid"] = "true"
	httpsSensitiveAPI.Metadata["prometheus_external_url_scheme"] = "https"
	for _, resource := range []model.Resource{invalid, zero, plaintext, plaintextAgent, httpWithoutSensitiveAPI, httpsSensitiveAPI} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	invalidFindings, err := NewKubernetesInvalidPrometheusWebConfigurationAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(invalidFindings) != 1 || invalidFindings[0].Resource.ID != "invalid" || invalidFindings[0].Severity != model.SeverityCritical || invalidFindings[0].Category != model.FindingCategoryConfiguration {
		t.Fatalf("unexpected invalid web findings: findings=%#v err=%v", invalidFindings, err)
	}
	zeroFindings, err := NewKubernetesPrometheusWebConnectionsDisabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(zeroFindings) != 1 || zeroFindings[0].Resource.ID != "zero" || zeroFindings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected zero web connection findings: findings=%#v err=%v", zeroFindings, err)
	}
	plaintextFindings, err := NewKubernetesPlaintextExternalSensitiveAPIAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(plaintextFindings) != 2 || plaintextFindings[0].Resource.ID != "plaintext" || plaintextFindings[1].Resource.ID != "plaintext-agent" {
		t.Fatalf("unexpected plaintext sensitive API findings: findings=%#v err=%v", plaintextFindings, err)
	}
	for _, finding := range plaintextFindings {
		if finding.Severity != model.SeverityCritical || finding.Category != model.FindingCategorySecurity {
			t.Fatalf("unexpected plaintext finding classification: %#v", finding)
		}
	}
}
