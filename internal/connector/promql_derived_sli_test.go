package connector

import "testing"

func TestExtractPromQLDerivedSLI(t *testing.T) {
	result, found, err := ExtractPromQLDerivedSLI(`histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))`)
	if err != nil || !found {
		t.Fatalf("expected derived SLI expression, found=%v err=%v", found, err)
	}
	if len(result.Quantiles) != 1 || result.Quantiles[0] != 0.99 || result.DynamicQuantile {
		t.Fatalf("unexpected quantile model: %#v", result)
	}
	if len(result.InputMetrics) != 1 || result.InputMetrics[0] != "http_request_duration_seconds_bucket" {
		t.Fatalf("unexpected input metrics: %#v", result.InputMetrics)
	}
}

func TestExtractPromQLDerivedSLIDoesNotGuessFromNames(t *testing.T) {
	_, found, err := ExtractPromQLDerivedSLI(`job:latency:p99`)
	if err != nil || found {
		t.Fatalf("metric name alone must not become derived SLI evidence, found=%v err=%v", found, err)
	}
}

func TestExtractPromQLDerivedSLISupportsRecordingInputNames(t *testing.T) {
	result, found, err := ExtractPromQLDerivedSLI(`histogram_quantile(scalar(sli_quantile), job:http_request_duration:bucket_rate5m)`)
	if err != nil || !found || !result.DynamicQuantile {
		t.Fatalf("expected dynamic derived SLI, result=%#v found=%v err=%v", result, found, err)
	}
	if len(result.InputMetrics) != 1 || result.InputMetrics[0] != "job:http_request_duration:bucket_rate5m" {
		t.Fatalf("recording input was not modeled: %#v", result)
	}
}
