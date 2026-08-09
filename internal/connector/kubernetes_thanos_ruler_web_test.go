package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsValidThanosRulerWebConfiguration(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: secure-web, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  web:
    tlsConfig:
      cert: {secret: {name: private-web-cert, key: tls.crt}}
      keySecret: {name: private-web-cert, key: tls.key}
    httpConfig:
      http2: true
      headers: {contentSecurityPolicy: "default-src 'self'"}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/secure-web"]
	expected := map[string]string{"thanos_ruler_web_metadata": "true", "thanos_ruler_web_declared": "true", "thanos_ruler_web_object_valid": "true", "thanos_ruler_web_invalid_setting_count": "0", "thanos_ruler_web_tls_declared": "true", "thanos_ruler_web_tls_complete": "true", "thanos_ruler_web_http_config_declared": "true", "thanos_ruler_web_http2_valid": "true", "thanos_ruler_web_http2_enabled": "true"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		for _, secret := range []string{"private-web-cert", "tls.crt", "tls.key", "default-src"} {
			if strings.Contains(key, secret) || strings.Contains(value, secret) {
				t.Fatalf("web TLS/header detail persisted in %s=%q", key, value)
			}
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidThanosRulerWebConfiguration(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid-web, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  web:
    tlsConfig:
      certFile: /private/cert.pem
      cert: {secret: {name: duplicate-source, key: tls.crt}}
    httpConfig:
      http2: invalid
      headers: []
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-web"]
	if resource.Metadata["thanos_ruler_web_invalid_setting_count"] != "4" || resource.Metadata["thanos_ruler_web_tls_complete"] != "false" || resource.Metadata["thanos_ruler_web_http2_valid"] != "false" {
		t.Fatalf("unexpected web metadata: %#v", resource.Metadata)
	}
}

func TestKubernetesManifestConnectorTracksThanosRulerHTTP2WithoutTLS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: plaintext-http2, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  web: {httpConfig: {http2: true}}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/plaintext-http2"]
	if resource.Metadata["thanos_ruler_web_invalid_setting_count"] != "0" || resource.Metadata["thanos_ruler_web_http2_enabled"] != "true" || resource.Metadata["thanos_ruler_web_tls_complete"] != "false" {
		t.Fatalf("unexpected HTTP/2 metadata: %#v", resource.Metadata)
	}
}
