package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerGRPCTLSWithoutRetainingPaths(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: secure-grpc, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  grpcServerTlsConfig:
    caFile: /private/ca.pem
    certFile: /private/cert.pem
    keyFile: /private/key.pem
    minVersion: TLS12
    cipherSuites: [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
    curves: [CurveP256]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/secure-grpc"]
	expected := map[string]string{"thanos_ruler_grpc_tls_metadata": "true", "thanos_ruler_grpc_tls_declared": "true", "thanos_ruler_grpc_tls_complete": "true", "thanos_ruler_grpc_tls_invalid_setting_count": "0", "thanos_ruler_grpc_tls_unsupported_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(key+value, "/private/") || strings.Contains(key+value, "TLS_ECDHE") || strings.Contains(key+value, "CurveP256") {
			t.Fatalf("gRPC TLS detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidAndUnsupportedThanosRulerGRPCTLS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid-grpc, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  grpcServerTlsConfig:
    caFile: {path: invalid}
    certFile: ""
    minVersion: TLS09
    cipherSuites: [duplicate, duplicate]
    cert: {secret: {name: unsupported, key: tls.crt}}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-grpc"]
	if resource.Metadata["thanos_ruler_grpc_tls_complete"] != "false" || resource.Metadata["thanos_ruler_grpc_tls_invalid_setting_count"] != "5" || resource.Metadata["thanos_ruler_grpc_tls_unsupported_setting_count"] != "1" {
		t.Fatalf("unexpected gRPC TLS metadata: %#v", resource.Metadata)
	}
}
