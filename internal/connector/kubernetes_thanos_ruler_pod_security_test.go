package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerPodSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: risky, namespace: monitoring}
spec:
  securityContext:
    runAsNonRoot: false
    runAsUser: 0
    seccompProfile: {type: Unconfined}
  containers:
    - name: thanos-ruler
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: false
        capabilities:
          add: [NET_ADMIN]
  initContainers:
    - name: bootstrap
      securityContext:
        windowsOptions: {hostProcess: true}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/risky"]
	expected := map[string]string{
		"thanos_ruler_root_user_context_count":                "1",
		"thanos_ruler_non_root_disabled_context_count":        "1",
		"thanos_ruler_privileged_container_count":             "1",
		"thanos_ruler_host_process_context_count":             "1",
		"thanos_ruler_privilege_escalation_context_count":     "1",
		"thanos_ruler_unconfined_seccomp_context_count":       "1",
		"thanos_ruler_capability_addition_context_count":      "1",
		"thanos_ruler_writable_root_filesystem_context_count": "1",
		"thanos_ruler_security_context_invalid_count":         "0",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedThanosRulerPodSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  securityContext:
    runAsNonRoot: enabled
    seccompProfile: {type: Unknown}
  containers:
    - name: thanos-ruler
      securityContext:
        privileged: enabled
        capabilities: {add: invalid}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["thanos_ruler_security_context_invalid_count"] != "4" {
		t.Fatalf("unexpected invalid security metadata: %#v", resource.Metadata)
	}
}
