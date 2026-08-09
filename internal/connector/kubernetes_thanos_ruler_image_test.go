package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerImage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: pinned, namespace: monitoring}
spec:
  image: quay.io/thanos/thanos@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  imagePullPolicy: IfNotPresent
  imagePullSecrets: [{name: registry-auth}]
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: mutable, namespace: monitoring}
spec:
  image: quay.io/thanos/thanos:latest
  imagePullPolicy: Never
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  image: "not a valid image"
  imagePullPolicy: Sometimes
  imagePullSecrets: [{name: duplicate}, {name: duplicate}, {}]
  baseImage: quay.io/thanos/thanos
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	pinned := resources["monitoring/pinned"]
	if pinned.Metadata["thanos_ruler_image_valid"] != "true" || pinned.Metadata["thanos_ruler_image_digest_pinned"] != "true" || pinned.Metadata["thanos_ruler_image_pull_policy"] != "IfNotPresent" || pinned.Metadata["thanos_ruler_image_pull_secret_count"] != "1" {
		t.Fatalf("unexpected pinned image metadata: %#v", pinned.Metadata)
	}
	mutable := resources["monitoring/mutable"]
	if mutable.Metadata["thanos_ruler_image_latest_tag"] != "true" || mutable.Metadata["thanos_ruler_image_digest_pinned"] != "false" || mutable.Metadata["thanos_ruler_image_pull_policy"] != "Never" {
		t.Fatalf("unexpected mutable image metadata: %#v", mutable.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["thanos_ruler_unsupported_legacy_image_field_count"] != "1" || invalid.Metadata["thanos_ruler_image_invalid_setting_count"] != "5" {
		t.Fatalf("unexpected invalid image metadata: %#v", invalid.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			if value == "registry-auth" || value == "duplicate" || value == "quay.io/thanos/thanos" {
				t.Fatalf("image or pull-secret identity persisted in %s=%q", key, value)
			}
		}
	}
}
