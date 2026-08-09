package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestKubernetesManifestConnectorSyncsMonitoringTopology(t *testing.T) {
	manifest := `
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: prod
  labels:
    app: api
    team: platform
spec:
  selector:
    app: api
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-monitor
  namespace: prod
  labels:
    team: platform
spec:
  selector:
    matchLabels:
      app: api
  endpoints:
    - port: http
      path: /metrics
    - targetPort: metrics
`
	path := filepath.Join(t.TempDir(), "k8s.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeService, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 1)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeTarget, model.ResourceTypeService)

	var foundService bool
	var foundMonitor bool
	for _, resource := range snapshot.Resources {
		switch resource.Type {
		case model.ResourceTypeService:
			foundService = resource.Name == "prod/api" &&
				resource.Source.System == "kubernetes" &&
				resource.Metadata["kubernetes_kind"] == "Service" &&
				resource.Metadata["namespace"] == "prod" &&
				resource.Metadata["selector"] == "app=api" &&
				resource.Labels["team"] == "platform"
		case model.ResourceTypeTarget:
			foundMonitor = resource.Name == "prod/api-monitor" &&
				resource.Metadata["kubernetes_kind"] == "ServiceMonitor" &&
				resource.Metadata["selector"] == "app=api" &&
				resource.Metadata["endpoint_count"] == "2" &&
				resource.Metadata["endpoint_ports"] == "port=http,targetPort=metrics"
		}
	}
	if !foundService {
		t.Fatalf("expected kubernetes service metadata, got %#v", snapshot.Resources)
	}
	if !foundMonitor {
		t.Fatalf("expected kubernetes monitor metadata, got %#v", snapshot.Resources)
	}
}

func TestKubernetesManifestConnectorLinksMonitorDeclaredBeforeService(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-monitor
  namespace: prod
spec:
  selector:
    matchLabels:
      app: api
  endpoints:
    - port: http
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: prod
  labels:
    app: api
spec:
  selector:
    app: api
`
	path := filepath.Join(t.TempDir(), "k8s.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeService, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 1)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeTarget, model.ResourceTypeService)
}

func TestKubernetesManifestConnectorDefaultsNamespaceAndAvoidsCrossNamespaceMatch(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-monitor
spec:
  selector:
    matchLabels:
      app: api
  endpoints:
    - port: http
---
apiVersion: v1
kind: Service
metadata:
  name: api
  labels:
    app: api
spec:
  selector:
    app: api
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: prod
  labels:
    app: api
spec:
  selector:
    app: api
`
	path := filepath.Join(t.TempDir(), "k8s.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeService, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 1)

	var references []model.Relationship
	for _, relationship := range snapshot.Relationships {
		if relationship.Type == model.RelationshipReferences {
			references = append(references, relationship)
		}
	}
	if len(references) != 1 {
		t.Fatalf("expected one default namespace monitor relationship, got %#v", snapshot.Relationships)
	}
	service, ok := resourceByID(snapshot, references[0].ToID)
	if !ok {
		t.Fatalf("expected referenced service resource")
	}
	if service.Name != "default/api" || service.Metadata["namespace"] != "default" {
		t.Fatalf("expected default namespace service relationship, got %#v", service)
	}
	monitor, ok := resourceByID(snapshot, references[0].FromID)
	if !ok {
		t.Fatalf("expected monitor resource")
	}
	if monitor.Name != "default/api-monitor" || monitor.Metadata["namespace"] != "default" {
		t.Fatalf("expected default namespace monitor, got %#v", monitor)
	}
}

func TestKubernetesManifestConnectorSupportsMonitorNamespaceSelectorMatchNames(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api-monitor
  namespace: monitoring
spec:
  namespaceSelector:
    matchNames:
      - prod
  selector:
    matchLabels:
      app: api
  endpoints:
    - port: http
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: prod
  labels:
    app: api
spec:
  selector:
    app: api
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: staging
  labels:
    app: api
spec:
  selector:
    app: api
`
	path := filepath.Join(t.TempDir(), "k8s.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	var references []model.Relationship
	for _, relationship := range snapshot.Relationships {
		if relationship.Type == model.RelationshipReferences {
			references = append(references, relationship)
		}
	}
	if len(references) != 1 {
		t.Fatalf("expected one namespaceSelector relationship, got %#v", snapshot.Relationships)
	}
	service, ok := resourceByID(snapshot, references[0].ToID)
	if !ok {
		t.Fatalf("expected referenced service resource")
	}
	if service.Name != "prod/api" || service.Metadata["namespace"] != "prod" {
		t.Fatalf("expected prod service relationship, got %#v", service)
	}
	monitor, ok := resourceByID(snapshot, references[0].FromID)
	if !ok {
		t.Fatalf("expected monitor resource")
	}
	if monitor.Metadata["namespace_selector"] != "matchNames=prod" {
		t.Fatalf("expected namespace selector metadata, got %#v", monitor.Metadata)
	}
}

func TestKubernetesManifestConnectorLinksPodMonitorToPodInstance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: worker-monitor
  namespace: prod
spec:
  selector:
    matchLabels:
      app: worker
  podMetricsEndpoints:
    - port: metrics
---
apiVersion: v1
kind: Pod
metadata:
  name: worker-0
  namespace: prod
  labels:
    app: worker
---
apiVersion: v1
kind: Service
metadata:
  name: worker
  namespace: prod
  labels:
    app: worker
spec:
  selector:
    app: worker
`
	path := filepath.Join(t.TempDir(), "k8s.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeService, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 1)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeTarget, model.ResourceTypeInstance)

	var references []model.Relationship
	for _, relationship := range snapshot.Relationships {
		if relationship.Type == model.RelationshipReferences {
			references = append(references, relationship)
		}
	}
	if len(references) != 1 {
		t.Fatalf("expected one pod monitor relationship, got %#v", snapshot.Relationships)
	}
	target, ok := resourceByID(snapshot, references[0].ToID)
	if !ok {
		t.Fatalf("expected referenced pod instance")
	}
	if target.Type != model.ResourceTypeInstance || target.Name != "prod/worker-0" || target.Metadata["kubernetes_kind"] != "Pod" {
		t.Fatalf("expected pod instance relationship, got %#v", target)
	}
}

func TestKubernetesManifestConnectorMapsPrometheusRulesAndMetricLineage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api-slo
  namespace: prod
  labels:
    team: platform
spec:
  groups:
    - name: api-slo.rules
      interval: 30s
      rules:
        - record: service:http_requests:error_rate5m
          expr: |
            sum(rate(http_requests_total{service="api",code=~"5.."}[5m]))
            /
            sum(rate(http_requests_total{service="api"}[5m]))
          labels:
            service: api
            slo: api-availability
            objective: "99.9"
            window: 5m
        - alert: APIErrorBudgetBurn
          expr: service:http_requests:error_rate5m > 0.001
          for: 10m
          labels:
            service: api
            slo: api-availability
            severity: critical
          annotations:
            summary: API error budget is burning
`
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeRecordingRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 2)
	assertRelationshipByName(t, snapshot, model.RelationshipProduces, model.ResourceTypeRecordingRule, "service:http_requests:error_rate5m", model.ResourceTypeMetric, "service:http_requests:error_rate5m")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeRecordingRule, "service:http_requests:error_rate5m", model.ResourceTypeMetric, "http_requests_total")
	assertRelationshipByName(t, snapshot, model.RelationshipProduces, model.ResourceTypeMetric, "http_requests_total", model.ResourceTypeMetric, "service:http_requests:error_rate5m")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIErrorBudgetBurn", model.ResourceTypeMetric, "service:http_requests:error_rate5m")

	var alertRuleID string
	for _, resource := range snapshot.Resources {
		switch resource.Type {
		case model.ResourceTypeRecordingRule:
			if resource.Metadata["kubernetes_kind"] != "PrometheusRule" ||
				resource.Metadata["namespace"] != "prod" ||
				resource.Metadata["prometheus_rule"] != "prod/api-slo" ||
				resource.Metadata[model.MetadataRuleGroup] != "api-slo.rules" ||
				resource.Metadata[model.MetadataEvaluationInterval] != "30s" ||
				resource.Metadata[model.MetadataRecordingRuleOutput] != "service:http_requests:error_rate5m" ||
				resource.Metadata[model.MetadataQueryLength] == "" ||
				resource.Metadata[model.MetadataSLORule] != "true" ||
				resource.Metadata[model.MetadataSLOName] != "api-availability" ||
				resource.Metadata[model.MetadataSLOObjective] != "99.9" ||
				resource.Metadata[model.MetadataSLOWindow] != "5m" ||
				resource.Labels["team"] != "platform" ||
				resource.Labels["service"] != "api" {
				t.Fatalf("unexpected recording rule: %#v", resource)
			}
		case model.ResourceTypeAlertRule:
			alertRuleID = resource.ID
			if resource.Metadata[model.MetadataAlertFor] != "10m" ||
				resource.Metadata["annotation.summary"] != "API error budget is burning" ||
				resource.Metadata[model.MetadataSLORule] != "true" ||
				resource.Labels["team"] != "platform" ||
				resource.Labels["severity"] != "critical" {
				t.Fatalf("unexpected alert rule: %#v", resource)
			}
		}
	}

	enriched := EnrichBusinessServices(snapshot, time.Unix(0, 0).UTC())
	assertResourceCount(t, enriched, model.ResourceTypeService, 1)
	assertServiceOwnership(t, enriched, "api", "", "platform")
	assertServiceRelationship(t, enriched, alertRuleID, "api", "label.service")
}

func TestKubernetesManifestConnectorSkipsInvalidPrometheusRuleRows(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: invalid
spec:
  groups:
    - name: invalid.rules
      rules:
        - expr: up == 0
        - alert: ValidAlert
          expr: up == 0
`
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeRecordingRule, 0)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "ValidAlert", model.ResourceTypeMetric, "up")
}

func TestKubernetesManifestConnectorMapsPrometheusOperatorProbes(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Probe
metadata:
  name: checkout-public
  namespace: prod
  labels:
    team: platform
spec:
  jobName: checkout-probe
  module: http_2xx
  interval: 30s
  scrapeTimeout: 10s
  prober:
    url: blackbox-exporter.monitoring.svc:9115
    scheme: http
    path: /probe
  targets:
    staticConfig:
      static:
        - https://checkout.example.com/health
        - https://checkout.example.com/ready
      labels:
        service: checkout
---
apiVersion: monitoring.coreos.com/v1
kind: Probe
metadata:
  name: public-ingresses
  namespace: monitoring
spec:
  prober:
    url: blackbox-exporter.monitoring.svc:9115
  targets:
    ingress:
      selector:
        matchLabels:
          probe: enabled
      namespaceSelector:
        any: true
`
	path := filepath.Join(t.TempDir(), "probes.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 2)
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeTarget {
			continue
		}
		if resource.Metadata["kubernetes_kind"] != "Probe" || resource.UID == "" {
			t.Fatalf("expected Probe target identity, got %#v", resource)
		}
		if strings.Contains(resource.Name, "checkout.example.com") || strings.Contains(fmt.Sprint(resource.Metadata), "checkout.example.com") {
			t.Fatalf("did not expect static target URLs to be persisted, got %#v", resource)
		}
		switch resource.Name {
		case "prod/checkout-public":
			if resource.Metadata["probe_job_name"] != "checkout-probe" ||
				resource.Metadata["probe_module"] != "http_2xx" ||
				resource.Metadata["probe_prober_url"] != "blackbox-exporter.monitoring.svc:9115" ||
				resource.Metadata["probe_prober_scheme"] != "http" ||
				resource.Metadata["probe_prober_path"] != "/probe" ||
				resource.Metadata["probe_target_mode"] != "static" ||
				resource.Metadata["probe_target_count"] != "2" ||
				resource.Metadata[model.MetadataScrapeInterval] != "30s" ||
				resource.Metadata[model.MetadataScrapeTimeout] != "10s" ||
				resource.Labels["service"] != "checkout" || resource.Labels["team"] != "platform" {
				t.Fatalf("unexpected static Probe resource: %#v", resource)
			}
		case "monitoring/public-ingresses":
			if resource.Metadata["probe_target_mode"] != "ingress" ||
				resource.Metadata["selector"] != "probe=enabled" ||
				resource.Metadata["namespace_selector"] != "*" {
				t.Fatalf("unexpected ingress Probe resource: %#v", resource)
			}
		default:
			t.Fatalf("unexpected Probe resource: %#v", resource)
		}
	}
}

func TestKubernetesManifestConnectorMapsPrometheusOperatorScrapeConfigs(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata:
  name: billing-static
  namespace: prod
  labels:
    team: platform
spec:
  jobName: billing-exporters
  metricsPath: /custom-metrics
  scheme: https
  scrapeInterval: 30s
  scrapeTimeout: 10s
  staticConfigs:
    - targets:
        - exporter-a.example.com:9100
        - exporter-b.example.com:9100
      labels:
        service: billing
        environment: prod
    - targets:
        - exporter-c.example.com:9100
      labels:
        service: billing
        environment: prod
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata:
  name: discovered
  namespace: monitoring
spec:
  kubernetesSDConfigs:
    - role: Node
  httpSDConfigs:
    - url: https://discovery.example.com/targets
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata:
  name: empty-static
  namespace: prod
spec:
  staticConfigs:
    - labels:
        service: empty
`
	path := filepath.Join(t.TempDir(), "scrape-configs.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 3)
	for _, resource := range snapshot.Resources {
		if resource.Metadata["kubernetes_kind"] != "ScrapeConfig" {
			continue
		}
		serialized := fmt.Sprint(resource.Metadata, resource.Labels, resource.Name)
		if strings.Contains(serialized, "exporter-a.example.com") || strings.Contains(serialized, "discovery.example.com") {
			t.Fatalf("did not expect scrape target or discovery URLs to be persisted, got %#v", resource)
		}
		switch resource.Name {
		case "prod/billing-static":
			if resource.Metadata["scrape_config_job_name"] != "billing-exporters" ||
				resource.Metadata["scrape_config_metrics_path"] != "/custom-metrics" ||
				resource.Metadata["scrape_config_scheme"] != "https" ||
				resource.Metadata["scrape_config_static_count"] != "2" ||
				resource.Metadata["scrape_config_empty_static_count"] != "0" ||
				resource.Metadata["scrape_config_static_target_count"] != "3" ||
				resource.Metadata["scrape_config_discovery_count"] != "0" ||
				resource.Metadata[model.MetadataScrapeInterval] != "30s" ||
				resource.Metadata[model.MetadataScrapeTimeout] != "10s" ||
				resource.Labels["service"] != "billing" || resource.Labels["environment"] != "prod" || resource.Labels["team"] != "platform" {
				t.Fatalf("unexpected static ScrapeConfig: %#v", resource)
			}
		case "monitoring/discovered":
			if resource.Metadata["scrape_config_static_count"] != "0" ||
				resource.Metadata["scrape_config_discovery_count"] != "2" ||
				resource.Metadata["scrape_config_discovery_types"] != "http,kubernetes" {
				t.Fatalf("unexpected discovered ScrapeConfig: %#v", resource)
			}
		case "prod/empty-static":
			if resource.Metadata["scrape_config_static_count"] != "1" ||
				resource.Metadata["scrape_config_empty_static_count"] != "1" ||
				resource.Metadata["scrape_config_static_target_count"] != "0" {
				t.Fatalf("unexpected empty ScrapeConfig: %#v", resource)
			}
		default:
			t.Fatalf("unexpected ScrapeConfig resource: %#v", resource)
		}
	}
}

func TestKubernetesManifestConnectorExpandsKubernetesList(t *testing.T) {
	manifest := `
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata:
      name: api
      namespace: prod
      labels:
        app: api
    spec:
      selector:
        app: api
  - apiVersion: monitoring.coreos.com/v1
    kind: ServiceMonitor
    metadata:
      name: api-monitor
      namespace: prod
    spec:
      selector:
        matchLabels:
          app: api
      endpoints:
        - targetPort: 9090
  - apiVersion: monitoring.coreos.com/v1
    kind: PrometheusRule
    metadata:
      name: api-rules
      namespace: prod
    spec:
      groups:
        - name: api.rules
          rules:
            - alert: APIUnavailable
              expr: up{service="api"} == 0
              labels:
                service: api
`
	path := filepath.Join(t.TempDir(), "list.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeService, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeAlertRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeMetric, 1)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeTarget, model.ResourceTypeService)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeAlertRule, "APIUnavailable", model.ResourceTypeMetric, "up")

	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeTarget && resource.Metadata["endpoint_ports"] != "targetPort=9090" {
			t.Fatalf("expected numeric targetPort to be normalized, got %#v", resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorReadsDirectoryAndLinksAcrossFiles(t *testing.T) {
	directory := t.TempDir()
	service := `
apiVersion: v1
kind: Service
metadata:
  name: checkout
  namespace: prod
  labels:
    app: checkout
spec:
  selector:
    app: checkout
`
	monitor := `
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: checkout-monitor
  namespace: prod
spec:
  selector:
    matchLabels:
      app: checkout
  endpoints:
    - port: metrics
`
	if err := os.WriteFile(filepath.Join(directory, "service.yaml"), []byte(service), 0o600); err != nil {
		t.Fatalf("write service: %v", err)
	}
	nested := filepath.Join(directory, "monitoring")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("create nested directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "monitor.yml"), []byte(monitor), 0o600); err != nil {
		t.Fatalf("write monitor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "README.txt"), []byte("kind: [ignored"), 0o600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	connector, err := NewKubernetesManifestConnector(directory)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeService, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTarget, 1)
	assertRelationship(t, snapshot, model.RelationshipReferences, model.ResourceTypeTarget, model.ResourceTypeService)
	for _, resource := range snapshot.Resources {
		if resource.Source.Instance != directory {
			t.Fatalf("expected directory source instance %q, got %#v", directory, resource.Source)
		}
		if resource.UID == "" || resource.UID != resource.ID {
			t.Fatalf("expected data-flow-compatible resource UID, got %#v", resource)
		}
	}
}

func TestKubernetesManifestConnectorMapsPrometheusSelections(t *testing.T) {
	manifest := `
apiVersion: v1
kind: Namespace
metadata:
  name: prod
  labels:
    environment: production
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  name: main
  namespace: monitoring
spec:
  version: v3.5.0
  replicas: 2
  shards: 2
  serviceMonitorSelector:
    matchLabels:
      team: platform
  serviceMonitorNamespaceSelector:
    matchLabels:
      environment: production
  podMonitorSelector:
    matchExpressions:
      - key: team
        operator: In
        values: [platform]
  podMonitorNamespaceSelector:
    matchLabels:
      environment: production
  probeSelector: {}
  scrapeConfigSelector:
    matchExpressions:
      - key: prometheus
        operator: In
        values: [main]
  scrapeConfigNamespaceSelector: {}
  ruleSelector:
    matchLabels:
      role: alert-rules
  ruleNamespaceSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: selected
  namespace: prod
  labels:
    team: platform
spec:
  endpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: unselected
  namespace: prod
  labels:
    team: product
spec:
  endpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: unknown-namespace
  namespace: workloads
  labels:
    team: platform
spec:
  podMetricsEndpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: Probe
metadata:
  name: local-probe
  namespace: monitoring
spec:
  prober: {url: blackbox-exporter:9115}
  targets:
    staticConfig:
      static: [https://example.invalid]
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata:
  name: selected-scrape
  namespace: prod
  labels:
    prometheus: main
spec:
  staticConfigs:
    - targets: [exporter:9100]
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: platform-rules
  namespace: prod
  labels:
    role: alert-rules
spec:
  groups:
    - name: availability
      rules:
        - alert: APIUnavailable
          expr: up == 0
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}

	assertResourceCount(t, snapshot, model.ResourceTypeTSDB, 1)
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeTSDB, "monitoring/main", model.ResourceTypeTarget, "prod/selected")
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeTSDB, "monitoring/main", model.ResourceTypeTarget, "monitoring/local-probe")
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeTSDB, "monitoring/main", model.ResourceTypeTarget, "prod/selected-scrape")
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeTSDB, "monitoring/main", model.ResourceTypeAlertRule, "APIUnavailable")

	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	if resources["prod/selected"].Metadata["prometheus_selected_count"] != "1" {
		t.Fatalf("expected selected ServiceMonitor metadata, got %#v", resources["prod/selected"].Metadata)
	}
	if resources["prod/unselected"].Metadata["prometheus_selection_evaluable"] != "true" || resources["prod/unselected"].Metadata["prometheus_selected_count"] != "0" {
		t.Fatalf("expected conclusive unselected metadata, got %#v", resources["prod/unselected"].Metadata)
	}
	if resources["workloads/unknown-namespace"].Metadata["prometheus_selection_evaluable"] != "false" {
		t.Fatalf("expected unknown namespace labels to remain unevaluable, got %#v", resources["workloads/unknown-namespace"].Metadata)
	}
	if resources["monitoring/main"].Metadata["prometheus_selected_resource_count"] != "4" || resources["monitoring/main"].Metadata["prometheus_nonzero_selected_resource_count"] != "4" || resources["monitoring/main"].Metadata["prometheus_desired_pod_count"] != "4" || resources["monitoring/main"].Metadata["prometheus_version"] != "v3.5.0" {
		t.Fatalf("unexpected Prometheus metadata: %#v", resources["monitoring/main"].Metadata)
	}
}

func TestKubernetesManifestConnectorMarksSelectionByZeroReplicaPrometheus(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  name: dormant
  namespace: monitoring
spec:
  replicas: 0
  serviceMonitorSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: api
  namespace: monitoring
spec:
  endpoints: [{port: metrics}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	if resources["monitoring/dormant"].Metadata["prometheus_desired_pod_count"] != "0" || resources["monitoring/dormant"].Metadata["prometheus_replicas_declared"] != "true" || resources["monitoring/dormant"].Metadata["prometheus_shards"] != "1" {
		t.Fatalf("unexpected zero-replica Prometheus metadata: %#v", resources["monitoring/dormant"].Metadata)
	}
	if resources["monitoring/api"].Metadata["prometheus_selected_count"] != "1" || resources["monitoring/api"].Metadata["prometheus_nonzero_selected_count"] != "0" {
		t.Fatalf("expected target to be selected only by zero-replica Prometheus, got %#v", resources["monitoring/api"].Metadata)
	}
}

func TestKubernetesManifestConnectorMapsPrometheusAgentSelections(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata:
  name: edge
  namespace: monitoring
spec:
  mode: StatefulSet
  replicas: 2
  serviceMonitorSelector:
    matchLabels:
      agent: edge
  ruleSelector: {}
  remoteWrite:
    - url: https://remote.example.invalid/api/v1/write
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: edge-app
  namespace: monitoring
  labels:
    agent: edge
spec:
  endpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: ignored-by-agent
  namespace: monitoring
spec:
  groups:
    - name: edge
      rules:
        - alert: EdgeDown
          expr: up == 0
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	agent := resources["monitoring/edge"]
	if agent.Metadata["kubernetes_kind"] != "PrometheusAgent" || agent.Metadata["prometheus_mode"] != "agent" || agent.Metadata["prometheus_agent_mode"] != "statefulset" || agent.Metadata["prometheus_remote_write_count"] != "1" || agent.Metadata["prometheus_desired_pod_count"] != "2" {
		t.Fatalf("unexpected PrometheusAgent metadata: %#v", agent.Metadata)
	}
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeTSDB, "monitoring/edge", model.ResourceTypeTarget, "monitoring/edge-app")
	for _, relationship := range snapshot.Relationships {
		if relationship.FromID == agent.ID && resources["EdgeDown"].ID == relationship.ToID {
			t.Fatalf("PrometheusAgent must not select PrometheusRule resources: %#v", relationship)
		}
	}
	if resources["monitoring/edge-app"].Metadata["prometheus_selected_count"] != "1" {
		t.Fatalf("expected monitor selected by PrometheusAgent, got %#v", resources["monitoring/edge-app"].Metadata)
	}
}

func TestKubernetesManifestConnectorTreatsDaemonSetAgentAsDeployable(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: node-agent, namespace: monitoring}
spec:
  mode: DaemonSet
  replicas: 0
  podMonitorSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: nodes, namespace: monitoring}
spec:
  podMetricsEndpoints: [{port: metrics}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	for _, resource := range snapshot.Resources {
		if resource.Name == "monitoring/nodes" && resource.Metadata["prometheus_nonzero_selected_count"] != "1" {
			t.Fatalf("expected DaemonSet agent to provide nonzero coverage, got %#v", resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorMapsThanosRulerRuleSelections(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: main-ruler, namespace: monitoring}
spec:
  version: v0.39.2
  replicas: 2
  queryEndpoints: [dnssrv+_http._tcp.thanos-query.monitoring.svc]
  ruleSelector:
    matchLabels: {ruler: main}
  ruleNamespaceSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: selected
  namespace: prod
  labels: {ruler: main}
spec:
  groups:
    - name: availability
      rules:
        - {alert: APIUnavailable, expr: "up == 0"}
        - {record: "job:up:sum", expr: "sum(up) by (job)"}
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: unselected
  namespace: prod
  labels: {ruler: other}
spec:
  groups:
    - name: capacity
      rules:
        - {alert: CapacityLow, expr: "capacity_available < 1"}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	ruler := resources["monitoring/main-ruler"]
	if ruler.Type != model.ResourceTypeInstance || ruler.Metadata["thanos_ruler_version"] != "v0.39.2" || ruler.Metadata["thanos_ruler_replicas"] != "2" || ruler.Metadata["thanos_ruler_query_endpoint_count"] != "1" || ruler.Metadata["thanos_ruler_selected_rule_count"] != "2" || ruler.Metadata["thanos_ruler_selected_alert_rule_count"] != "1" {
		t.Fatalf("unexpected ThanosRuler metadata: %#v", ruler)
	}
	for key, value := range ruler.Metadata {
		if strings.Contains(key, "endpoint") && strings.Contains(value, "thanos-query") {
			t.Fatalf("query endpoint value must not be persisted: %s=%q", key, value)
		}
	}
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeInstance, "monitoring/main-ruler", model.ResourceTypeAlertRule, "APIUnavailable")
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeInstance, "monitoring/main-ruler", model.ResourceTypeRecordingRule, "job:up:sum")
	if resources["APIUnavailable"].Metadata["rule_evaluator_selected_count"] != "1" || resources["APIUnavailable"].Metadata["rule_evaluator_nonzero_selected_count"] != "1" {
		t.Fatalf("expected selected rule coverage, got %#v", resources["APIUnavailable"].Metadata)
	}
	if resources["CapacityLow"].Metadata["rule_evaluator_selection_evaluable"] != "true" || resources["CapacityLow"].Metadata["rule_evaluator_selected_count"] != "0" {
		t.Fatalf("expected conclusive unselected rule, got %#v", resources["CapacityLow"].Metadata)
	}
}

func TestKubernetesManifestConnectorMarksRuleSelectedByZeroReplicaThanosRuler(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: dormant, namespace: monitoring}
spec:
  replicas: 0
  queryConfig: {name: thanos-query, key: endpoints.yaml}
  ruleSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: {name: rules, namespace: monitoring}
spec:
  groups:
    - name: test
      rules:
        - {alert: DormantRule, expr: "up == 0"}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	for _, resource := range snapshot.Resources {
		if resource.Name == "DormantRule" && (resource.Metadata["rule_evaluator_selected_count"] != "1" || resource.Metadata["rule_evaluator_nonzero_selected_count"] != "0") {
			t.Fatalf("unexpected zero-replica rule coverage: %#v", resource.Metadata)
		}
		if resource.Name == "monitoring/dormant" && resource.Metadata["thanos_ruler_query_config_declared"] != "true" {
			t.Fatalf("expected queryConfig declaration metadata: %#v", resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerConfigTopology(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: main, namespace: monitoring}
spec:
  version: v0.28.1
  replicas: 3
  alertmanagerConfigSelector:
    matchLabels: {alertmanager: main}
  alertmanagerConfigNamespaceSelector: {}
---
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata:
  name: platform-routing
  namespace: prod
  labels: {alertmanager: main}
spec:
  route:
    receiver: default
    groupBy: [alertname]
    routes:
      - receiver: pager
        matchers:
          - {name: severity, matchType: "=", value: critical}
        muteTimeIntervals: [maintenance]
      - receiver: missing
  receivers:
    - name: default
      webhookConfigs:
        - url: http://notify.example.invalid/hook
    - name: pager
      pagerdutyConfigs:
        - routingKey: {name: pagerduty, key: token}
  inhibitRules:
    - sourceMatch:
        - {name: severity, matchType: "=", value: critical}
      targetMatch:
        - {name: severity, matchType: "=~", value: warning|info}
      equal: [alertname]
  timeIntervals:
    - name: maintenance
      timeIntervals:
        - weekdays: [saturday]
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: AlertmanagerConfig
metadata:
  name: ignored-routing
  namespace: prod
  labels: {alertmanager: other}
spec:
  route: {receiver: ignored}
  receivers:
    - name: ignored
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeNotificationPolicy, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeReceiver, 4)
	assertResourceCount(t, snapshot, model.ResourceTypeInhibitionRule, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeTimeInterval, 1)
	assertRelationshipByName(t, snapshot, model.RelationshipReferences, model.ResourceTypeInstance, "monitoring/main", model.ResourceTypeNotificationPolicy, "prod/platform-routing")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeNotificationPolicy, "prod/platform-routing", model.ResourceTypeReceiver, "pager")

	var alertmanager, selectedPolicy, ignoredPolicy, defaultReceiver, inhibition model.Resource
	for _, resource := range snapshot.Resources {
		switch {
		case resource.Name == "monitoring/main":
			alertmanager = resource
		case resource.Name == "prod/platform-routing":
			selectedPolicy = resource
		case resource.Name == "prod/ignored-routing":
			ignoredPolicy = resource
		case resource.Type == model.ResourceTypeReceiver && resource.Name == "default":
			defaultReceiver = resource
		case resource.Type == model.ResourceTypeInhibitionRule:
			inhibition = resource
		}
	}
	if alertmanager.Metadata["alertmanager_selected_config_count"] != "1" || alertmanager.Metadata["alertmanager_replicas"] != "3" || alertmanager.Metadata["alertmanager_version"] != "v0.28.1" {
		t.Fatalf("unexpected Alertmanager metadata: %#v", alertmanager.Metadata)
	}
	if selectedPolicy.Metadata["alertmanager_selected_count"] != "1" || selectedPolicy.Metadata["alertmanager_nonzero_selected_count"] != "1" || selectedPolicy.Metadata[model.MetadataPolicyDefaultReceiver] != "default" || selectedPolicy.Metadata[model.MetadataPolicyRouteCount] != "3" {
		t.Fatalf("unexpected selected policy metadata: %#v", selectedPolicy.Metadata)
	}
	if ignoredPolicy.Metadata["alertmanager_selection_evaluable"] != "true" || ignoredPolicy.Metadata["alertmanager_selected_count"] != "0" {
		t.Fatalf("unexpected ignored policy metadata: %#v", ignoredPolicy.Metadata)
	}
	if defaultReceiver.Metadata[model.MetadataReceiverIntegrations] != "webhook" || defaultReceiver.Metadata[model.MetadataReceiverInsecureEndpointCount] != "1" {
		t.Fatalf("unexpected receiver metadata: %#v", defaultReceiver.Metadata)
	}
	if inhibition.Metadata[model.MetadataInhibitionSourceMatcherCount] != "1" || inhibition.Metadata[model.MetadataInhibitionTargetRegexCount] != "1" || inhibition.Metadata[model.MetadataInhibitionEqualLabelCount] != "1" {
		t.Fatalf("unexpected inhibition metadata: %#v", inhibition.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for _, value := range resource.Metadata {
			if strings.Contains(value, "notify.example.invalid") || strings.Contains(value, "pagerduty") && strings.Contains(value, "token") {
				t.Fatalf("sensitive AlertmanagerConfig value persisted: %#v", resource.Metadata)
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsGlobalAlertmanagerConfiguration(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: dormant, namespace: monitoring}
spec:
  replicas: 0
  alertmanagerConfiguration: {name: global-routing}
---
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata: {name: global-routing, namespace: monitoring}
spec:
  route: {receiver: default}
  receivers:
    - name: default
      emailConfigs:
        - to: platform@example.invalid
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	for _, resource := range snapshot.Resources {
		if resource.Name == "monitoring/global-routing" && (resource.Metadata["alertmanager_selected_count"] != "1" || resource.Metadata["alertmanager_nonzero_selected_count"] != "0") {
			t.Fatalf("unexpected global config coverage: %#v", resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorMapsScrapeClassTopology(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: main, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  serviceMonitorNamespaceSelector: {}
  scrapeClasses:
    - name: mesh
      tlsConfig:
        caFile: /etc/istio/root.pem
        insecureSkipVerify: true
    - name: mesh
      relabelings:
        - {action: labeldrop, regex: secret}
    - name: default-a
      default: true
    - name: default-b
      default: true
    - name: unused
      authorization:
        credentials: {name: scrape-token, key: token}
    - default: false
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: explicit, namespace: prod}
spec:
  scrapeClass: mesh
  endpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: inherited, namespace: prod}
spec:
  endpoints: [{port: metrics}]
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: missing, namespace: prod}
spec:
  scrapeClassName: absent
  endpoints: [{port: metrics}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeScrapeClass, 4)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeTarget, "prod/explicit", model.ResourceTypeScrapeClass, "mesh")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeTarget, "prod/inherited", model.ResourceTypeScrapeClass, "default-a")

	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	workload := resources["monitoring/main"]
	if workload.Metadata["scrape_class_count"] != "6" || workload.Metadata["scrape_class_default_count"] != "2" || workload.Metadata["scrape_class_unnamed_count"] != "1" || workload.Metadata["scrape_class_duplicate_name_count"] != "1" {
		t.Fatalf("unexpected scrape class set metadata: %#v", workload.Metadata)
	}
	if resources["mesh"].Metadata["scrape_class_definition_count"] != "2" || resources["mesh"].Metadata["scrape_class_usage_count"] != "1" || resources["mesh"].Metadata["scrape_class_tls_config_declared"] != "true" || resources["mesh"].Metadata["scrape_class_tls_insecure"] != "true" || resources["mesh"].Metadata["scrape_class_relabeling_count"] != "1" {
		t.Fatalf("unexpected mesh class metadata: %#v", resources["mesh"].Metadata)
	}
	if resources["unused"].Metadata["scrape_class_usage_count"] != "0" || resources["unused"].Metadata["scrape_class_authorization_declared"] != "true" {
		t.Fatalf("unexpected unused class metadata: %#v", resources["unused"].Metadata)
	}
	if resources["prod/missing"].Metadata["scrape_class"] != "absent" || resources["prod/missing"].Metadata["scrape_class_resolution_evaluable"] != "true" || resources["prod/missing"].Metadata["scrape_class_missing_workload_count"] != "1" {
		t.Fatalf("unexpected missing class resolution: %#v", resources["prod/missing"].Metadata)
	}
	if resources["prod/inherited"].Metadata["scrape_class_applied_count"] != "2" {
		t.Fatalf("expected both invalid defaults to remain visible, got %#v", resources["prod/inherited"].Metadata)
	}
	for _, resource := range snapshot.Resources {
		for _, value := range resource.Metadata {
			if strings.Contains(value, "/etc/istio") || strings.Contains(value, "scrape-token") {
				t.Fatalf("scrape class secret/path persisted: %#v", resource.Metadata)
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsRemoteWriteTopology(t *testing.T) {
	manifest := `
apiVersion: v1
kind: Namespace
metadata: {name: prod, labels: {tenant: enabled}}
---
apiVersion: v1
kind: Namespace
metadata: {name: dev, labels: {tenant: disabled}}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: main, namespace: monitoring}
spec:
  remoteWriteSelector: {matchLabels: {team: platform}}
  remoteWriteNamespaceSelector: {matchLabels: {tenant: enabled}}
  remoteWrite:
    - name: shared
      url: https://metrics.example.invalid/api/v1/write
      authorization: {credentials: {name: remote-token, key: token}}
    - name: shared
      url: http://legacy.example.invalid/write
      tlsConfig: {insecureSkipVerify: true, caFile: /etc/private/ca.pem}
    - name: broken
      basicAuth: {username: {name: basic-secret, key: username}}
      oauth2: {clientSecret: {name: oauth-secret, key: secret}}
      headers: {X-Tenant: secret-tenant}
      proxyUrl: http://proxy.example.invalid
      queueConfig: {capacity: -1, minShards: 8, maxShards: 2, maxSamplesPerSend: 0}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: edge, namespace: monitoring}
spec:
  remoteWrite:
    - name: edge
      url: https://edge.example.invalid/write
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: ruler, namespace: monitoring}
spec:
  queryEndpoints: [http://query.monitoring.svc]
  remoteWrite:
    - name: ruler
      url: https://ruler.example.invalid/write
      sigv4: {accessKey: {name: aws-secret, key: access}}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: RemoteWrite
metadata: {name: tenant, namespace: prod, labels: {team: platform}}
spec:
  name: shared
  url: https://tenant.example.invalid/write
  sigv4:
    accessKey: {name: tenant-aws-secret, key: access}
    secretKey: {name: tenant-aws-secret, key: secret}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: RemoteWrite
metadata: {name: ignored, namespace: dev, labels: {team: platform}}
spec:
  url: https://ignored.example.invalid/write
  queueConfig: {maxShards: nope}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeExporter, 7)
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeTSDB, "monitoring/main", model.ResourceTypeExporter, "prod/tenant")
	assertRelationshipByName(t, snapshot, model.RelationshipUses, model.ResourceTypeInstance, "monitoring/ruler", model.ResourceTypeExporter, "ruler")

	resources := map[string]model.Resource{}
	var broken, insecure model.Resource
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
		if resource.Type == model.ResourceTypeExporter && resource.Metadata["remote_write_parent_name"] == "monitoring/main" {
			switch resource.Metadata["remote_write_name"] {
			case "broken":
				broken = resource
			case "shared":
				if resource.Metadata["remote_write_url_scheme"] == "http" {
					insecure = resource
				}
			}
		}
	}
	main := resources["monitoring/main"]
	if main.Metadata["remote_write_inline_count"] != "3" || main.Metadata["remote_write_selected_crd_count"] != "1" || main.Metadata["remote_write_effective_count"] != "4" || main.Metadata["prometheus_remote_write_count"] != "4" || main.Metadata["remote_write_duplicate_name_count"] != "1" {
		t.Fatalf("unexpected Prometheus remote write metadata: %#v", main.Metadata)
	}
	if resources["monitoring/edge"].Metadata["prometheus_remote_write_count"] != "1" || resources["monitoring/ruler"].Metadata["thanos_ruler_remote_write_count"] != "1" {
		t.Fatalf("unexpected Agent/Ruler remote write counts: edge=%#v ruler=%#v", resources["monitoring/edge"].Metadata, resources["monitoring/ruler"].Metadata)
	}
	if resources["prod/tenant"].Metadata["remote_write_selected_count"] != "1" || resources["prod/tenant"].Metadata["remote_write_sigv4_declared"] != "true" || resources["prod/tenant"].Metadata["remote_write_crd_proposal"] != "true" {
		t.Fatalf("unexpected selected RemoteWrite CRD metadata: %#v", resources["prod/tenant"].Metadata)
	}
	if resources["dev/ignored"].Metadata["remote_write_selection_evaluable"] != "true" || resources["dev/ignored"].Metadata["remote_write_selected_count"] != "0" || resources["dev/ignored"].Metadata["remote_write_queue_max_shards_declared"] != "true" || resources["dev/ignored"].Metadata["remote_write_queue_max_shards_valid"] != "false" || resources["dev/ignored"].Metadata["remote_write_queue_invalid"] != "true" {
		t.Fatalf("unexpected ignored RemoteWrite CRD metadata: %#v", resources["dev/ignored"].Metadata)
	}
	if broken.Metadata["remote_write_destination_declared"] != "false" || broken.Metadata["remote_write_auth_method_count"] != "2" || broken.Metadata["remote_write_header_count"] != "1" || broken.Metadata["remote_write_queue_capacity"] != "-1" || broken.Metadata["remote_write_queue_min_shards"] != "8" || broken.Metadata["remote_write_queue_max_shards"] != "2" || broken.Metadata["remote_write_queue_invalid"] != "true" || broken.Metadata["remote_write_queue_issue_count"] != "3" {
		t.Fatalf("unexpected broken RemoteWrite metadata: %#v", broken.Metadata)
	}
	if insecure.Metadata["remote_write_url_scheme"] != "http" || insecure.Metadata["remote_write_tls_insecure"] != "true" {
		t.Fatalf("unexpected insecure RemoteWrite metadata: %#v", insecure.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			if strings.Contains(value, "example.invalid") || strings.Contains(value, "remote-token") || strings.Contains(value, "basic-secret") || strings.Contains(value, "oauth-secret") || strings.Contains(value, "tenant-aws-secret") || strings.Contains(value, "secret-tenant") || strings.Contains(value, "/etc/private") || strings.Contains(value, "proxy.example") {
				t.Fatalf("sensitive RemoteWrite value persisted in %s=%q: %#v", key, value, resource.Metadata)
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsRemoteReadTopology(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: main, namespace: monitoring}
spec:
  remoteRead:
    - name: shared
      url: https://metrics.example.invalid/api/v1/read
      authorization: {credentials: {name: remote-token, key: token}}
      requiredMatchers: {tenant: secret-tenant}
      headers: {X-Tenant: secret-header}
      remoteTimeout: 30s
    - name: shared
      url: http://legacy.example.invalid/read
      tlsConfig: {insecureSkipVerify: true, caFile: /etc/private/ca.pem}
    - name: broken
      basicAuth: {username: {name: basic-secret, key: username}}
      oauth2: {clientSecret: {name: oauth-secret, key: secret}}
      readRecent: true
      filterExternalLabels: false
      proxyUrl: http://proxy.example.invalid
    - name: token
      url: https://token.example.invalid/read
      bearerToken: super-secret-token
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: edge, namespace: monitoring}
spec:
  remoteRead:
    - name: ignored
      url: https://ignored.example.invalid/read
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeDatasource, 4)
	resources := map[string]model.Resource{}
	var sharedHTTPS, broken, token model.Resource
	remoteReadUses := 0
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
		if resource.Type != model.ResourceTypeDatasource || resource.Metadata["kubernetes_kind"] != "RemoteRead" {
			continue
		}
		switch {
		case resource.Metadata["remote_read_name"] == "shared" && resource.Metadata["remote_read_url_scheme"] == "https":
			sharedHTTPS = resource
		case resource.Metadata["remote_read_name"] == "broken":
			broken = resource
		case resource.Metadata["remote_read_name"] == "token":
			token = resource
		}
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.Type == model.RelationshipUses && relationship.Metadata["usage_kind"] == "RemoteRead" {
			remoteReadUses++
		}
	}
	if remoteReadUses != 4 {
		t.Fatalf("expected four RemoteRead USES relationships, got %d", remoteReadUses)
	}
	main := resources["monitoring/main"]
	if main.Metadata["prometheus_remote_read_count"] != "4" || main.Metadata["remote_read_duplicate_name_count"] != "1" {
		t.Fatalf("unexpected Prometheus remote read metadata: %#v", main.Metadata)
	}
	if resources["monitoring/edge"].Metadata["prometheus_remote_read_count"] != "0" {
		t.Fatalf("PrometheusAgent must ignore unsupported remoteRead: %#v", resources["monitoring/edge"].Metadata)
	}
	if sharedHTTPS.Metadata["remote_read_required_matcher_count"] != "1" || sharedHTTPS.Metadata["remote_read_header_count"] != "1" || sharedHTTPS.Metadata["remote_read_remote_timeout"] != "30s" || sharedHTTPS.Metadata["remote_read_auth_method_count"] != "1" || sharedHTTPS.Metadata["datasource_health_evaluable"] != "false" {
		t.Fatalf("unexpected valid RemoteRead metadata: %#v", sharedHTTPS.Metadata)
	}
	if broken.Metadata["remote_read_destination_declared"] != "false" || broken.Metadata["remote_read_auth_method_count"] != "2" || broken.Metadata["remote_read_read_recent"] != "true" || broken.Metadata["remote_read_filter_external_labels"] != "false" || broken.Metadata["remote_read_required_matcher_count"] != "0" || broken.Metadata["remote_read_proxy_declared"] != "true" {
		t.Fatalf("unexpected broad RemoteRead metadata: %#v", broken.Metadata)
	}
	if token.Metadata["remote_read_cleartext_bearer_declared"] != "true" || token.Metadata["remote_read_auth_method_count"] != "1" {
		t.Fatalf("unexpected bearer RemoteRead metadata: %#v", token.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, secret := range []string{"example.invalid", "secret-tenant", "secret-header", "remote-token", "basic-secret", "oauth-secret", "super-secret-token", "/etc/private", "proxy.example"} {
				if strings.Contains(value, secret) {
					t.Fatalf("sensitive RemoteRead value persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsPrometheusStorageGovernance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: persistent, namespace: monitoring}
spec:
  retention: 15d
  retentionSize: 90GB
  walCompression: true
  storage:
    volumeClaimTemplate:
      spec:
        storageClassName: secret-storage-class
        selector: {matchLabels: {private-volume: selected}}
        resources: {requests: {storage: 100Gi}}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: default-storage, namespace: monitoring}
spec: {}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: conflict, namespace: monitoring}
spec:
  retention: forever
  retentionSize: lots
  walCompression: false
  storage:
    emptyDir: {}
    volumeClaimTemplate:
      spec: {resources: {requests: {storage: 20Gi}}}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: undersized, namespace: monitoring}
spec:
  retentionSize: 100GB
  storage:
    volumeClaimTemplate:
      spec: {resources: {requests: {storage: 80Gi}}}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: compaction-off, namespace: monitoring}
spec:
  disableCompaction: true
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: thanos-storage, namespace: monitoring}
spec:
  disableCompaction: true
  thanos:
    objectStorageConfig: {name: thanos-secret, key: object-store.yaml}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: thanos-file, namespace: monitoring}
spec:
  thanos:
    objectStorageConfigFile: /etc/thanos/private-object-store.yaml
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: edge, namespace: monitoring}
spec:
  walCompression: false
  retention: forever
  retentionSize: lots
  storage: {ephemeral: {}}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	persistent := resources["monitoring/persistent"]
	if persistent.Metadata["prometheus_storage_mode"] != "pvc" || persistent.Metadata["prometheus_storage_option_count"] != "1" || persistent.Metadata["prometheus_pvc_request_bytes"] != "107374182400" || persistent.Metadata["prometheus_retention_seconds"] != "1296000" || persistent.Metadata["prometheus_retention_size_bytes"] != "96636764160" || persistent.Metadata["prometheus_wal_compression_enabled"] != "true" {
		t.Fatalf("unexpected persistent storage metadata: %#v", persistent.Metadata)
	}
	defaultStorage := resources["monitoring/default-storage"]
	if defaultStorage.Metadata["prometheus_storage_mode"] != "default-empty-dir" || defaultStorage.Metadata["prometheus_storage_option_count"] != "0" || defaultStorage.Metadata["prometheus_retention_declared"] != "false" || defaultStorage.Metadata["prometheus_retention_size_declared"] != "false" || defaultStorage.Metadata["prometheus_wal_compression_declared"] != "false" || defaultStorage.Metadata["prometheus_wal_compression_enabled"] != "true" {
		t.Fatalf("unexpected default storage metadata: %#v", defaultStorage.Metadata)
	}
	conflict := resources["monitoring/conflict"]
	if conflict.Metadata["prometheus_storage_mode"] != "empty-dir" || conflict.Metadata["prometheus_storage_option_count"] != "2" || conflict.Metadata["prometheus_retention_valid"] != "false" || conflict.Metadata["prometheus_retention_size_valid"] != "false" || conflict.Metadata["prometheus_wal_compression_declared"] != "true" || conflict.Metadata["prometheus_wal_compression_enabled"] != "false" {
		t.Fatalf("unexpected conflicting storage metadata: %#v", conflict.Metadata)
	}
	undersized := resources["monitoring/undersized"]
	if undersized.Metadata["prometheus_storage_mode"] != "pvc" || undersized.Metadata["prometheus_pvc_request_bytes"] != "85899345920" || undersized.Metadata["prometheus_retention_size_bytes"] != "107374182400" || undersized.Metadata["prometheus_retention_exceeds_pvc"] != "true" {
		t.Fatalf("unexpected undersized storage metadata: %#v", undersized.Metadata)
	}
	compactionOff := resources["monitoring/compaction-off"]
	if compactionOff.Metadata["prometheus_disable_compaction"] != "true" || compactionOff.Metadata["prometheus_thanos_object_storage_declared"] != "false" {
		t.Fatalf("unexpected unowned compaction metadata: %#v", compactionOff.Metadata)
	}
	thanosStorage := resources["monitoring/thanos-storage"]
	if thanosStorage.Metadata["prometheus_disable_compaction"] != "true" || thanosStorage.Metadata["prometheus_thanos_object_storage_declared"] != "true" {
		t.Fatalf("unexpected Thanos object storage metadata: %#v", thanosStorage.Metadata)
	}
	thanosFile := resources["monitoring/thanos-file"]
	if thanosFile.Metadata["prometheus_disable_compaction"] != "false" || thanosFile.Metadata["prometheus_thanos_object_storage_declared"] != "true" {
		t.Fatalf("unexpected Thanos object storage file metadata: %#v", thanosFile.Metadata)
	}
	agent := resources["monitoring/edge"]
	if agent.Metadata["prometheus_storage_mode"] != "ephemeral" || agent.Metadata["prometheus_wal_compression_enabled"] != "false" || agent.Metadata["prometheus_retention_declared"] != "false" || agent.Metadata["prometheus_retention_size_declared"] != "false" {
		t.Fatalf("unexpected Agent storage metadata: %#v", agent.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			if strings.Contains(value, "secret-storage-class") || strings.Contains(value, "private-volume") || strings.Contains(value, "selected") || strings.Contains(value, "thanos-secret") || strings.Contains(value, "object-store.yaml") || strings.Contains(value, "/etc/thanos") {
				t.Fatalf("storage implementation detail persisted in %s=%q: %#v", key, value, resource.Metadata)
			}
		}
	}
}

func TestPrometheusStorageQuantityParsing(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		prometheus bool
		want       int64
		valid      bool
	}{
		{name: "prometheus GB", value: "2GB", prometheus: true, want: 2 * 1024 * 1024 * 1024, valid: true},
		{name: "kubernetes Gi", value: "1.5Gi", want: 1610612736, valid: true},
		{name: "kubernetes decimal G", value: "2G", want: 2_000_000_000, valid: true},
		{name: "missing unit permitted for pvc", value: "1024", want: 1024, valid: true},
		{name: "invalid", value: "lots", valid: false},
		{name: "zero", value: "0Gi", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got int64
			var valid bool
			if test.prometheus {
				got, valid = parsePrometheusByteSize(test.value)
			} else {
				got, valid = parseKubernetesStorageQuantity(test.value)
			}
			if got != test.want || valid != test.valid {
				t.Fatalf("parse %q: got bytes=%d valid=%t, want bytes=%d valid=%t", test.value, got, valid, test.want, test.valid)
			}
		})
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerStorageGovernance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: default-storage, namespace: monitoring}
spec: {}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: ha-empty, namespace: monitoring}
spec:
  replicas: 3
  retention: 120h
  storage: {emptyDir: {}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: persistent, namespace: monitoring}
spec:
  retention: 24h
  storage:
    volumeClaimTemplate:
      spec:
        storageClassName: private-storage-class
        selector: {matchLabels: {private-volume: selected}}
        resources: {requests: {storage: 10Gi}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: conflict, namespace: monitoring}
spec:
  retention: 1h30m
  storage:
    emptyDir: {}
    ephemeral: {}
    volumeClaimTemplate:
      spec: {resources: {requests: {storage: 5Gi}}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: immediate, namespace: monitoring}
spec:
  version: v0.25.0
  terminationGracePeriodSeconds: 0
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid-grace, namespace: monitoring}
spec:
  terminationGracePeriodSeconds: -1
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: old-version, namespace: monitoring}
spec:
  version: v0.24.0
  terminationGracePeriodSeconds: 120
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	defaultStorage := resources["monitoring/default-storage"]
	if defaultStorage.Metadata["alertmanager_storage_mode"] != "default-empty-dir" || defaultStorage.Metadata["alertmanager_storage_option_count"] != "0" || defaultStorage.Metadata["alertmanager_retention_declared"] != "false" {
		t.Fatalf("unexpected default Alertmanager metadata: %#v", defaultStorage.Metadata)
	}
	haEmpty := resources["monitoring/ha-empty"]
	if haEmpty.Metadata["alertmanager_storage_mode"] != "empty-dir" || haEmpty.Metadata["alertmanager_storage_option_count"] != "1" || haEmpty.Metadata["alertmanager_retention_valid"] != "true" || haEmpty.Metadata["alertmanager_retention_milliseconds"] != "432000000" {
		t.Fatalf("unexpected HA Alertmanager metadata: %#v", haEmpty.Metadata)
	}
	persistent := resources["monitoring/persistent"]
	if persistent.Metadata["alertmanager_storage_mode"] != "pvc" || persistent.Metadata["alertmanager_pvc_request_valid"] != "true" || persistent.Metadata["alertmanager_pvc_request_bytes"] != "10737418240" || persistent.Metadata["alertmanager_retention_milliseconds"] != "86400000" {
		t.Fatalf("unexpected persistent Alertmanager metadata: %#v", persistent.Metadata)
	}
	conflict := resources["monitoring/conflict"]
	if conflict.Metadata["alertmanager_storage_mode"] != "empty-dir" || conflict.Metadata["alertmanager_storage_option_count"] != "3" || conflict.Metadata["alertmanager_retention_declared"] != "true" || conflict.Metadata["alertmanager_retention_valid"] != "false" {
		t.Fatalf("unexpected conflicting Alertmanager metadata: %#v", conflict.Metadata)
	}
	immediate := resources["monitoring/immediate"]
	if immediate.Metadata["alertmanager_termination_grace_valid"] != "true" || immediate.Metadata["alertmanager_termination_grace_seconds"] != "0" || immediate.Metadata["alertmanager_termination_grace_version_unsupported"] != "false" {
		t.Fatalf("unexpected immediate termination metadata: %#v", immediate.Metadata)
	}
	invalidGrace := resources["monitoring/invalid-grace"]
	if invalidGrace.Metadata["alertmanager_termination_grace_declared"] != "true" || invalidGrace.Metadata["alertmanager_termination_grace_valid"] != "false" {
		t.Fatalf("unexpected invalid grace metadata: %#v", invalidGrace.Metadata)
	}
	oldVersion := resources["monitoring/old-version"]
	if oldVersion.Metadata["alertmanager_termination_grace_version_evaluable"] != "true" || oldVersion.Metadata["alertmanager_termination_grace_version_unsupported"] != "true" {
		t.Fatalf("unexpected old-version grace metadata: %#v", oldVersion.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, private := range []string{"private-storage-class", "private-volume", "selected"} {
				if strings.Contains(value, private) {
					t.Fatalf("Alertmanager storage detail persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestAlertmanagerRetentionParsing(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int64
		valid bool
	}{{"120h", 432000000, true}, {"1ms", 1, true}, {"0h", 0, false}, {"5d", 0, false}, {"1h30m", 0, false}, {"", 0, false}} {
		got, valid := parseAlertmanagerRetention(test.value)
		if got != test.want || valid != test.valid {
			t.Fatalf("parse Alertmanager retention %q: got %d valid=%t, want %d valid=%t", test.value, got, valid, test.want, test.valid)
		}
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerLimits(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: default-limits, namespace: monitoring}
spec: {version: v0.28.0}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: bounded, namespace: monitoring}
spec:
  version: v0.28.0
  limits: {maxSilences: 5000, maxPerSilenceBytes: 1MB}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: disabled, namespace: monitoring}
spec:
  version: v0.28.0
  limits: {maxSilences: 0, maxPerSilenceBytes: 0}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  limits: {maxSilences: -1, maxPerSilenceBytes: lots}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid-object, namespace: monitoring}
spec: {limits: enabled}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: old, namespace: monitoring}
spec:
  version: v0.27.0
  limits: {maxSilences: 100}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	defaults := resources["monitoring/default-limits"]
	if defaults.Metadata["alertmanager_limits_declared"] != "false" || defaults.Metadata["alertmanager_max_silences_enabled"] != "false" || defaults.Metadata["alertmanager_max_per_silence_bytes_enabled"] != "false" {
		t.Fatalf("unexpected default limits metadata: %#v", defaults.Metadata)
	}
	bounded := resources["monitoring/bounded"]
	if bounded.Metadata["alertmanager_max_silences"] != "5000" || bounded.Metadata["alertmanager_max_silences_enabled"] != "true" || bounded.Metadata["alertmanager_max_per_silence_bytes"] != "1048576" || bounded.Metadata["alertmanager_max_per_silence_bytes_enabled"] != "true" || bounded.Metadata["alertmanager_limits_version_unsupported"] != "false" {
		t.Fatalf("unexpected bounded limits metadata: %#v", bounded.Metadata)
	}
	disabled := resources["monitoring/disabled"]
	if disabled.Metadata["alertmanager_max_silences_valid"] != "true" || disabled.Metadata["alertmanager_max_per_silence_bytes_valid"] != "true" || disabled.Metadata["alertmanager_max_silences_enabled"] != "false" || disabled.Metadata["alertmanager_max_per_silence_bytes_enabled"] != "false" {
		t.Fatalf("unexpected disabled limits metadata: %#v", disabled.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["alertmanager_limits_invalid_setting_count"] != "2" {
		t.Fatalf("unexpected invalid limits metadata: %#v", invalid.Metadata)
	}
	invalidObject := resources["monitoring/invalid-object"]
	if invalidObject.Metadata["alertmanager_limits_object_valid"] != "false" || invalidObject.Metadata["alertmanager_limits_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected invalid limits object metadata: %#v", invalidObject.Metadata)
	}
	old := resources["monitoring/old"]
	if old.Metadata["alertmanager_limits_version_evaluable"] != "true" || old.Metadata["alertmanager_limits_version_unsupported"] != "true" {
		t.Fatalf("unexpected old-version limits metadata: %#v", old.Metadata)
	}
}

func TestAlertmanagerLimitByteSizeParsing(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int64
		valid bool
	}{{"0", 0, true}, {"0B", 0, true}, {"1MB", 1048576, true}, {"2GB", 2147483648, true}, {"1MiB", 0, false}, {"lots", 0, false}, {"-1", 0, false}} {
		got, valid := parseAlertmanagerLimitByteSize(test.value)
		if got != test.want || valid != test.valid {
			t.Fatalf("parse Alertmanager silence byte limit %q: got %d valid=%t, want %d valid=%t", test.value, got, valid, test.want, test.valid)
		}
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: safe, namespace: monitoring}
spec:
  version: v0.24.0
  replicas: 3
  hostNetwork: false
  automountServiceAccountToken: false
  clusterTLS:
    server: {cert: {secret: {name: private-server, key: tls.crt}}, keySecret: {name: private-server, key: tls.key}}
    client: {ca: {secret: {name: private-ca, key: ca.crt}}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: exposed, namespace: monitoring}
spec:
  replicas: 3
  hostNetwork: true
  automountServiceAccountToken: true
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: incomplete, namespace: monitoring}
spec:
  clusterTLS: {server: {}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: old, namespace: monitoring}
spec:
  version: v0.23.0
  clusterTLS: {server: {}, client: {}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: malformed, namespace: monitoring}
spec:
  hostNetwork: enabled
  automountServiceAccountToken: enabled
  clusterTLS: enabled
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	safe := resources["monitoring/safe"]
	if safe.Metadata["alertmanager_host_network_enabled"] != "false" || safe.Metadata["alertmanager_automount_token_enabled"] != "false" || safe.Metadata["alertmanager_cluster_tls_complete"] != "true" || safe.Metadata["alertmanager_cluster_tls_version_unsupported"] != "false" {
		t.Fatalf("unexpected safe Alertmanager security metadata: %#v", safe.Metadata)
	}
	exposed := resources["monitoring/exposed"]
	if exposed.Metadata["alertmanager_host_network_enabled"] != "true" || exposed.Metadata["alertmanager_automount_token_enabled"] != "true" || exposed.Metadata["alertmanager_cluster_tls_declared"] != "false" {
		t.Fatalf("unexpected exposed Alertmanager security metadata: %#v", exposed.Metadata)
	}
	incomplete := resources["monitoring/incomplete"]
	if incomplete.Metadata["alertmanager_cluster_tls_complete"] != "false" || incomplete.Metadata["alertmanager_cluster_tls_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected incomplete cluster TLS metadata: %#v", incomplete.Metadata)
	}
	old := resources["monitoring/old"]
	if old.Metadata["alertmanager_cluster_tls_version_evaluable"] != "true" || old.Metadata["alertmanager_cluster_tls_version_unsupported"] != "true" {
		t.Fatalf("unexpected old cluster TLS metadata: %#v", old.Metadata)
	}
	malformed := resources["monitoring/malformed"]
	if malformed.Metadata["alertmanager_host_network_declared"] != "true" || malformed.Metadata["alertmanager_host_network_valid"] != "false" || malformed.Metadata["alertmanager_automount_token_valid"] != "false" || malformed.Metadata["alertmanager_cluster_tls_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected malformed security metadata: %#v", malformed.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, secret := range []string{"private-server", "private-ca", "tls.crt", "tls.key", "ca.crt"} {
				if strings.Contains(value, secret) {
					t.Fatalf("Alertmanager TLS secret detail persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerArguments(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: supported, namespace: monitoring}
spec:
  version: v0.27.0
  enableFeatures: [utf8-strict-mode]
  additionalArgs:
    - {name: secret-hidden-flag, value: private-value}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: duplicate, namespace: monitoring}
spec:
  enableFeatures: [feature-a, feature-a, ""]
  additionalArgs:
    - {name: arg-a, value: first-secret}
    - {name: arg-a, value: second-secret}
    - {value: missing-name-secret}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: malformed, namespace: monitoring}
spec:
  enableFeatures: enabled
  additionalArgs: enabled
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: old-feature, namespace: monitoring}
spec:
  version: v0.26.0
  enableFeatures: [feature-a]
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: old-args, namespace: monitoring}
spec:
  version: v0.24.0
  additionalArgs: [{name: arg-a, value: private-old-value}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	supported := resources["monitoring/supported"]
	if supported.Metadata["alertmanager_feature_count"] != "1" || supported.Metadata["alertmanager_feature_version_unsupported"] != "false" || supported.Metadata["alertmanager_additional_arg_count"] != "1" || supported.Metadata["alertmanager_additional_args_version_unsupported"] != "false" {
		t.Fatalf("unexpected supported argument metadata: %#v", supported.Metadata)
	}
	duplicate := resources["monitoring/duplicate"]
	if duplicate.Metadata["alertmanager_feature_count"] != "2" || duplicate.Metadata["alertmanager_feature_invalid_count"] != "1" || duplicate.Metadata["alertmanager_feature_duplicate_count"] != "1" || duplicate.Metadata["alertmanager_additional_arg_count"] != "2" || duplicate.Metadata["alertmanager_additional_arg_invalid_count"] != "1" || duplicate.Metadata["alertmanager_additional_arg_duplicate_count"] != "1" {
		t.Fatalf("unexpected duplicate argument metadata: %#v", duplicate.Metadata)
	}
	malformed := resources["monitoring/malformed"]
	if malformed.Metadata["alertmanager_feature_invalid_count"] != "1" || malformed.Metadata["alertmanager_additional_arg_invalid_count"] != "1" {
		t.Fatalf("unexpected malformed argument metadata: %#v", malformed.Metadata)
	}
	oldFeature := resources["monitoring/old-feature"]
	if oldFeature.Metadata["alertmanager_feature_version_evaluable"] != "true" || oldFeature.Metadata["alertmanager_feature_version_unsupported"] != "true" {
		t.Fatalf("unexpected old feature metadata: %#v", oldFeature.Metadata)
	}
	oldArgs := resources["monitoring/old-args"]
	if oldArgs.Metadata["alertmanager_additional_args_version_evaluable"] != "true" || oldArgs.Metadata["alertmanager_additional_args_version_unsupported"] != "true" {
		t.Fatalf("unexpected old additionalArgs metadata: %#v", oldArgs.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, secret := range []string{"utf8-strict-mode", "secret-hidden-flag", "private-value", "feature-a", "arg-a", "first-secret", "second-secret", "missing-name-secret", "private-old-value"} {
				if strings.Contains(value, secret) {
					t.Fatalf("Alertmanager argument detail persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerWeb(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: defaults, namespace: monitoring}
spec: {}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: bounded, namespace: monitoring}
spec:
  externalUrl: https://alerts.example.invalid/private/path
  web:
    getConcurrency: 0
    timeout: 30
    tlsConfig: {cert: {secret: {name: private-web-cert, key: tls.crt}}}
    httpConfig: {headers: {X-Frame-Options: Deny}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: zero-timeout, namespace: monitoring}
spec: {web: {timeout: 0}}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  web:
    getConcurrency: -1
    timeout: lots
    tlsConfig: enabled
    httpConfig: enabled
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid-object, namespace: monitoring}
spec: {web: enabled}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: plaintext, namespace: monitoring}
spec: {externalUrl: http://alerts.example.invalid/secret-path}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	defaults := resources["monitoring/defaults"]
	if defaults.Metadata["alertmanager_web_metadata"] != "true" || defaults.Metadata["alertmanager_web_declared"] != "false" || defaults.Metadata["alertmanager_web_timeout_enabled"] != "false" {
		t.Fatalf("unexpected default Alertmanager web metadata: %#v", defaults.Metadata)
	}
	bounded := resources["monitoring/bounded"]
	if bounded.Metadata["alertmanager_web_get_concurrency_valid"] != "true" || bounded.Metadata["alertmanager_web_get_concurrency"] != "0" || bounded.Metadata["alertmanager_web_timeout_seconds"] != "30" || bounded.Metadata["alertmanager_web_timeout_enabled"] != "true" || bounded.Metadata["alertmanager_web_tls_declared"] != "true" || bounded.Metadata["alertmanager_web_http_config_declared"] != "true" || bounded.Metadata["alertmanager_external_url_scheme"] != "https" {
		t.Fatalf("unexpected bounded Alertmanager web metadata: %#v", bounded.Metadata)
	}
	zero := resources["monitoring/zero-timeout"]
	if zero.Metadata["alertmanager_web_timeout_valid"] != "true" || zero.Metadata["alertmanager_web_timeout_seconds"] != "0" || zero.Metadata["alertmanager_web_timeout_enabled"] != "false" {
		t.Fatalf("unexpected zero-timeout metadata: %#v", zero.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["alertmanager_web_invalid_setting_count"] != "4" {
		t.Fatalf("unexpected invalid Alertmanager web metadata: %#v", invalid.Metadata)
	}
	invalidObject := resources["monitoring/invalid-object"]
	if invalidObject.Metadata["alertmanager_web_object_valid"] != "false" || invalidObject.Metadata["alertmanager_web_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected invalid Alertmanager web object metadata: %#v", invalidObject.Metadata)
	}
	plaintext := resources["monitoring/plaintext"]
	if plaintext.Metadata["alertmanager_external_url_valid"] != "true" || plaintext.Metadata["alertmanager_external_url_scheme"] != "http" {
		t.Fatalf("unexpected plaintext external URL metadata: %#v", plaintext.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, private := range []string{"alerts.example.invalid", "private/path", "secret-path", "private-web-cert", "tls.crt", "X-Frame-Options"} {
				if strings.Contains(value, private) {
					t.Fatalf("Alertmanager web detail persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsAlertmanagerClusterAdvertiseAddress(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: routable, namespace: monitoring}
spec:
  replicas: 3
  additionalPeers: [peer-one.private.example:9094]
  clusterAdvertiseAddress: 10.20.30.40:9094
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: loopback, namespace: monitoring}
spec: {replicas: 2, clusterAdvertiseAddress: "127.0.0.1:9094"}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: wildcard, namespace: monitoring}
spec: {forceEnableClusterMode: true, clusterAdvertiseAddress: "[::]:9094"}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: malformed, namespace: monitoring}
spec:
  additionalPeers: [missing-port.example]
  clusterAdvertiseAddress: bad_host:9094
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	routable := resources["monitoring/routable"]
	if routable.Metadata["alertmanager_cluster_advertise_address_declared"] != "true" || routable.Metadata["alertmanager_cluster_advertise_address_valid"] != "true" || routable.Metadata["alertmanager_cluster_advertise_address_loopback"] != "false" || routable.Metadata["alertmanager_cluster_advertise_address_unspecified"] != "false" || routable.Metadata["alertmanager_additional_peer_invalid_count"] != "0" {
		t.Fatalf("unexpected routable advertise metadata: %#v", routable.Metadata)
	}
	loopback := resources["monitoring/loopback"]
	if loopback.Metadata["alertmanager_cluster_advertise_address_loopback"] != "true" {
		t.Fatalf("unexpected loopback advertise metadata: %#v", loopback.Metadata)
	}
	wildcard := resources["monitoring/wildcard"]
	if wildcard.Metadata["alertmanager_cluster_advertise_address_unspecified"] != "true" {
		t.Fatalf("unexpected wildcard advertise metadata: %#v", wildcard.Metadata)
	}
	malformed := resources["monitoring/malformed"]
	if malformed.Metadata["alertmanager_cluster_advertise_address_valid"] != "false" || malformed.Metadata["alertmanager_additional_peer_invalid_count"] != "1" {
		t.Fatalf("unexpected malformed advertise metadata: %#v", malformed.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, private := range []string{"peer-one.private.example", "10.20.30.40", "127.0.0.1", "missing-port.example", "bad_host"} {
				if strings.Contains(value, private) {
					t.Fatalf("Alertmanager cluster address persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsPrometheusQueryGovernance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: guarded, namespace: monitoring}
spec:
  scrapeInterval: 30s
  query: {maxConcurrency: 20, maxSamples: 50000000, timeout: 2m, lookbackDelta: 5m}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: permissive, namespace: monitoring}
spec:
  scrapeInterval: 15s
  query: {maxConcurrency: 40, maxSamples: 100000000, timeout: 5m, lookbackDelta: 10m}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  scrapeInterval: 30s
  query: {maxConcurrency: 0, maxSamples: -1, timeout: never, lookbackDelta: 0s}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: gap, namespace: monitoring}
spec:
  scrapeInterval: 30s
  query: {lookbackDelta: 15s}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: malformed, namespace: monitoring}
spec:
  query: invalid-object
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: edge, namespace: monitoring}
spec:
  query: {maxConcurrency: 1000, maxSamples: 999999999, timeout: 1h, lookbackDelta: 1h}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	guarded := resources["monitoring/guarded"]
	if guarded.Metadata["prometheus_query_max_concurrency"] != "20" || guarded.Metadata["prometheus_query_max_samples"] != "50000000" || guarded.Metadata["prometheus_query_timeout_seconds"] != "120" || guarded.Metadata["prometheus_query_lookback_seconds"] != "300" || guarded.Metadata["prometheus_scrape_interval_seconds"] != "30" || guarded.Metadata["prometheus_query_invalid_setting_count"] != "0" || guarded.Metadata["prometheus_query_lookback_below_scrape_interval"] != "false" {
		t.Fatalf("unexpected guarded query metadata: %#v", guarded.Metadata)
	}
	permissive := resources["monitoring/permissive"]
	if permissive.Metadata["prometheus_query_max_concurrency"] != "40" || permissive.Metadata["prometheus_query_max_samples"] != "100000000" || permissive.Metadata["prometheus_query_timeout_seconds"] != "300" || permissive.Metadata["prometheus_query_lookback_seconds"] != "600" {
		t.Fatalf("unexpected permissive query metadata: %#v", permissive.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["prometheus_query_invalid_setting_count"] != "4" || invalid.Metadata["prometheus_query_max_concurrency_valid"] != "false" || invalid.Metadata["prometheus_query_max_samples_valid"] != "false" || invalid.Metadata["prometheus_query_timeout_valid"] != "false" || invalid.Metadata["prometheus_query_lookback_valid"] != "false" {
		t.Fatalf("unexpected invalid query metadata: %#v", invalid.Metadata)
	}
	gap := resources["monitoring/gap"]
	if gap.Metadata["prometheus_query_lookback_below_scrape_interval"] != "true" {
		t.Fatalf("expected lookback below scrape interval: %#v", gap.Metadata)
	}
	malformed := resources["monitoring/malformed"]
	if malformed.Metadata["prometheus_query_declared"] != "true" || malformed.Metadata["prometheus_query_object_valid"] != "false" || malformed.Metadata["prometheus_query_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected malformed query metadata: %#v", malformed.Metadata)
	}
	agent := resources["monitoring/edge"]
	if agent.Metadata["prometheus_query_declared"] != "false" || agent.Metadata["prometheus_query_max_concurrency"] != "0" || agent.Metadata["prometheus_query_invalid_setting_count"] != "0" {
		t.Fatalf("PrometheusAgent must ignore unsupported QuerySpec: %#v", agent.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsIngestionLimitCoverage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: protected, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  enforcedSampleLimit: 1000
  enforcedTargetLimit: 100
  enforcedLabelLimit: 50
  enforcedLabelNameLengthLimit: 100
  enforcedLabelValueLengthLimit: 500
  enforcedBodySizeLimit: 10MB
  enforcedKeepDroppedTargets: 1000
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: partial, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  enforcedSampleLimit: 2000
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: edge, namespace: monitoring}
spec:
  podMonitorSelector: {}
  enforcedSampleLimit: 500
  enforcedTargetLimit: 50
  enforcedLabelLimit: 30
  enforcedLabelNameLengthLimit: 80
  enforcedLabelValueLengthLimit: 300
  enforcedBodySizeLimit: 5MB
  enforcedKeepDroppedTargets: 500
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: inherited, namespace: monitoring}
spec: {selector: {matchLabels: {app: inherited}}, endpoints: [{port: metrics}]}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: local, namespace: monitoring}
spec:
  selector: {matchLabels: {app: local}}
  endpoints: [{port: metrics}]
  sampleLimit: 900
  targetLimit: 90
  labelLimit: 40
  labelNameLengthLimit: 90
  labelValueLengthLimit: 400
  bodySizeLimit: 8MB
  keepDroppedTargets: 800
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: invalid, namespace: monitoring}
spec:
  selector: {matchLabels: {app: invalid}}
  endpoints: [{port: metrics}]
  sampleLimit: 0
  targetLimit: -1
  labelLimit: nope
  labelNameLengthLimit: 0
  labelValueLengthLimit: -2
  bodySizeLimit: unlimited
  keepDroppedTargets: 0
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: agent-target, namespace: monitoring}
spec: {selector: {matchLabels: {app: edge}}, podMetricsEndpoints: [{port: metrics}]}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	protected := resources["monitoring/protected"]
	if protected.Metadata["prometheus_enforced_sample_limit_value"] != "1000" || protected.Metadata["prometheus_enforced_body_size_limit_value"] != "10485760" || protected.Metadata["prometheus_enforced_keep_dropped_targets_limit_value"] != "1000" || protected.Metadata["prometheus_enforced_ingestion_limit_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected protected workload limits: %#v", protected.Metadata)
	}
	partial := resources["monitoring/partial"]
	if partial.Metadata["prometheus_enforced_sample_limit_valid"] != "true" || partial.Metadata["prometheus_enforced_target_limit_declared"] != "false" {
		t.Fatalf("unexpected partial workload limits: %#v", partial.Metadata)
	}
	inherited := resources["monitoring/inherited"]
	if inherited.Metadata["prometheus_selected_count"] != "2" || inherited.Metadata["prometheus_sample_limit_covered_count"] != "2" || inherited.Metadata["prometheus_sample_limit_unprotected_count"] != "0" || inherited.Metadata["prometheus_target_limit_covered_count"] != "1" || inherited.Metadata["prometheus_target_limit_unprotected_count"] != "1" || inherited.Metadata["prometheus_body_limit_unprotected_count"] != "1" {
		t.Fatalf("unexpected inherited limit coverage: %#v", inherited.Metadata)
	}
	local := resources["monitoring/local"]
	for _, dimension := range []string{"sample", "target", "label", "label_name_length", "label_value_length", "body", "keep_dropped_targets"} {
		if local.Metadata["prometheus_"+dimension+"_limit_covered_count"] != "2" || local.Metadata["prometheus_"+dimension+"_limit_unprotected_count"] != "0" {
			t.Fatalf("expected local %s limit to cover both workloads: %#v", dimension, local.Metadata)
		}
	}
	if local.Metadata["monitor_body_size_limit_value"] != "8388608" || local.Metadata["monitor_keep_dropped_targets_limit_value"] != "800" || local.Metadata["monitor_ingestion_limit_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected local monitor limits: %#v", local.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["monitor_ingestion_limit_invalid_setting_count"] != "7" || invalid.Metadata["prometheus_sample_limit_unprotected_count"] != "0" || invalid.Metadata["prometheus_target_limit_unprotected_count"] != "1" || invalid.Metadata["prometheus_keep_dropped_targets_limit_unprotected_count"] != "1" {
		t.Fatalf("unexpected invalid monitor limits: %#v", invalid.Metadata)
	}
	agentTarget := resources["monitoring/agent-target"]
	if agentTarget.Metadata["prometheus_selected_count"] != "1" {
		t.Fatalf("expected Agent to select PodMonitor: %#v", agentTarget.Metadata)
	}
	for _, dimension := range []string{"sample", "target", "label", "label_name_length", "label_value_length", "body", "keep_dropped_targets"} {
		if agentTarget.Metadata["prometheus_"+dimension+"_limit_unprotected_count"] != "0" {
			t.Fatalf("expected Agent-enforced %s coverage: %#v", dimension, agentTarget.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorMapsScrapeTimingGovernance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: valid, namespace: monitoring}
spec:
  scrapeInterval: 30s
  scrapeTimeout: 10s
  serviceMonitorSelector: {matchLabels: {timing: selected}}
  podMonitorSelector: {matchLabels: {timing: selected}}
  probeSelector: {matchLabels: {timing: selected}}
  scrapeConfigSelector: {matchLabels: {timing: selected}}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: conflict, namespace: monitoring}
spec: {scrapeInterval: 10s, scrapeTimeout: 20s}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid, namespace: monitoring}
spec: {scrapeInterval: never, scrapeTimeout: 0s}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: local-conflict, namespace: monitoring, labels: {timing: selected}}
spec:
  endpoints:
    - {port: web, interval: 15s, scrapeTimeout: 20s}
    - {port: admin, interval: invalid}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: inherited-conflict, namespace: monitoring, labels: {timing: selected}}
spec: {podMetricsEndpoints: [{port: web, scrapeTimeout: 45s}]}
---
apiVersion: monitoring.coreos.com/v1
kind: Probe
metadata: {name: valid-probe, namespace: monitoring, labels: {timing: selected}}
spec: {interval: 20s, scrapeTimeout: 5s}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata: {name: invalid-config, namespace: monitoring, labels: {timing: selected}}
spec: {scrapeInterval: 30s, scrapeTimeout: invalid}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: unselected, namespace: monitoring, labels: {timing: other}}
spec: {podMetricsEndpoints: [{port: web, scrapeTimeout: 45s}]}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	valid := resources["monitoring/valid"]
	if valid.Metadata["prometheus_scrape_interval_seconds"] != "30" || valid.Metadata["prometheus_scrape_timeout_seconds"] != "10" || valid.Metadata["prometheus_scrape_timing_invalid_setting_count"] != "0" || valid.Metadata["prometheus_scrape_timeout_exceeds_interval"] != "false" {
		t.Fatalf("unexpected valid workload timing: %#v", valid.Metadata)
	}
	conflict := resources["monitoring/conflict"]
	if conflict.Metadata["prometheus_scrape_timeout_exceeds_interval"] != "true" {
		t.Fatalf("expected global timing conflict: %#v", conflict.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["prometheus_scrape_timing_invalid_setting_count"] != "2" {
		t.Fatalf("expected two invalid global timings: %#v", invalid.Metadata)
	}
	local := resources["monitoring/local-conflict"]
	if local.Metadata["monitor_scrape_timing_invalid_setting_count"] != "1" || local.Metadata["monitor_scrape_timeout_exceeds_interval_count"] != "1" || local.Metadata["prometheus_scrape_timeout_conflict_count"] != "0" {
		t.Fatalf("unexpected local timing metadata: %#v", local.Metadata)
	}
	inherited := resources["monitoring/inherited-conflict"]
	if inherited.Metadata["monitor_scrape_timeout_without_interval_seconds"] != "45" || inherited.Metadata["prometheus_selected_count"] != "1" || inherited.Metadata["prometheus_scrape_timeout_conflict_count"] != "1" {
		t.Fatalf("unexpected inherited timing conflict: %#v", inherited.Metadata)
	}
	probe := resources["monitoring/valid-probe"]
	if probe.Metadata["monitor_scrape_timing_invalid_setting_count"] != "0" || probe.Metadata["monitor_scrape_timeout_exceeds_interval_count"] != "0" {
		t.Fatalf("unexpected probe timing metadata: %#v", probe.Metadata)
	}
	scrapeConfig := resources["monitoring/invalid-config"]
	if scrapeConfig.Metadata["monitor_scrape_timing_invalid_setting_count"] != "1" {
		t.Fatalf("expected invalid ScrapeConfig timeout: %#v", scrapeConfig.Metadata)
	}
	unselected := resources["monitoring/unselected"]
	if unselected.Metadata["prometheus_selected_count"] != "0" || unselected.Metadata["prometheus_scrape_timeout_conflict_count"] != "0" {
		t.Fatalf("unselected monitor must not inherit a conflict: %#v", unselected.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsArbitraryFileAccessCoverage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: protected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  podMonitorSelector: {matchLabels: {scope: selected}}
  probeSelector: {matchLabels: {scope: selected}}
  arbitraryFSAccessThroughSMs: {deny: true}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: unprotected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  podMonitorSelector: {matchLabels: {scope: selected}}
  probeSelector: {matchLabels: {scope: selected}}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: risky, namespace: monitoring, labels: {scope: selected}}
spec:
  endpoints:
    - port: web
      bearerTokenFile: /etc/prometheus/secrets/token
      tlsConfig:
        caFile: /etc/prometheus/tls/ca.pem
        certFile: /etc/prometheus/tls/cert.pem
        keyFile: /etc/prometheus/tls/key.pem
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: safe, namespace: monitoring, labels: {scope: selected}}
spec: {podMetricsEndpoints: [{port: web}]}
---
apiVersion: monitoring.coreos.com/v1
kind: Probe
metadata: {name: probe-risk, namespace: monitoring, labels: {scope: selected}}
spec:
  bearerTokenFile: /etc/prometheus/secrets/probe-token
  prober: {url: blackbox:9115}
  targets: {staticConfig: {static: [https://example.test]}}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: unselected, namespace: monitoring, labels: {scope: other}}
spec: {endpoints: [{port: web, bearerTokenFile: /etc/prometheus/secrets/unused}]}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata: {name: scrape-config, namespace: monitoring}
spec: {jobName: test, bearerTokenFile: /etc/prometheus/secrets/config, staticConfigs: [{targets: [example.test:9090]}]}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
		for key, value := range resource.Metadata {
			if strings.Contains(value, "/etc/prometheus/") {
				t.Fatalf("file path leaked in %s metadata %s", resource.Name, key)
			}
		}
	}
	protected := resources["monitoring/protected"]
	if protected.Metadata["prometheus_arbitrary_fs_access_denied"] != "true" {
		t.Fatalf("expected protected workload metadata: %#v", protected.Metadata)
	}
	risky := resources["monitoring/risky"]
	if risky.Metadata["monitor_arbitrary_file_reference_count"] != "4" || risky.Metadata["prometheus_selected_count"] != "2" || risky.Metadata["prometheus_arbitrary_file_access_protected_count"] != "1" || risky.Metadata["prometheus_arbitrary_file_access_unprotected_count"] != "1" {
		t.Fatalf("unexpected risky monitor coverage: %#v", risky.Metadata)
	}
	probe := resources["monitoring/probe-risk"]
	if probe.Metadata["monitor_arbitrary_file_reference_count"] != "1" || probe.Metadata["prometheus_arbitrary_file_access_unprotected_count"] != "1" {
		t.Fatalf("unexpected Probe file access coverage: %#v", probe.Metadata)
	}
	safe := resources["monitoring/safe"]
	if safe.Metadata["monitor_arbitrary_file_reference_count"] != "0" || safe.Metadata["prometheus_arbitrary_file_access_unprotected_count"] != "0" {
		t.Fatalf("safe monitor must not receive a gap: %#v", safe.Metadata)
	}
	unselected := resources["monitoring/unselected"]
	if unselected.Metadata["prometheus_selected_count"] != "0" || unselected.Metadata["prometheus_arbitrary_file_access_unprotected_count"] != "0" {
		t.Fatalf("unselected monitor must not receive a gap: %#v", unselected.Metadata)
	}
	scrapeConfig := resources["monitoring/scrape-config"]
	if scrapeConfig.Metadata["monitor_arbitrary_file_reference_count"] != "0" {
		t.Fatalf("ScrapeConfig is outside arbitraryFSAccessThroughSMs scope: %#v", scrapeConfig.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsHonorOverrideCoverage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: protected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  podMonitorSelector: {matchLabels: {scope: selected}}
  scrapeConfigSelector: {matchLabels: {scope: selected}}
  overrideHonorLabels: true
  overrideHonorTimestamps: true
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: unprotected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  podMonitorSelector: {matchLabels: {scope: selected}}
  scrapeConfigSelector: {matchLabels: {scope: selected}}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: explicit, namespace: monitoring, labels: {scope: selected}}
spec:
  endpoints:
    - {port: web, honorLabels: true, honorTimestamps: true}
    - {port: admin, honorLabels: true, honorTimestamps: false}
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: safe, namespace: monitoring, labels: {scope: selected}}
spec: {podMetricsEndpoints: [{port: web, honorLabels: false, honorTimestamps: false}]}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata: {name: config, namespace: monitoring, labels: {scope: selected}}
spec: {jobName: test, honorLabels: true, honorTimestamps: true, staticConfigs: [{targets: [example.test:9090]}]}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: unselected, namespace: monitoring, labels: {scope: other}}
spec: {endpoints: [{port: web, honorLabels: true, honorTimestamps: true}]}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	protected := resources["monitoring/protected"]
	if protected.Metadata["prometheus_override_honor_labels"] != "true" || protected.Metadata["prometheus_override_honor_timestamps"] != "true" {
		t.Fatalf("unexpected protected override metadata: %#v", protected.Metadata)
	}
	explicit := resources["monitoring/explicit"]
	if explicit.Metadata["monitor_honor_labels_count"] != "2" || explicit.Metadata["monitor_explicit_honor_timestamps_count"] != "1" || explicit.Metadata["prometheus_selected_count"] != "2" || explicit.Metadata["prometheus_honor_labels_override_count"] != "1" || explicit.Metadata["prometheus_honor_labels_unprotected_count"] != "1" || explicit.Metadata["prometheus_honor_timestamps_override_count"] != "1" || explicit.Metadata["prometheus_honor_timestamps_unprotected_count"] != "1" {
		t.Fatalf("unexpected explicit honor coverage: %#v", explicit.Metadata)
	}
	safe := resources["monitoring/safe"]
	if safe.Metadata["monitor_honor_labels_count"] != "0" || safe.Metadata["prometheus_honor_labels_unprotected_count"] != "0" || safe.Metadata["prometheus_honor_timestamps_unprotected_count"] != "0" {
		t.Fatalf("safe monitor must not receive honor gaps: %#v", safe.Metadata)
	}
	scrapeConfig := resources["monitoring/config"]
	if scrapeConfig.Metadata["monitor_honor_labels_count"] != "1" || scrapeConfig.Metadata["monitor_explicit_honor_timestamps_count"] != "0" || scrapeConfig.Metadata["prometheus_honor_labels_unprotected_count"] != "1" {
		t.Fatalf("unexpected ScrapeConfig honor coverage: %#v", scrapeConfig.Metadata)
	}
	unselected := resources["monitoring/unselected"]
	if unselected.Metadata["prometheus_selected_count"] != "0" || unselected.Metadata["prometheus_honor_labels_unprotected_count"] != "0" || unselected.Metadata["prometheus_honor_timestamps_unprotected_count"] != "0" {
		t.Fatalf("unselected monitor must not receive honor gaps: %#v", unselected.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsIgnoredNamespaceSelectorCoverage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: protected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  podMonitorSelector: {matchLabels: {scope: selected}}
  probeSelector: {matchLabels: {scope: selected}}
  ignoreNamespaceSelectors: true
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: effective, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  podMonitorSelector: {matchLabels: {scope: selected}}
  probeSelector: {matchLabels: {scope: selected}}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: broad-service, namespace: monitoring, labels: {scope: selected}}
spec:
  namespaceSelector: {any: true}
  endpoints: [{port: web}]
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: narrow-pod, namespace: monitoring, labels: {scope: selected}}
spec:
  namespaceSelector: {matchNames: [prod]}
  podMetricsEndpoints: [{port: web}]
---
apiVersion: monitoring.coreos.com/v1
kind: Probe
metadata: {name: broad-probe, namespace: monitoring, labels: {scope: selected}}
spec:
  prober: {url: blackbox:9115}
  targets:
    ingress:
      selector: {matchLabels: {app: web}}
      namespaceSelector: {any: true}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: unselected, namespace: monitoring, labels: {scope: other}}
spec:
  namespaceSelector: {any: true}
  endpoints: [{port: web}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	protected := resources["monitoring/protected"]
	if protected.Metadata["prometheus_ignore_namespace_selectors"] != "true" {
		t.Fatalf("expected protected workload metadata, got %#v", protected.Metadata)
	}
	effective := resources["monitoring/effective"]
	if effective.Metadata["prometheus_ignore_namespace_selectors"] != "false" {
		t.Fatalf("expected default false workload metadata, got %#v", effective.Metadata)
	}
	for _, name := range []string{"monitoring/broad-service", "monitoring/broad-probe"} {
		resource := resources[name]
		if resource.Metadata["prometheus_selected_count"] != "2" || resource.Metadata["prometheus_namespace_selector_ignored_count"] != "1" || resource.Metadata["prometheus_namespace_selector_effective_count"] != "1" {
			t.Fatalf("unexpected broad selector coverage for %s: %#v", name, resource.Metadata)
		}
	}
	narrow := resources["monitoring/narrow-pod"]
	if narrow.Metadata["prometheus_selected_count"] != "2" || narrow.Metadata["prometheus_namespace_selector_ignored_count"] != "0" || narrow.Metadata["prometheus_namespace_selector_effective_count"] != "0" {
		t.Fatalf("narrow selector must not receive broad coverage: %#v", narrow.Metadata)
	}
	unselected := resources["monitoring/unselected"]
	if unselected.Metadata["prometheus_selected_count"] != "0" || unselected.Metadata["prometheus_namespace_selector_ignored_count"] != "0" || unselected.Metadata["prometheus_namespace_selector_effective_count"] != "0" {
		t.Fatalf("unselected monitor must not receive broad selector exposure: %#v", unselected.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsNamespaceLabelEnforcementCoverage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: protected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  serviceMonitorNamespaceSelector: {}
  ruleSelector: {}
  ruleNamespaceSelector: {}
  enforcedNamespaceLabel: source_namespace
  excludedFromEnforcement:
    - {group: monitoring.coreos.com, resource: servicemonitors, namespace: tenant, name: excluded-monitor}
    - {group: monitoring.coreos.com, resource: prometheusrules, namespace: tenant, name: excluded-rules}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: unprotected, namespace: monitoring}
spec:
  serviceMonitorSelector: {matchLabels: {scope: selected}}
  serviceMonitorNamespaceSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: protected-ruler, namespace: monitoring}
spec:
  ruleSelector: {}
  ruleNamespaceSelector: {}
  queryEndpoints: [http://thanos-query:9090]
  enforcedNamespaceLabel: source_namespace
  prometheusRulesExcludedFromEnforce:
    - {ruleNamespace: tenant, ruleName: excluded-rules}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: unprotected-ruler, namespace: monitoring}
spec:
  ruleSelector: {matchLabels: {scope: risk}}
  ruleNamespaceSelector: {}
  queryEndpoints: [http://thanos-query:9090]
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: mixed-monitor, namespace: tenant, labels: {scope: selected}}
spec: {endpoints: [{port: web}]}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: excluded-monitor, namespace: tenant, labels: {scope: selected}}
spec: {endpoints: [{port: web}]}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: {name: local-monitor, namespace: monitoring, labels: {scope: selected}}
spec: {endpoints: [{port: web}]}
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: {name: safe-rules, namespace: tenant, labels: {scope: safe}}
spec:
  groups: [{name: safe, rules: [{alert: SafeAlert, expr: up == 0}]}]
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: {name: risk-rules, namespace: tenant, labels: {scope: risk}}
spec:
  groups: [{name: risk, rules: [{record: risk:up, expr: sum(up)}]}]
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata: {name: excluded-rules, namespace: tenant, labels: {scope: excluded}}
spec:
  groups: [{name: excluded, rules: [{alert: ExcludedAlert, expr: up == 0}]}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	protected := resources["monitoring/protected"]
	if protected.Metadata["prometheus_enforced_namespace_label_declared"] != "true" || protected.Metadata["prometheus_namespace_enforcement_exclusion_count"] != "2" {
		t.Fatalf("unexpected Prometheus namespace enforcement metadata: %#v", protected.Metadata)
	}
	ruler := resources["monitoring/protected-ruler"]
	if ruler.Metadata["thanos_ruler_enforced_namespace_label_declared"] != "true" || ruler.Metadata["thanos_ruler_namespace_enforcement_exclusion_count"] != "1" {
		t.Fatalf("unexpected ThanosRuler namespace enforcement metadata: %#v", ruler.Metadata)
	}
	mixed := resources["tenant/mixed-monitor"]
	if mixed.Metadata["prometheus_cross_namespace_selected_count"] != "2" || mixed.Metadata["prometheus_namespace_label_enforced_count"] != "1" || mixed.Metadata["prometheus_namespace_label_excluded_count"] != "0" || mixed.Metadata["prometheus_namespace_label_unprotected_count"] != "1" {
		t.Fatalf("unexpected mixed monitor enforcement coverage: %#v", mixed.Metadata)
	}
	excluded := resources["tenant/excluded-monitor"]
	if excluded.Metadata["prometheus_cross_namespace_selected_count"] != "2" || excluded.Metadata["prometheus_namespace_label_enforced_count"] != "0" || excluded.Metadata["prometheus_namespace_label_excluded_count"] != "1" || excluded.Metadata["prometheus_namespace_label_unprotected_count"] != "1" {
		t.Fatalf("unexpected excluded monitor enforcement coverage: %#v", excluded.Metadata)
	}
	local := resources["monitoring/local-monitor"]
	if local.Metadata["prometheus_cross_namespace_selected_count"] != "0" || local.Metadata["prometheus_namespace_label_unprotected_count"] != "0" {
		t.Fatalf("same-namespace monitor must not require source namespace enforcement: %#v", local.Metadata)
	}
	safeRule := resources["SafeAlert"]
	if safeRule.Metadata["rule_evaluator_cross_namespace_selected_count"] != "2" || safeRule.Metadata["rule_evaluator_namespace_label_enforced_count"] != "2" || safeRule.Metadata["rule_evaluator_namespace_label_excluded_count"] != "0" || safeRule.Metadata["rule_evaluator_namespace_label_unprotected_count"] != "0" {
		t.Fatalf("unexpected safe rule enforcement coverage: %#v", safeRule.Metadata)
	}
	riskRule := model.Resource{}
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeRecordingRule && resource.Name == "risk:up" {
			riskRule = resource
			break
		}
	}
	if riskRule.Metadata["rule_evaluator_cross_namespace_selected_count"] != "3" || riskRule.Metadata["rule_evaluator_namespace_label_enforced_count"] != "2" || riskRule.Metadata["rule_evaluator_namespace_label_unprotected_count"] != "1" {
		t.Fatalf("unexpected risk rule enforcement coverage: %#v", riskRule.Metadata)
	}
	excludedRule := resources["ExcludedAlert"]
	if excludedRule.Metadata["rule_evaluator_cross_namespace_selected_count"] != "2" || excludedRule.Metadata["rule_evaluator_namespace_label_enforced_count"] != "0" || excludedRule.Metadata["rule_evaluator_namespace_label_excluded_count"] != "2" || excludedRule.Metadata["rule_evaluator_namespace_label_unprotected_count"] != "0" {
		t.Fatalf("unexpected excluded rule enforcement coverage: %#v", excludedRule.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsPrometheusManagedConfiguration(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: unmanaged, namespace: monitoring}
spec:
  ruleSelector: {}
  ruleNamespaceSelector: {}
  additionalScrapeConfigs: {name: extra-scrapes, key: prometheus.yaml}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: managed-empty, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: unmanaged-agent, namespace: monitoring}
spec:
  remoteWrite:
    - {url: https://remote.example/api/v1/write}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: managed-agent, namespace: monitoring}
spec:
  scrapeConfigSelector: {matchLabels: {agent: enabled}}
  remoteWrite:
    - {url: https://remote.example/api/v1/write}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	unmanaged := resources["monitoring/unmanaged"]
	if unmanaged.Metadata["prometheus_declared_selector_count"] != "1" || unmanaged.Metadata["prometheus_declared_monitor_selector_count"] != "0" || unmanaged.Metadata["prometheus_configuration_managed"] != "false" || unmanaged.Metadata["prometheus_additional_scrape_configs_declared"] != "true" {
		t.Fatalf("ruleSelector must not make scrape configuration managed: %#v", unmanaged.Metadata)
	}
	managed := resources["monitoring/managed-empty"]
	if managed.Metadata["prometheus_declared_monitor_selector_count"] != "1" || managed.Metadata["prometheus_configuration_managed"] != "true" {
		t.Fatalf("empty ServiceMonitor selector must enable managed configuration: %#v", managed.Metadata)
	}
	unmanagedAgent := resources["monitoring/unmanaged-agent"]
	if unmanagedAgent.Metadata["prometheus_declared_monitor_selector_count"] != "0" || unmanagedAgent.Metadata["prometheus_configuration_managed"] != "false" {
		t.Fatalf("remote write must not make Agent scrape configuration managed: %#v", unmanagedAgent.Metadata)
	}
	managedAgent := resources["monitoring/managed-agent"]
	if managedAgent.Metadata["prometheus_declared_monitor_selector_count"] != "1" || managedAgent.Metadata["prometheus_configuration_managed"] != "true" {
		t.Fatalf("ScrapeConfig selector must enable managed Agent configuration: %#v", managedAgent.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsPrometheusExternalLabelGovernance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: defaults, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: disabled, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  replicas: 2
  replicaExternalLabelName: ""
  prometheusExternalLabelName: ""
  externalLabels: {cluster: production, region: east}
  remoteWrite: [{url: https://remote.example/api/v1/write}]
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: custom, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  replicas: 2
  replicaExternalLabelName: __replica__
  prometheusExternalLabelName: prometheus_cluster
  thanos:
    objectStorageConfig: {name: thanos-secret, key: config.yaml}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: agent, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  replicas: 2
  replicaExternalLabelName: ""
  remoteWrite: [{url: https://remote.example/api/v1/write}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	defaults := resources["monitoring/defaults"]
	if defaults.Metadata["prometheus_replica_external_label_declared"] != "false" || defaults.Metadata["prometheus_replica_external_label_enabled"] != "true" || defaults.Metadata["prometheus_instance_external_label_enabled"] != "true" || defaults.Metadata["prometheus_external_label_count"] != "0" {
		t.Fatalf("unexpected default external-label metadata: %#v", defaults.Metadata)
	}
	disabled := resources["monitoring/disabled"]
	if disabled.Metadata["prometheus_replica_external_label_declared"] != "true" || disabled.Metadata["prometheus_replica_external_label_enabled"] != "false" || disabled.Metadata["prometheus_instance_external_label_declared"] != "true" || disabled.Metadata["prometheus_instance_external_label_enabled"] != "false" || disabled.Metadata["prometheus_external_label_count"] != "2" || disabled.Metadata["prometheus_remote_write_count"] != "1" {
		t.Fatalf("unexpected disabled external-label metadata: %#v", disabled.Metadata)
	}
	custom := resources["monitoring/custom"]
	if custom.Metadata["prometheus_replica_external_label_enabled"] != "true" || custom.Metadata["prometheus_instance_external_label_enabled"] != "true" || custom.Metadata["prometheus_thanos_object_storage_declared"] != "true" {
		t.Fatalf("unexpected custom external-label metadata: %#v", custom.Metadata)
	}
	agent := resources["monitoring/agent"]
	if agent.Metadata["prometheus_replica_external_label_enabled"] != "false" || agent.Metadata["prometheus_remote_write_count"] != "1" {
		t.Fatalf("unexpected Agent external-label metadata: %#v", agent.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			if strings.Contains(value, "__replica__") || strings.Contains(value, "prometheus_cluster") || strings.Contains(value, "production") || strings.Contains(value, "east") {
				t.Fatalf("external-label name/value persisted in %s=%q: %#v", key, value, resource.Metadata)
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsPrometheusWebEndpointGovernance(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: defaults, namespace: monitoring}
spec: {serviceMonitorSelector: {}}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: exposed, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  version: v2.32.1
  enableAdminAPI: true
  enableRemoteWriteReceiver: true
  enableOTLPReceiver: true
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: agent-receiver, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  version: v2.46.0
  enableAdminAPI: true
  enableRemoteWriteReceiver: true
  otlp: {}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: supported, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  version: v2.47.0
  enableRemoteWriteReceiver: true
  enableOTLPReceiver: true
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid-web, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  web: broken
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid-max, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  web: {maxConnections: -1}
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: zero-http, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  enableAdminAPI: true
  externalUrl: http://sensitive.example/prometheus
  web: {maxConnections: 0}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: secure-agent, namespace: monitoring}
spec:
  serviceMonitorSelector: {}
  enableOTLPReceiver: true
  externalUrl: https://secure.example/prometheus
  web: {maxConnections: 100}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := map[string]model.Resource{}
	for _, resource := range snapshot.Resources {
		resources[resource.Name] = resource
	}
	defaults := resources["monitoring/defaults"]
	if defaults.Metadata["prometheus_admin_api_enabled"] != "false" || defaults.Metadata["prometheus_remote_write_receiver_enabled"] != "false" || defaults.Metadata["prometheus_otlp_receiver_enabled"] != "false" || defaults.Metadata["prometheus_receiver_version_evaluable"] != "false" {
		t.Fatalf("unexpected default web endpoint metadata: %#v", defaults.Metadata)
	}
	exposed := resources["monitoring/exposed"]
	if exposed.Metadata["prometheus_admin_api_enabled"] != "true" || exposed.Metadata["prometheus_remote_write_receiver_enabled"] != "true" || exposed.Metadata["prometheus_otlp_receiver_enabled"] != "true" || exposed.Metadata["prometheus_remote_write_receiver_version_unsupported"] != "true" || exposed.Metadata["prometheus_otlp_receiver_version_unsupported"] != "true" {
		t.Fatalf("unexpected Prometheus web endpoint metadata: %#v", exposed.Metadata)
	}
	agent := resources["monitoring/agent-receiver"]
	if agent.Metadata["prometheus_admin_api_enabled"] != "false" || agent.Metadata["prometheus_remote_write_receiver_enabled"] != "true" || agent.Metadata["prometheus_otlp_config_declared"] != "true" || agent.Metadata["prometheus_otlp_receiver_enabled"] != "true" || agent.Metadata["prometheus_remote_write_receiver_version_unsupported"] != "false" || agent.Metadata["prometheus_otlp_receiver_version_unsupported"] != "true" {
		t.Fatalf("server-only admin API field must be ignored on Agent: %#v", agent.Metadata)
	}
	supported := resources["monitoring/supported"]
	if supported.Metadata["prometheus_receiver_version_evaluable"] != "true" || supported.Metadata["prometheus_remote_write_receiver_version_unsupported"] != "false" || supported.Metadata["prometheus_otlp_receiver_version_unsupported"] != "false" {
		t.Fatalf("unexpected supported receiver version metadata: %#v", supported.Metadata)
	}
	if resources["monitoring/invalid-web"].Metadata["prometheus_web_invalid_setting_count"] != "1" || resources["monitoring/invalid-max"].Metadata["prometheus_web_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected invalid web metadata: web=%#v max=%#v", resources["monitoring/invalid-web"].Metadata, resources["monitoring/invalid-max"].Metadata)
	}
	zeroHTTP := resources["monitoring/zero-http"]
	if zeroHTTP.Metadata["prometheus_web_max_connections_declared"] != "true" || zeroHTTP.Metadata["prometheus_web_max_connections_valid"] != "true" || zeroHTTP.Metadata["prometheus_web_max_connections"] != "0" || zeroHTTP.Metadata["prometheus_external_url_scheme"] != "http" || zeroHTTP.Metadata["prometheus_external_url_valid"] != "true" {
		t.Fatalf("unexpected zero/plaintext web metadata: %#v", zeroHTTP.Metadata)
	}
	secureAgent := resources["monitoring/secure-agent"]
	if secureAgent.Metadata["prometheus_web_max_connections"] != "100" || secureAgent.Metadata["prometheus_external_url_scheme"] != "https" || secureAgent.Metadata["prometheus_external_url_valid"] != "true" {
		t.Fatalf("unexpected secure Agent web metadata: %#v", secureAgent.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			if strings.Contains(value, "sensitive.example") || strings.Contains(value, "secure.example") || strings.Contains(value, "/prometheus") {
				t.Fatalf("external URL leaked through %s=%q: %#v", key, value, resource.Metadata)
			}
		}
	}
}

func TestKubernetesPrometheusVersionAtLeast(t *testing.T) {
	tests := []struct {
		version   string
		expected  bool
		evaluable bool
	}{
		{version: "v2.47.0", expected: true, evaluable: true},
		{version: "2.47", expected: true, evaluable: true},
		{version: "v2.47.0-rc.1", expected: false, evaluable: true},
		{version: "v2.47.1-rc.1", expected: true, evaluable: true},
		{version: "v3.0.0", expected: true, evaluable: true},
		{version: "v2.46.9", expected: false, evaluable: true},
		{version: "latest", expected: false, evaluable: false},
		{version: "", expected: false, evaluable: false},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			actual, evaluable := kubernetesPrometheusVersionAtLeast(test.version, 2, 47)
			if actual != test.expected || evaluable != test.evaluable {
				t.Fatalf("expected supported=%t evaluable=%t, got supported=%t evaluable=%t", test.expected, test.evaluable, actual, evaluable)
			}
		})
	}
}

func TestKubernetesLabelSelectorMatchesOperators(t *testing.T) {
	labels := map[string]string{"team": "platform", "tier": "backend"}
	tests := []struct {
		name       string
		expression kubernetesLabelExpression
		matches    bool
		known      bool
	}{
		{name: "in", expression: kubernetesLabelExpression{Key: "team", Operator: "In", Values: []string{"platform"}}, matches: true, known: true},
		{name: "not in missing", expression: kubernetesLabelExpression{Key: "region", Operator: "NotIn", Values: []string{"cn"}}, matches: true, known: true},
		{name: "exists", expression: kubernetesLabelExpression{Key: "tier", Operator: "Exists"}, matches: true, known: true},
		{name: "does not exist", expression: kubernetesLabelExpression{Key: "region", Operator: "DoesNotExist"}, matches: true, known: true},
		{name: "unknown operator", expression: kubernetesLabelExpression{Key: "team", Operator: "Equals", Values: []string{"platform"}}, matches: false, known: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, known := kubernetesLabelSelectorMatches(kubernetesLabelSelector{Declared: true, MatchExpressions: []kubernetesLabelExpression{test.expression}}, labels)
			if matches != test.matches || known != test.known {
				t.Fatalf("expected matches=%t known=%t, got matches=%t known=%t", test.matches, test.known, matches, known)
			}
		})
	}
}

func TestKubernetesManifestConnectorRejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte("kind: Service\nmetadata:\n  name: [broken\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "parse kubernetes manifest") {
		t.Fatalf("expected malformed YAML error, got %v", err)
	}
}

func TestKubernetesManifestConnectorRejectsMalformedListItems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: List\nitems: {}\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	connector, err := NewKubernetesManifestConnector(path)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "List items must be a sequence") {
		t.Fatalf("expected malformed List error, got %v", err)
	}
}

func TestKubernetesManifestConnectorRejectsEmptyDirectory(t *testing.T) {
	connector, err := NewKubernetesManifestConnector(t.TempDir())
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "contains no YAML or JSON files") {
		t.Fatalf("expected empty directory error, got %v", err)
	}
}

func resourceByID(snapshot Snapshot, id string) (model.Resource, bool) {
	for _, resource := range snapshot.Resources {
		if resource.ID == id {
			return resource, true
		}
	}
	return model.Resource{}, false
}
