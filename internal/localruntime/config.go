package localruntime

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"monicheck/internal/connector"
	"monicheck/internal/model"
)

type FileConfig struct {
	Version    int             `yaml:"version"`
	Connectors []ConnectorSpec `yaml:"connectors"`
}

type ConnectorSpec struct {
	Type               string   `yaml:"type"`
	Name               string   `yaml:"name"`
	URL                string   `yaml:"url"`
	Path               string   `yaml:"path"`
	HealthURL          string   `yaml:"health_url"`
	MetricsURL         string   `yaml:"metrics_url"`
	RulePath           string   `yaml:"rule_path"`
	GraphQLPath        string   `yaml:"graphql_path"`
	Namespace          string   `yaml:"namespace"`
	TenantID           string   `yaml:"tenant_id"`
	FeatureGates       string   `yaml:"feature_gates"`
	Lookback           string   `yaml:"lookback"`
	DependencyLookback string   `yaml:"dependency_lookback"`
	OperationLimit     int      `yaml:"operation_limit"`
	DependencyLimit    int      `yaml:"dependency_limit"`
	TagValueLimit      int      `yaml:"tag_value_limit"`
	EndpointLimit      int      `yaml:"endpoint_limit"`
	AlarmLimit         int      `yaml:"alarm_limit"`
	AccountID          int      `yaml:"account_id"`
	HistoryWindowHours int      `yaml:"history_window_hours"`
	HistoryEventLimit  int      `yaml:"history_event_limit"`
	Auth               AuthSpec `yaml:"auth"`
	TLS                TLSSpec  `yaml:"tls"`
}

type AuthSpec struct {
	BearerTokenEnv    string `yaml:"bearer_token_env"`
	UsernameEnv       string `yaml:"username_env"`
	PasswordEnv       string `yaml:"password_env"`
	APIKeyEnv         string `yaml:"api_key_env"`
	ApplicationKeyEnv string `yaml:"application_key_env"`
	UserKeyEnv        string `yaml:"user_key_env"`
}

type TLSSpec struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
	ClientCertFile     string `yaml:"client_cert_file"`
	ClientKeyFile      string `yaml:"client_key_file"`
	Timeout            string `yaml:"timeout"`
}

type ConnectorInfo struct {
	Type, Group, Description string
}

var connectorCatalog = []ConnectorInfo{
	{"prometheus", "Metrics", "Prometheus HTTP API"}, {"thanos", "Metrics", "Thanos Query API"},
	{"victoriametrics", "Metrics", "VictoriaMetrics API"}, {"mimir", "Metrics", "Grafana Mimir API"},
	{"cortex", "Metrics", "Cortex API"}, {"grafana", "Visualization", "Grafana dashboards and data sources"},
	{"loki", "Logs", "Grafana Loki API"}, {"elasticsearch", "Logs", "Elasticsearch API"},
	{"opensearch", "Logs", "OpenSearch API"}, {"tempo", "Traces", "Grafana Tempo API"},
	{"jaeger", "Traces", "Jaeger API"}, {"skywalking", "Traces", "Apache SkyWalking GraphQL API"},
	{"pyroscope", "Profiles", "Grafana Pyroscope API"}, {"otelcol", "Collection", "OpenTelemetry Collector config and telemetry"},
	{"alertmanager", "Alerting", "Prometheus Alertmanager API"}, {"n9e", "Alerting", "Nightingale API and rules"},
	{"kubernetes", "Platform", "Kubernetes and Prometheus Operator manifests"},
	{"datadog", "SaaS", "Datadog monitoring APIs"}, {"newrelic", "SaaS", "New Relic NerdGraph API"},
}

func ConnectorCatalog() []ConnectorInfo { return append([]ConnectorInfo(nil), connectorCatalog...) }

func ConnectorGroup(id string) string {
	typeName := strings.SplitN(id, ":", 2)[0]
	for _, item := range connectorCatalog {
		if item.Type == typeName {
			return item.Group
		}
	}
	return "Other"
}

func ValidateFileConfig(path string) (FileConfig, error) {
	cfg, err := LoadFileConfig(path)
	if err != nil {
		return FileConfig{}, err
	}
	if _, err := buildConfiguredConnectors(cfg); err != nil {
		return FileConfig{}, err
	}
	return cfg, nil
}

func LoadFileConfig(path string) (FileConfig, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return FileConfig{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var cfg FileConfig
	if err := decoder.Decode(&cfg); err != nil {
		return FileConfig{}, fmt.Errorf("decode connector config: %w", err)
	}
	if cfg.Version != 1 {
		return FileConfig{}, fmt.Errorf("connector config version must be 1")
	}
	if len(cfg.Connectors) == 0 {
		return FileConfig{}, fmt.Errorf("connector config must contain at least one connector")
	}
	return cfg, nil
}

func buildConfiguredConnectors(cfg FileConfig) ([]connector.Connector, error) {
	seenNames := map[string]bool{}
	result := make([]connector.Connector, 0, len(cfg.Connectors))
	for index, spec := range cfg.Connectors {
		typeName := strings.ToLower(strings.TrimSpace(spec.Type))
		name := strings.TrimSpace(spec.Name)
		if name == "" {
			name = typeName
		}
		key := typeName + ":" + name
		if seenNames[key] {
			return nil, fmt.Errorf("connectors[%d]: duplicate type and name %q", index, key)
		}
		seenNames[key] = true
		base, err := buildConnector(spec)
		if err != nil {
			return nil, fmt.Errorf("connectors[%d] %s: %w", index, name, err)
		}
		result = append(result, namespaceConnector(base, name))
	}
	return result, nil
}

func buildConnector(spec ConnectorSpec) (connector.Connector, error) {
	typeName := strings.ToLower(strings.TrimSpace(spec.Type))
	options, err := connectorHTTPOptions(spec)
	if err != nil {
		return nil, err
	}
	lookback, err := durationValue(spec.Lookback, 6*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("lookback: %w", err)
	}
	dependencyLookback, err := durationValue(spec.DependencyLookback, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("dependency_lookback: %w", err)
	}
	switch typeName {
	case "prometheus":
		return connector.NewPrometheusConnectorWithOptions(spec.URL, options)
	case "thanos":
		return connector.NewThanosConnectorWithOptions(spec.URL, options)
	case "victoriametrics":
		return connector.NewVictoriaMetricsConnectorWithOptions(spec.URL, options)
	case "mimir":
		return connector.NewMimirConnectorWithOptions(spec.URL, options)
	case "cortex":
		return connector.NewCortexConnectorWithOptions(spec.URL, options)
	case "loki":
		options.Headers = tenantHeader(options.Headers, spec.TenantID)
		return connector.NewLokiConnectorWithOptions(spec.URL, options)
	case "grafana":
		return connector.NewGrafanaConnectorWithNamespace(spec.URL, spec.Namespace, options)
	case "alertmanager":
		return connector.NewAlertmanagerConnectorWithOptions(spec.URL, options)
	case "opensearch":
		return connector.NewOpenSearchConnectorWithOptions(spec.URL, options)
	case "elasticsearch":
		if key, err := envSecret(spec.Auth.APIKeyEnv); err != nil {
			return nil, err
		} else if key != "" {
			options.Headers = mergeHeader(options.Headers, "Authorization", "ApiKey "+key)
		}
		return connector.NewElasticsearchConnectorWithOptions(spec.URL, options)
	case "datadog":
		apiKey, err := envSecret(spec.Auth.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		applicationKey, err := envSecret(spec.Auth.ApplicationKeyEnv)
		if err != nil {
			return nil, err
		}
		if apiKey == "" || applicationKey == "" {
			return nil, fmt.Errorf("datadog requires api_key_env and application_key_env")
		}
		options.Headers = mergeHeader(options.Headers, "DD-API-KEY", apiKey)
		options.Headers = mergeHeader(options.Headers, "DD-APPLICATION-KEY", applicationKey)
		return connector.NewDatadogConnectorWithOptions(spec.URL, options)
	case "newrelic":
		userKey, err := envSecret(spec.Auth.UserKeyEnv)
		if err != nil {
			return nil, err
		}
		if userKey == "" {
			return nil, fmt.Errorf("newrelic requires user_key_env")
		}
		options.Headers = mergeHeader(options.Headers, "API-Key", userKey)
		return connector.NewNewRelicConnectorWithOptions(spec.URL, spec.AccountID, options)
	case "tempo":
		return connector.NewTempoConnectorWithGovernanceOptions(spec.URL, lookback, positive(spec.TagValueLimit, 500), options)
	case "jaeger":
		return connector.NewJaegerConnectorWithRuntimeOptions(spec.URL, spec.HealthURL, positive(spec.OperationLimit, 1000), dependencyLookback, positive(spec.DependencyLimit, 5000), options)
	case "pyroscope":
		options.Headers = tenantHeader(options.Headers, spec.TenantID)
		return connector.NewPyroscopeConnectorWithOptions(spec.URL, lookback, options)
	case "skywalking":
		return connector.NewSkyWalkingConnectorWithGovernanceOptions(spec.URL, defaultString(spec.GraphQLPath, "/graphql"), lookback, positive(spec.EndpointLimit, 1000), positive(spec.AlarmLimit, 1000), options)
	case "otelcol":
		return connector.NewOpenTelemetryCollectorConnectorWithTelemetryOptions(spec.Path, spec.HealthURL, spec.MetricsURL, spec.FeatureGates, options)
	case "kubernetes":
		return connector.NewKubernetesManifestConnector(spec.Path)
	case "n9e":
		apiKey, err := envSecret(spec.Auth.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		options.APIKey = apiKey
		options.BearerToken = apiKey
		return connector.NewN9EConnectorWithGovernanceOptions(spec.URL, spec.RulePath, positive(spec.HistoryWindowHours, 24), positive(spec.HistoryEventLimit, 10000), options)
	default:
		return nil, fmt.Errorf("unsupported connector type %q", typeName)
	}
}

func connectorHTTPOptions(spec ConnectorSpec) (connector.HTTPOptions, error) {
	bearer, err := envSecret(spec.Auth.BearerTokenEnv)
	if err != nil {
		return connector.HTTPOptions{}, err
	}
	username, err := envSecret(spec.Auth.UsernameEnv)
	if err != nil {
		return connector.HTTPOptions{}, err
	}
	password, err := envSecret(spec.Auth.PasswordEnv)
	if err != nil {
		return connector.HTTPOptions{}, err
	}
	timeout, err := durationValue(spec.TLS.Timeout, 15*time.Second)
	if err != nil {
		return connector.HTTPOptions{}, fmt.Errorf("tls.timeout: %w", err)
	}
	return connector.HTTPOptions{BearerToken: bearer, Username: username, Password: password, InsecureSkipVerify: spec.TLS.InsecureSkipVerify, CAFile: spec.TLS.CAFile, ClientCertFile: spec.TLS.ClientCertFile, ClientKeyFile: spec.TLS.ClientKeyFile, Timeout: timeout}, nil
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func envSecret(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if !envNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid environment variable name %q", name)
	}
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	return value, nil
}
func durationValue(raw string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("must be a positive duration")
	}
	return value, nil
}
func positive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
func tenantHeader(headers map[string]string, tenant string) map[string]string {
	if strings.TrimSpace(tenant) == "" {
		return headers
	}
	return mergeHeader(headers, "X-Scope-OrgID", strings.TrimSpace(tenant))
}
func mergeHeader(headers map[string]string, key, value string) map[string]string {
	if headers == nil {
		headers = map[string]string{}
	}
	if strings.TrimSpace(value) != "" {
		headers[key] = value
	}
	return headers
}

type namespacedConnector struct {
	base        connector.Connector
	id, display string
}

func namespaceConnector(base connector.Connector, name string) connector.Connector {
	clean := strings.ToLower(regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(name, "-"))
	return &namespacedConnector{base: base, id: base.ID() + ":" + clean, display: name + " (" + base.Name() + ")"}
}
func (c *namespacedConnector) ID() string   { return c.id }
func (c *namespacedConnector) Name() string { return c.display }
func (c *namespacedConnector) Sync(ctx context.Context) (connector.Snapshot, error) {
	snapshot, err := c.base.Sync(ctx)
	if err != nil {
		return snapshot, err
	}
	externalPrometheusMetrics := c.base.ID() == "grafana" && snapshotHasDiagnostic(snapshot, "grafana_prometheus_datasource_link")
	idMap := make(map[string]string, len(snapshot.Resources))
	resources := make([]model.Resource, 0, len(snapshot.Resources))
	for index := range snapshot.Resources {
		resource := snapshot.Resources[index]
		old := resource.ID
		if externalPrometheusMetrics && resource.Type == model.ResourceTypeMetric && resource.Source.System == "prometheus" {
			idMap[old] = old
			continue
		}
		next := model.StableID("local_connector_resource", c.id, old)
		idMap[old] = next
		resource.ID = next
		resource.Source.Cluster = c.id
		resources = append(resources, resource)
	}
	snapshot.Resources = resources
	for index := range snapshot.Relationships {
		relation := &snapshot.Relationships[index]
		relation.ID = model.StableID("local_connector_relationship", c.id, relation.ID)
		if next := idMap[relation.FromID]; next != "" {
			relation.FromID = next
		}
		if next := idMap[relation.ToID]; next != "" {
			relation.ToID = next
		}
	}
	for index := range snapshot.Diagnostics {
		snapshot.Diagnostics[index].ID = c.id + ":" + snapshot.Diagnostics[index].ID
	}
	return snapshot, nil
}

func snapshotHasDiagnostic(snapshot connector.Snapshot, id string) bool {
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID == id {
			return true
		}
	}
	return false
}
