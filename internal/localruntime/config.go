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
	coveragepkg "monicheck/internal/coverage"
	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

type FileConfig struct {
	Version              int                       `yaml:"version"`
	Connectors           []ConnectorSpec           `yaml:"connectors"`
	CoverageExpectations []CoverageExpectationSpec `yaml:"coverage_expectations"`
	CoverageExceptions   []CoverageExceptionSpec   `yaml:"coverage_exceptions"`
}

type CoverageExpectationSpec struct {
	ID              string   `yaml:"id"`
	Name            string   `yaml:"name"`
	Scope           string   `yaml:"scope"`
	ScopeValue      string   `yaml:"scope_value"`
	RequiredSignals []string `yaml:"required_signals"`
	Owner           string   `yaml:"owner"`
	Rationale       string   `yaml:"rationale"`
	Enabled         *bool    `yaml:"enabled"`
}

type CoverageExceptionSpec struct {
	ID            string `yaml:"id"`
	ExpectationID string `yaml:"expectation_id"`
	ServiceID     string `yaml:"service_id"`
	Signal        string `yaml:"signal"`
	Owner         string `yaml:"owner"`
	Reason        string `yaml:"reason"`
	CreatedBy     string `yaml:"created_by"`
	ExpiresAt     string `yaml:"expires_at"`
}

type ConnectorSpec struct {
	Type                    string   `yaml:"type"`
	Name                    string   `yaml:"name"`
	URL                     string   `yaml:"url"`
	PrometheusDatasourceUID string   `yaml:"prometheus_datasource_uid"`
	DatasourceFilterUID     string   `yaml:"datasource_filter_uid"`
	Path                    string   `yaml:"path"`
	HealthURL               string   `yaml:"health_url"`
	MetricsURL              string   `yaml:"metrics_url"`
	RulePath                string   `yaml:"rule_path"`
	GraphQLPath             string   `yaml:"graphql_path"`
	Namespace               string   `yaml:"namespace"`
	TenantID                string   `yaml:"tenant_id"`
	FeatureGates            string   `yaml:"feature_gates"`
	Lookback                string   `yaml:"lookback"`
	DependencyLookback      string   `yaml:"dependency_lookback"`
	OperationLimit          int      `yaml:"operation_limit"`
	DependencyLimit         int      `yaml:"dependency_limit"`
	TagValueLimit           int      `yaml:"tag_value_limit"`
	EndpointLimit           int      `yaml:"endpoint_limit"`
	AlarmLimit              int      `yaml:"alarm_limit"`
	AccountID               int      `yaml:"account_id"`
	HistoryWindowHours      int      `yaml:"history_window_hours"`
	HistoryEventLimit       int      `yaml:"history_event_limit"`
	Auth                    AuthSpec `yaml:"auth"`
	TLS                     TLSSpec  `yaml:"tls"`
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
		return FileConfig{}, fmt.Errorf("config must contain at least one connector")
	}
	return cfg, nil
}

func applyCoverageConfig(ctx context.Context, store *storage.Store, cfg FileConfig, now time.Time) error {
	expectations, err := store.CoverageExpectations.List(ctx)
	if err != nil {
		return err
	}
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return err
	}
	relationships, err := store.Relationships.List(ctx)
	if err != nil {
		return err
	}
	resourceGraph := graph.NewBounded(resources, relationships)
	pendingExpectations := make([]model.CoverageExpectation, 0, len(cfg.CoverageExpectations))
	for index, spec := range cfg.CoverageExpectations {
		enabled := true
		if spec.Enabled != nil {
			enabled = *spec.Enabled
		}
		signals := make([]model.CoverageSignal, 0, len(spec.RequiredSignals))
		for _, signal := range spec.RequiredSignals {
			signals = append(signals, model.CoverageSignal(strings.ToLower(strings.TrimSpace(signal))))
		}
		expectation := model.CoverageExpectation{
			ID: strings.TrimSpace(spec.ID), Name: strings.TrimSpace(spec.Name), Scope: model.CoverageExpectationScope(strings.ToUpper(strings.TrimSpace(spec.Scope))),
			ScopeValue: strings.TrimSpace(spec.ScopeValue), RequiredSignals: signals, Owner: strings.TrimSpace(spec.Owner), Rationale: strings.TrimSpace(spec.Rationale),
			Enabled: enabled, CreatedBy: "local-config", CreatedAt: now, UpdatedBy: "local-config", UpdatedAt: now,
		}
		if err := coveragepkg.ValidateExpectation(expectation); err != nil {
			return fmt.Errorf("coverage_expectations[%d]: %w", index, err)
		}
		if expectation.Enabled {
			summary := coveragepkg.Assess(resources, resourceGraph, []model.CoverageExpectation{expectation}, nil, now)
			if len(summary.Assessments) == 0 {
				return fmt.Errorf("coverage_expectations[%d] %q matched 0 active services; check scope and scope_value against the observed Service inventory", index, expectation.ID)
			}
		}
		pendingExpectations = append(pendingExpectations, expectation)
		expectations = replaceCoverageExpectation(expectations, expectation)
	}
	pendingExceptions := make([]model.CoverageException, 0, len(cfg.CoverageExceptions))
	for index, spec := range cfg.CoverageExceptions {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(spec.ExpiresAt))
		if err != nil {
			return fmt.Errorf("coverage_exceptions[%d].expires_at must be RFC3339", index)
		}
		exception := model.CoverageException{
			ID: strings.TrimSpace(spec.ID), ExpectationID: strings.TrimSpace(spec.ExpectationID), ServiceID: strings.TrimSpace(spec.ServiceID),
			Signal: model.CoverageSignal(strings.ToLower(strings.TrimSpace(spec.Signal))), Owner: strings.TrimSpace(spec.Owner), Reason: strings.TrimSpace(spec.Reason),
			CreatedBy: strings.TrimSpace(spec.CreatedBy), CreatedAt: now, ExpiresAt: expiresAt,
		}
		if exception.ID == "" {
			exception.ID = model.StableID("coverage_exception", exception.ExpectationID, exception.ServiceID, string(exception.Signal))
		}
		if err := coveragepkg.ValidateException(exception, expectations, now); err != nil {
			return fmt.Errorf("coverage_exceptions[%d]: %w", index, err)
		}
		summary := coveragepkg.Assess(resources, resourceGraph, expectations, []model.CoverageException{exception}, now)
		if !coverageExceptionApplied(summary, exception) {
			return fmt.Errorf("coverage_exceptions[%d] %q matched 0 active service-signal assessments; scan first, then copy the exact service_id and verify the expectation scope", index, exception.ID)
		}
		pendingExceptions = append(pendingExceptions, exception)
	}
	for _, expectation := range pendingExpectations {
		if err := store.CoverageExpectations.Save(ctx, expectation); err != nil {
			return err
		}
	}
	for _, exception := range pendingExceptions {
		if err := store.CoverageExceptions.Save(ctx, exception); err != nil {
			return err
		}
	}
	return nil
}

func replaceCoverageExpectation(items []model.CoverageExpectation, candidate model.CoverageExpectation) []model.CoverageExpectation {
	for index := range items {
		if items[index].ID == candidate.ID {
			items[index] = candidate
			return items
		}
	}
	return append(items, candidate)
}

func coverageExceptionApplied(summary coveragepkg.Summary, exception model.CoverageException) bool {
	for _, assessment := range summary.Assessments {
		if assessment.ExpectationID != exception.ExpectationID || assessment.ServiceID != exception.ServiceID {
			continue
		}
		for _, signal := range assessment.Signals {
			if signal.Signal == exception.Signal && signal.State == coveragepkg.SignalExempt && signal.ExceptionID == exception.ID {
				return true
			}
		}
	}
	return false
}

func buildConfiguredConnectors(cfg FileConfig) ([]connector.Connector, error) {
	type configuredConnector struct {
		base     connector.Connector
		name     string
		typeName string
		spec     ConnectorSpec
	}
	seenNames := map[string]bool{}
	configured := make([]configuredConnector, 0, len(cfg.Connectors))
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
		if strings.TrimSpace(spec.PrometheusDatasourceUID) != "" && typeName != "prometheus" {
			return nil, fmt.Errorf("connectors[%d] %s: prometheus_datasource_uid is valid only for prometheus", index, name)
		}
		if strings.TrimSpace(spec.DatasourceFilterUID) != "" && typeName != "grafana" {
			return nil, fmt.Errorf("connectors[%d] %s: datasource_filter_uid is valid only for grafana", index, name)
		}
		configured = append(configured, configuredConnector{base: base, name: name, typeName: typeName, spec: spec})
	}

	var binding *configuredConnector
	grafanaCount := 0
	var grafana *connector.GrafanaConnector
	for index := range configured {
		item := &configured[index]
		if item.typeName == "grafana" {
			grafanaCount++
			grafana, _ = item.base.(*connector.GrafanaConnector)
			if strings.TrimSpace(item.spec.DatasourceFilterUID) != "" {
				if err := grafana.ConfigureDashboardDatasourceFilter(item.spec.DatasourceFilterUID); err != nil {
					return nil, fmt.Errorf("configure Grafana dashboard datasource filter: %w", err)
				}
			}
		}
		if strings.TrimSpace(item.spec.PrometheusDatasourceUID) != "" {
			if binding != nil {
				return nil, fmt.Errorf("only one prometheus_datasource_uid binding is supported per config")
			}
			binding = item
		}
	}
	if binding != nil {
		if grafanaCount != 1 || grafana == nil {
			return nil, fmt.Errorf("prometheus_datasource_uid requires exactly one grafana connector")
		}
		if err := grafana.ConfigurePrometheusDatasource(binding.spec.URL, binding.spec.PrometheusDatasourceUID, namespacedConnectorID(binding.base, binding.name)); err != nil {
			return nil, fmt.Errorf("configure prometheus datasource binding: %w", err)
		}
	}

	result := make([]connector.Connector, 0, len(configured))
	for _, item := range configured {
		result = append(result, namespaceConnector(item.base, item.name))
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
		apiKey, err := envSecret(spec.Auth.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		if options.BearerToken == "" {
			options.BearerToken = apiKey
		}
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
	return &namespacedConnector{base: base, id: namespacedConnectorID(base, name), display: name + " (" + base.Name() + ")"}
}
func namespacedConnectorID(base connector.Connector, name string) string {
	clean := strings.ToLower(regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(name, "-"))
	return base.ID() + ":" + clean
}
func (c *namespacedConnector) ID() string   { return c.id }
func (c *namespacedConnector) Name() string { return c.display }
func (c *namespacedConnector) Sync(ctx context.Context) (connector.Snapshot, error) {
	snapshot, err := c.base.Sync(ctx)
	if err != nil {
		return snapshot, err
	}
	idMap := make(map[string]string, len(snapshot.Resources))
	resources := make([]model.Resource, 0, len(snapshot.Resources))
	references := append([]model.Resource(nil), snapshot.References...)
	for _, reference := range snapshot.References {
		idMap[reference.ID] = reference.ID
	}
	for index := range snapshot.Resources {
		resource := snapshot.Resources[index]
		old := resource.ID
		next := model.LocalConnectorResourceID(c.id, old)
		idMap[old] = next
		resource.ID = next
		resource.Source.Cluster = c.id
		resources = append(resources, resource)
	}
	snapshot.Resources = resources
	snapshot.References = references
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
