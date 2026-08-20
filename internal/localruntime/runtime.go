package localruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/connector"
	"monicheck/internal/execution"
	"monicheck/internal/logger"
	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

type Options struct {
	Listen, StoragePath, LogLevel, ConfigPath                      string
	PrometheusURL, GrafanaURL, AlertmanagerURL, KubernetesManifest string
	ActivationStartedAt                                            time.Time
}

type Runtime struct {
	Store     *storage.Store
	Engine    *execution.Engine
	Execution model.ExecutionResult
}

func ValidateOptions(o Options) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(o.Listen))
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return errors.New("--listen must be a loopback host and port")
	}
	if strings.TrimSpace(o.StoragePath) == "" {
		return errors.New("--storage-path is required")
	}
	if o.ConfigPath == "" && o.PrometheusURL == "" && o.GrafanaURL == "" && o.AlertmanagerURL == "" && o.KubernetesManifest == "" {
		return errors.New("configure at least one local source")
	}
	return nil
}

func New(ctx context.Context, o Options) (*Runtime, error) {
	started := o.ActivationStartedAt.UTC()
	if started.IsZero() {
		started = time.Now().UTC()
	}
	store, err := storage.NewFileStore(o.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("open local state: %w", err)
	}
	connectors, err := buildConnectors(o)
	if err != nil {
		return nil, err
	}
	engine := execution.NewEngine(store, connectors, newRegistry(), logger.New(os.Stderr, o.LogLevel))
	executionResult, err := engine.Bootstrap(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := report.SaveLocalPostureSnapshot(ctx, store, executionResult); err != nil {
		return nil, err
	}
	if _, err := report.SaveLocalActivationTiming(ctx, store, started, time.Now().UTC(), 15*time.Minute); err != nil {
		return nil, err
	}
	return &Runtime{Store: store, Engine: engine, Execution: executionResult}, nil
}

func (r *Runtime) LatestReport(ctx context.Context) (model.ReportExport, error) {
	exports, err := r.Store.ReportExports.List(ctx)
	if err != nil {
		return model.ReportExport{}, err
	}
	var latest model.ReportExport
	for _, item := range exports {
		if item.Origin == report.LocalPostureSnapshotOrigin && (latest.CreatedAt.IsZero() || item.CreatedAt.After(latest.CreatedAt)) {
			latest = item
		}
	}
	if latest.ID == "" {
		return latest, errors.New("local report unavailable")
	}
	return latest, nil
}

func buildConnectors(o Options) ([]connector.Connector, error) {
	var result []connector.Connector
	if strings.TrimSpace(o.ConfigPath) != "" {
		cfg, err := LoadFileConfig(o.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("load --config: %w", err)
		}
		configured, err := buildConfiguredConnectors(cfg)
		if err != nil {
			return nil, err
		}
		result = append(result, configured...)
	}
	for _, item := range []struct{ id, url string }{{"prometheus", o.PrometheusURL}, {"grafana", o.GrafanaURL}, {"alertmanager", o.AlertmanagerURL}} {
		if strings.TrimSpace(item.url) == "" {
			continue
		}
		httpOptions := envHTTPOptions(strings.ToUpper(item.id))
		var c connector.Connector
		var err error
		switch item.id {
		case "prometheus":
			c, err = connector.NewPrometheusConnectorWithOptions(item.url, httpOptions)
		case "grafana":
			c, err = connector.NewGrafanaConnectorWithOptions(item.url, httpOptions)
		case "alertmanager":
			c, err = connector.NewAlertmanagerConnectorWithOptions(item.url, httpOptions)
		}
		if err != nil {
			return nil, fmt.Errorf("configure %s: %w", item.id, err)
		}
		result = append(result, namespaceConnector(c, item.id+"-shortcut"))
	}
	if o.KubernetesManifest != "" {
		c, err := connector.NewKubernetesManifestConnector(o.KubernetesManifest)
		if err != nil {
			return nil, err
		}
		result = append(result, namespaceConnector(c, "kubernetes-shortcut"))
	}
	return result, nil
}

func envHTTPOptions(prefix string) connector.HTTPOptions {
	key := "MONICHECK_" + prefix + "_"
	insecure, _ := strconv.ParseBool(os.Getenv(key + "TLS_INSECURE_SKIP_VERIFY"))
	return connector.HTTPOptions{BearerToken: os.Getenv(key + "BEARER_TOKEN"), Username: os.Getenv(key + "USERNAME"), Password: os.Getenv(key + "PASSWORD"), APIKey: os.Getenv(key + "API_KEY"), CAFile: os.Getenv(key + "TLS_CA_FILE"), ClientCertFile: os.Getenv(key + "TLS_CLIENT_CERT_FILE"), ClientKeyFile: os.Getenv(key + "TLS_CLIENT_KEY_FILE"), InsecureSkipVerify: insecure}
}
