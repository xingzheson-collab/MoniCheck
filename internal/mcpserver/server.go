package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"monicheck/internal/agentkit"
	"monicheck/internal/buildinfo"
	"monicheck/internal/localruntime"
	"monicheck/internal/model"
)

const latestProtocolVersion = "2025-11-25"

var supportedProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

type Server struct {
	Input  io.Reader
	Output io.Writer
	Errors io.Writer
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *protocolError  `json:"error,omitempty"`
}

type protocolError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolResult struct {
	Content           []textContent `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type scanInput struct {
	ConfigPath  string `json:"config_path"`
	StoragePath string `json:"storage_path"`
}

type findingsQueryToolInput struct {
	StoragePath string `json:"storage_path"`
	Service     string `json:"service"`
	Entity      string `json:"entity"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Limit       int    `json:"limit"`
	Purpose     string `json:"purpose"`
}

type coverageByServiceToolInput struct {
	StoragePath string `json:"storage_path"`
	Service     string `json:"service"`
	Purpose     string `json:"purpose"`
}

type entityGetToolInput struct {
	StoragePath string `json:"storage_path"`
	ID          string `json:"id"`
	Limit       int    `json:"limit"`
	Purpose     string `json:"purpose"`
}

type baselineDiffToolInput struct {
	StoragePath string `json:"storage_path"`
	Limit       int    `json:"limit"`
	Purpose     string `json:"purpose"`
}

type reportExportToolInput struct {
	StoragePath string `json:"storage_path"`
	OutputPath  string `json:"output_path"`
}

func (s Server) Run(ctx context.Context) error {
	if s.Input == nil || s.Output == nil {
		return errors.New("MCP stdio input and output are required")
	}
	if s.Errors == nil {
		s.Errors = io.Discard
	}
	scanner := bufio.NewScanner(s.Input)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	encoder := json.NewEncoder(s.Output)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var message request
		if err := json.Unmarshal(line, &message); err != nil {
			if encodeErr := encoder.Encode(response{JSONRPC: "2.0", Error: &protocolError{Code: -32700, Message: "Parse error"}}); encodeErr != nil {
				return encodeErr
			}
			continue
		}
		result, rpcErr := s.handle(ctx, message)
		if len(message.ID) == 0 {
			continue
		}
		if err := encoder.Encode(response{JSONRPC: "2.0", ID: message.ID, Result: result, Error: rpcErr}); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP stdio: %w", err)
	}
	return nil
}

func (s Server) handle(ctx context.Context, message request) (any, *protocolError) {
	if message.JSONRPC != "2.0" || strings.TrimSpace(message.Method) == "" {
		return nil, &protocolError{Code: -32600, Message: "Invalid Request"}
	}
	switch message.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(message.Params, &params); err != nil {
			return nil, &protocolError{Code: -32602, Message: "Invalid initialize parameters"}
		}
		protocolVersion := latestProtocolVersion
		if supportedProtocolVersions[params.ProtocolVersion] {
			protocolVersion = params.ProtocolVersion
		}
		info := buildinfo.Current()
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo": map[string]any{
				"name": "monicheck-local", "title": "MoniCheck Local", "version": info.Version,
				"description": "Read-only local observability audit tools backed by deterministic MoniCheck analyzers.",
			},
			"instructions": "Audit tools return privacy-safe aggregate evidence by default. Entity identifiers are available only through bounded need-to-know query tools with an explicit user purpose and a local audit record. Credentials are read only from the MoniCheck process environment and must never be passed as tool arguments.",
		}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools()}, nil
	case "tools/call":
		var params callToolParams
		if err := json.Unmarshal(message.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			return nil, &protocolError{Code: -32602, Message: "Invalid tool parameters"}
		}
		return s.callTool(ctx, params), nil
	default:
		return nil, &protocolError{Code: -32601, Message: "Method not found"}
	}
}

func tools() []toolDefinition {
	localReadOnly := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	auditReadOnly := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true}
	queryReadOnly := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false}
	localWrite := map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	return []toolDefinition{
		{
			Name: "monicheck.connectors.list", Title: "List MoniCheck connectors",
			Description: "List Local connector types without contacting an observability system.",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false}, Annotations: localReadOnly,
		},
		{
			Name: "monicheck.config.validate", Title: "Validate MoniCheck configuration",
			Description: "Validate a local YAML connector configuration. Secret values are not accepted in YAML; only environment variable names are allowed.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{"config_path": map[string]any{"type": "string", "description": "Local path to a MoniCheck connector YAML file."}},
				"required":   []string{"config_path"},
			}, Annotations: localReadOnly,
		},
		{
			Name: "monicheck.audit.run", Title: "Run a local observability audit",
			Description: "Run deterministic Local connectors and analyzers, persist the local baseline, and return a bounded privacy-safe agent-audit.v1 summary. At least one YAML or environment-configured live source is required; persisted state is never silently replayed. Credentials come only from process environment variables.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"config_path":  map[string]any{"type": "string", "description": "Optional local YAML configuration path. Endpoint and credential values are read by MoniCheck, not returned to the agent."},
					"storage_path": map[string]any{"type": "string", "description": "Optional durable local state path used for baseline comparison."},
				},
			}, Annotations: auditReadOnly,
		},
		{
			Name: "monicheck.report.export", Title: "Export the latest owner-only governance report",
			Description: "Write the latest completed governance report from durable Local state to a user-selected private file. The report content is not returned through MCP.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"storage_path": map[string]any{"type": "string", "description": "Optional durable Local state path produced by a completed audit."},
					"output_path":  map[string]any{"type": "string", "description": "Required local destination for the owner-only governance JSON."},
				},
				"required": []string{"output_path"},
			}, Annotations: localWrite,
		},
		{
			Name: "monicheck.findings.query", Title: "Query scoped MoniCheck findings",
			Description: "Return bounded current findings for a user-requested service, entity, finding type, or severity. Resource identifiers are disclosed only within this purpose-bound scope and the disclosure is recorded locally.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"storage_path": map[string]any{"type": "string", "description": "Optional durable Local state path produced by monicheck.audit.run."},
					"service":      map[string]any{"type": "string", "description": "Optional exact or uniquely matching Service name, UID, or ID from the user's question."},
					"entity":       map[string]any{"type": "string", "description": "Optional exact or uniquely matching entity name, UID, or ID from the user's question."},
					"type":         map[string]any{"type": "string", "description": "Optional exact finding type."},
					"severity":     map[string]any{"type": "string", "enum": []string{"CRITICAL", "WARNING", "INFO"}},
					"limit":        map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
					"purpose":      map[string]any{"type": "string", "maxLength": 240, "description": "Required concise statement of the user's active investigation purpose."},
				},
				"required": []string{"purpose"},
			}, Annotations: queryReadOnly,
		},
		{
			Name: "monicheck.coverage.by_service", Title: "Inspect monitoring coverage for one Service",
			Description: "Return the deterministic metric, dashboard, and alert coverage matrix for one user-requested Service, preserving MISSING and UNKNOWN semantics.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"storage_path": map[string]any{"type": "string"},
					"service":      map[string]any{"type": "string", "description": "Exact or uniquely matching Service name, UID, or ID."},
					"purpose":      map[string]any{"type": "string", "maxLength": 240, "description": "Required concise statement of the user's active investigation purpose."},
				},
				"required": []string{"service", "purpose"},
			}, Annotations: queryReadOnly,
		},
		{
			Name: "monicheck.entity.get", Title: "Inspect one MoniCheck entity",
			Description: "Return one exact entity, bounded graph relationships, and current findings. Labels, raw queries, raw evidence, endpoints, and credentials remain excluded.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"storage_path": map[string]any{"type": "string"},
					"id":           map[string]any{"type": "string", "description": "Exact entity ID returned by another MoniCheck query."},
					"limit":        map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
					"purpose":      map[string]any{"type": "string", "maxLength": 240, "description": "Required concise statement of the user's active investigation purpose."},
				},
				"required": []string{"id", "purpose"},
			}, Annotations: queryReadOnly,
		},
		{
			Name: "monicheck.baseline.diff", Title: "Inspect the latest Local baseline change",
			Description: "Return bounded deterministic changes between the latest two Local snapshots, with identifiers only where current evidence can resolve them.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"storage_path": map[string]any{"type": "string"},
					"limit":        map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
					"purpose":      map[string]any{"type": "string", "maxLength": 240, "description": "Required concise statement of the user's active comparison purpose."},
				},
				"required": []string{"purpose"},
			}, Annotations: queryReadOnly,
		},
	}
}

func (s Server) callTool(ctx context.Context, params callToolParams) toolResult {
	var value any
	var err error
	switch params.Name {
	case "monicheck.connectors.list":
		value = map[string]any{"contract_version": "connector-catalog.v1", "connectors": localruntime.ConnectorCatalog()}
	case "monicheck.config.validate":
		var input struct {
			ConfigPath string `json:"config_path"`
		}
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		if strings.TrimSpace(input.ConfigPath) == "" {
			err = errors.New("config_path is required")
			break
		}
		var config localruntime.FileConfig
		config, err = localruntime.ValidateFileConfig(input.ConfigPath)
		if err == nil {
			connectorCounts := make(map[string]int)
			for _, connector := range config.Connectors {
				connectorCounts[connector.Type]++
			}
			value = map[string]any{"contract_version": "config-validation.v1", "valid": true, "connector_count": len(config.Connectors), "connector_type_counts": connectorCounts}
		}
	case "monicheck.audit.run":
		var input scanInput
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		storagePath := strings.TrimSpace(input.StoragePath)
		if storagePath == "" {
			storagePath = defaultStoragePath()
		}
		value, err = agentkit.Run(ctx, localruntime.Options{
			Listen: "127.0.0.1:0", StoragePath: storagePath, LogLevel: "quiet", ConfigPath: input.ConfigPath,
			PrometheusURL:           os.Getenv("MONICHECK_PROMETHEUS_URL"),
			PrometheusDatasourceUID: os.Getenv("MONICHECK_GRAFANA_PROMETHEUS_DATASOURCE_UID"),
			GrafanaURL:              os.Getenv("MONICHECK_GRAFANA_URL"),
			AlertmanagerURL:         os.Getenv("MONICHECK_ALERTMANAGER_URL"),
			KubernetesManifest:      os.Getenv("MONICHECK_KUBERNETES_MANIFEST_PATH"),
		})
	case "monicheck.report.export":
		var input reportExportToolInput
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		storagePath := queryStoragePath(input.StoragePath)
		var exported model.ReportExport
		exported, err = localruntime.ExportLatestReport(ctx, storagePath, input.OutputPath)
		if err == nil {
			value = map[string]any{
				"contract_version": "agent-report-export.v1", "written": true,
				"output_path": input.OutputPath, "created_at": exported.CreatedAt,
				"content_returned": false,
			}
		}
	case "monicheck.findings.query":
		var input findingsQueryToolInput
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		value, err = agentkit.QueryFindings(ctx, queryStoragePath(input.StoragePath), agentkit.FindingQueryInput{
			Service: input.Service, Entity: input.Entity, Type: input.Type, Severity: input.Severity, Limit: input.Limit, Purpose: input.Purpose,
		})
	case "monicheck.coverage.by_service":
		var input coverageByServiceToolInput
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		value, err = agentkit.CoverageByService(ctx, queryStoragePath(input.StoragePath), agentkit.CoverageByServiceInput{Service: input.Service, Purpose: input.Purpose})
	case "monicheck.entity.get":
		var input entityGetToolInput
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		value, err = agentkit.GetEntity(ctx, queryStoragePath(input.StoragePath), agentkit.EntityGetInput{ID: input.ID, Limit: input.Limit, Purpose: input.Purpose})
	case "monicheck.baseline.diff":
		var input baselineDiffToolInput
		if decodeErr := decodeArguments(params.Arguments, &input); decodeErr != nil {
			err = decodeErr
			break
		}
		value, err = agentkit.BaselineDiff(ctx, queryStoragePath(input.StoragePath), agentkit.BaselineDiffInput{Limit: input.Limit, Purpose: input.Purpose})
	default:
		err = fmt.Errorf("unknown tool %q", params.Name)
	}
	if err != nil {
		return toolResult{Content: []textContent{{Type: "text", Text: err.Error()}}, IsError: true}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return toolResult{Content: []textContent{{Type: "text", Text: "encode tool result failed"}}, IsError: true}
	}
	return toolResult{Content: []textContent{{Type: "text", Text: string(encoded)}}, StructuredContent: value, IsError: false}
}

func decodeArguments(raw json.RawMessage, target any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	return nil
}

func defaultStoragePath() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return ".monicheck-state.json"
	}
	return filepath.Join(directory, "monicheck", "local-state.json")
}

func queryStoragePath(value string) string {
	if strings.TrimSpace(value) == "" {
		return defaultStoragePath()
	}
	return strings.TrimSpace(value)
}
