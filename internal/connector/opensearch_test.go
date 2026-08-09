package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"monicheck/internal/model"
)

func TestOpenSearchConnectorAggregatesWithoutPersistingNames(t *testing.T) {
	t.Parallel()
	var healthCalls, indexCalls, nodeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("reader:secret")) {
			t.Fatalf("unexpected authorization header %q", got)
		}
		switch r.URL.Path {
		case "/_cluster/health":
			healthCalls++
			_, _ = w.Write([]byte(`{"cluster_name":"customer-prod","status":"yellow","timed_out":false,"number_of_nodes":3,"number_of_data_nodes":2,"discovered_cluster_manager":true,"active_primary_shards":5,"active_shards":8,"relocating_shards":1,"initializing_shards":0,"unassigned_shards":2,"delayed_unassigned_shards":1,"number_of_pending_tasks":7,"number_of_in_flight_fetch":2,"task_max_waiting_in_queue_millis":1234,"active_shards_percent_as_number":80}`))
		case "/_cat/indices":
			indexCalls++
			if r.URL.Query().Get("format") != "json" || r.URL.Query().Get("bytes") != "b" {
				t.Fatalf("unexpected index query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{"health":"green","status":"open","index":"payments-private","uuid":"secret-uuid","pri":"1","rep":"1","docs.count":"10","store.size":"1000"},{"health":"yellow","status":"open","index":"customer-pii","pri":"1","rep":"1","docs.count":"20","store.size":"2000"}]`))
		case "/_nodes/stats/fs,jvm,process":
			nodeCalls++
			_, _ = w.Write([]byte(`{"_nodes":{"total":2,"successful":2,"failed":0},"nodes":{"private-node-id-1":{"name":"secret-node-a","roles":["data"],"fs":{"total":{"total_in_bytes":1000,"available_in_bytes":200}},"jvm":{"mem":{"heap_used_percent":71}},"process":{"open_file_descriptors":60,"max_file_descriptors":100}},"private-node-id-2":{"name":"secret-node-b","roles":["cluster_manager"],"fs":{"total":{"total_in_bytes":2000,"available_in_bytes":1000}},"jvm":{"mem":{"heap_used_percent":42}},"process":{"open_file_descriptors":20,"max_file_descriptors":100}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewOpenSearchConnectorWithOptions(server.URL, HTTPOptions{Username: "reader", Password: "secret", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Partial || healthCalls != 1 || indexCalls != 1 || nodeCalls != 1 || len(snapshot.Resources) != 1 {
		t.Fatalf("unexpected snapshot %#v calls=%d/%d/%d", snapshot, healthCalls, indexCalls, nodeCalls)
	}
	resource := snapshot.Resources[0]
	if resource.Type != model.ResourceTypeInstance || resource.Source.System != openSearchSystem {
		t.Fatalf("unexpected resource %#v", resource)
	}
	if resource.Metadata[model.MetadataOpenSearchClusterStatus] != "yellow" ||
		resource.Metadata[model.MetadataOpenSearchIndexCount] != "2" ||
		resource.Metadata[model.MetadataOpenSearchDocumentCount] != "30" ||
		resource.Metadata[model.MetadataOpenSearchStoreBytes] != "3000" ||
		resource.Metadata[model.MetadataOpenSearchNodeStatsAvailable] != "true" ||
		resource.Metadata[model.MetadataOpenSearchMaxDiskUsedPercent] != "80.00" ||
		resource.Metadata[model.MetadataOpenSearchMinDiskAvailable] != "200" ||
		resource.Metadata[model.MetadataOpenSearchMaxHeapUsedPercent] != "71" ||
		resource.Metadata[model.MetadataOpenSearchMaxFDUsedPercent] != "60.00" {
		t.Fatalf("unexpected metadata %#v", resource.Metadata)
	}
	for key, value := range resource.Metadata {
		if key == "cluster_name" || value == "customer-prod" || value == "payments-private" || value == "customer-pii" || value == "secret-uuid" ||
			value == "private-node-id-1" || value == "private-node-id-2" || value == "secret-node-a" || value == "secret-node-b" {
			t.Fatalf("sensitive value retained in metadata %#v", resource.Metadata)
		}
	}
}

func TestOpenSearchConnectorKeepsCoreHealthWhenIndexStatsFail(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_cluster/health" {
			_, _ = w.Write([]byte(`{"status":"green","number_of_nodes":1,"number_of_data_nodes":1,"active_shards_percent_as_number":100}`))
			return
		}
		http.Error(w, `{"error":"index-name-and-path-must-not-leak"}`, http.StatusForbidden)
	}))
	defer server.Close()

	connector, err := NewOpenSearchConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Partial || len(snapshot.Resources) != 1 || len(snapshot.Diagnostics) != 2 {
		t.Fatalf("unexpected snapshot %#v", snapshot)
	}
	if snapshot.Resources[0].Metadata[model.MetadataOpenSearchIndexStatsAvailable] != "false" {
		t.Fatalf("expected unavailable index stats %#v", snapshot.Resources[0].Metadata)
	}
	if snapshot.Resources[0].Metadata[model.MetadataOpenSearchNodeStatsAvailable] != "false" {
		t.Fatalf("expected unavailable node stats %#v", snapshot.Resources[0].Metadata)
	}
	if snapshot.Diagnostics[0].Metadata["error"] != "" || strings.Contains(snapshot.Diagnostics[0].Message, "index-name") {
		t.Fatalf("error body leaked in diagnostic %#v", snapshot.Diagnostics[0])
	}
}

func TestOpenSearchConnectorRejectsInvalidHealthStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"unknown","cluster_name":"private"}`))
	}))
	defer server.Close()
	connector, err := NewOpenSearchConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatal("expected invalid health status error")
	}
}

func TestElasticsearchConnectorUsesIndependentIdentityAndRedactedAggregates(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiKey elastic-secret" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		switch r.URL.Path {
		case "/_cluster/health":
			_, _ = w.Write([]byte(`{"cluster_name":"private-elastic","status":"green","number_of_nodes":2,"number_of_data_nodes":1,"discovered_master":true,"active_primary_shards":3,"active_shards":5,"unassigned_shards":0,"active_shards_percent_as_number":100}`))
		case "/_cat/indices":
			_, _ = w.Write([]byte(`[{"health":"green","status":"open","index":"customer-private","pri":"1","rep":"1","docs.count":"12","store.size":"2048"}]`))
		case "/_nodes/stats/fs,jvm,process":
			_, _ = w.Write([]byte(`{"_nodes":{"total":1,"successful":1,"failed":0},"nodes":{"private-node":{"name":"secret-host","fs":{"total":{"total_in_bytes":1000,"available_in_bytes":400}},"jvm":{"mem":{"heap_used_percent":50}},"process":{"open_file_descriptors":25,"max_file_descriptors":100}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	elastic, err := NewElasticsearchConnectorWithOptions(server.URL, HTTPOptions{
		Headers:    map[string]string{"Authorization": "ApiKey elastic-secret"},
		MaxRetries: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := elastic.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elastic.ID() != elasticsearchSystem || elastic.Name() != "Elasticsearch Connector" ||
		snapshot.Partial || len(snapshot.Resources) != 1 || len(snapshot.Diagnostics) != 2 {
		t.Fatalf("unexpected connector snapshot %#v", snapshot)
	}
	resource := snapshot.Resources[0]
	if resource.Source.System != elasticsearchSystem || resource.Name != "Elasticsearch Cluster" ||
		resource.Metadata["elasticsearch_index_count"] != "1" ||
		resource.Metadata["elasticsearch_max_disk_used_percent"] != "60.00" ||
		resource.Metadata[model.MetadataOpenSearchIndexCount] != "" {
		t.Fatalf("unexpected Elasticsearch aggregate %#v", resource)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(data)
	for _, secret := range []string{"elastic-secret", "private-elastic", "customer-private", "private-node", "secret-host"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, serialized)
		}
	}
	if snapshot.Diagnostics[0].ID != "elasticsearch_index_stats" ||
		snapshot.Diagnostics[1].ID != "elasticsearch_node_stats" {
		t.Fatalf("unexpected diagnostics %#v", snapshot.Diagnostics)
	}
}

func TestSearchClusterConnectorRejectsURLUserinfo(t *testing.T) {
	t.Parallel()
	for _, constructor := range []func(string, HTTPOptions) (*OpenSearchConnector, error){
		NewOpenSearchConnectorWithOptions,
		NewElasticsearchConnectorWithOptions,
	} {
		if _, err := constructor("https://reader:secret@example.test", HTTPOptions{}); err == nil {
			t.Fatal("expected URL userinfo to be rejected")
		}
	}
}
