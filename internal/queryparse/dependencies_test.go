package queryparse

import "testing"

func TestLogStreams(t *testing.T) {
	dependencies, err := LogStreams(`{app="api",message="literal } brace"} |= "error" or count_over_time({}[5m])`)
	if err != nil {
		t.Fatalf("parse LogQL dependencies: %v", err)
	}
	if len(dependencies) != 2 {
		t.Fatalf("expected two log streams, got %#v", dependencies)
	}
	counts := map[int]int{}
	for _, dependency := range dependencies {
		if dependency.Fingerprint == "" {
			t.Fatalf("expected privacy-safe fingerprint: %#v", dependency)
		}
		counts[dependency.MatcherCount]++
	}
	if counts[0] != 1 || counts[2] != 1 {
		t.Fatalf("unexpected matcher counts: %#v", dependencies)
	}
	if _, err := LogStreams(`{app="api"`); err == nil {
		t.Fatal("expected malformed selector error")
	}
}

func TestTraceServices(t *testing.T) {
	services, err := TraceServices(`{ resource.service.name = "checkout" && span.name =~ "GET.*" } || { .service.name = "${service}" } || { resource.service.name =~ "worker.*" }`)
	if err != nil {
		t.Fatalf("parse TraceQL services: %v", err)
	}
	if len(services) != 1 || services[0] != "checkout" {
		t.Fatalf("expected exact static checkout service, got %#v", services)
	}
}

func TestSQLTables(t *testing.T) {
	tables, err := SQLTables(`
		WITH recent AS (
			SELECT * FROM "sales"."orders"
		)
		SELECT *
		FROM recent
		JOIN customers c ON c.id = recent.customer_id
		JOIN UNNEST(c.items) item ON true;
		UPDATE audit.events SET reviewed = true;
		INSERT INTO reporting.daily_orders SELECT 1;
	`)
	if err != nil {
		t.Fatalf("parse SQL tables: %v", err)
	}
	expected := []string{"audit.events", "customers", "reporting.daily_orders", "sales.orders"}
	if len(tables) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, tables)
	}
	for index := range expected {
		if tables[index] != expected[index] {
			t.Fatalf("expected %v, got %v", expected, tables)
		}
	}
	if _, err := SQLTables(`SELECT * FROM "orders`); err == nil {
		t.Fatal("expected malformed quoted identifier error")
	}
}

func TestNRQLTopLevelScope(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		evaluable   bool
		scopeClause bool
		wantErr     bool
	}{
		{name: "unscoped", query: `SELECT average(duration) FROM Transaction`, evaluable: true},
		{name: "top-level where", query: `SELECT average(duration) FROM Transaction WHERE appName = 'checkout'`, evaluable: true, scopeClause: true},
		{name: "top-level facet", query: `SELECT average(duration) FROM Transaction FACET appName`, evaluable: true, scopeClause: true},
		{name: "case insensitive", query: `select count(*) from Metric where entity.guid = 'opaque' facet hostname`, evaluable: true, scopeClause: true},
		{name: "filter where is not top level", query: `SELECT filter(count(*), WHERE result = 'FAILED') FROM SyntheticCheck`, evaluable: true},
		{name: "quoted keywords", query: `SELECT latest("WHERE") FROM "FACET"`, evaluable: true},
		{name: "commented keywords", query: "SELECT count(*) FROM Transaction -- WHERE appName = 'checkout'\n", evaluable: true},
		{name: "block-commented facet", query: `SELECT count(*) FROM Transaction /* FACET appName */`, evaluable: true},
		{name: "nested source", query: `SELECT max(value) FROM (SELECT average(duration) AS value FROM Transaction WHERE appName = 'checkout')`},
		{name: "missing select", query: `FROM Transaction WHERE appName = 'checkout'`},
		{name: "missing from", query: `SELECT 1`},
		{name: "unclosed quote", query: `SELECT count(*) FROM Transaction WHERE appName = 'checkout`, wantErr: true},
		{name: "unclosed comment", query: `SELECT count(*) FROM Transaction /* FACET appName`, wantErr: true},
		{name: "unbalanced parenthesis", query: `SELECT count(*) FROM Transaction)`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluable, scopeClause, err := NRQLTopLevelScope(test.query)
			if (err != nil) != test.wantErr {
				t.Fatalf("got err=%v, wantErr=%t", err, test.wantErr)
			}
			if evaluable != test.evaluable || scopeClause != test.scopeClause {
				t.Fatalf("got evaluable=%t scopeClause=%t, want evaluable=%t scopeClause=%t", evaluable, scopeClause, test.evaluable, test.scopeClause)
			}
		})
	}
}

func TestNRQLAlertCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		evaluable    bool
		incompatible int
		wantErr      bool
	}{
		{name: "compatible", query: `SELECT average(duration) FROM Transaction WHERE appName = 'checkout' FACET hostname`, evaluable: true},
		{name: "all incompatible clauses", query: `SELECT count(*) FROM Transaction SINCE 1 hour AGO UNTIL now TIMESERIES 1 minute COMPARE WITH 1 week AGO LIMIT 10 SLIDE BY 30 seconds`, evaluable: true, incompatible: 6},
		{name: "case insensitive", query: `select count(*) from Transaction since 5 minutes ago limit max`, evaluable: true, incompatible: 2},
		{name: "source named limit", query: `SELECT count(*) FROM Limit WHERE enabled = true`, evaluable: true},
		{name: "second source named limit", query: `SELECT count(*) FROM Transaction, Limit WHERE enabled = true`, evaluable: true},
		{name: "function-local keywords", query: `SELECT filter(count(*), WHERE clause = 'LIMIT') FROM Transaction`, evaluable: true},
		{name: "quoted keywords", query: `SELECT latest("SINCE") FROM "LIMIT" WHERE note = 'TIMESERIES COMPARE WITH'`, evaluable: true},
		{name: "commented keywords", query: "SELECT count(*) FROM Transaction -- SINCE 1 day ago LIMIT 1\n", evaluable: true},
		{name: "block-commented keywords", query: `SELECT count(*) FROM Transaction /* TIMESERIES COMPARE WITH */`, evaluable: true},
		{name: "compare without with", query: `SELECT latest(compare) FROM Transaction FACET compare`, evaluable: true},
		{name: "compare function before with", query: `SELECT count(*) FROM Transaction FACET compare(hostname) WITH TIMEZONE 'UTC'`, evaluable: true},
		{name: "slide without by", query: `SELECT latest(slide) FROM Transaction FACET slide`, evaluable: true},
		{name: "nested source", query: `SELECT max(value) FROM (SELECT average(duration) AS value FROM Transaction SINCE 1 hour AGO)`},
		{name: "missing select", query: `FROM Transaction LIMIT 1`},
		{name: "missing from", query: `SELECT 1 TIMESERIES 1 minute`},
		{name: "unclosed quote", query: `SELECT count(*) FROM Transaction WHERE appName = 'checkout`, wantErr: true},
		{name: "unclosed comment", query: `SELECT count(*) FROM Transaction /* LIMIT 1`, wantErr: true},
		{name: "unbalanced parenthesis", query: `SELECT count(*) FROM Transaction)`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluable, incompatible, err := NRQLAlertCompatibility(test.query)
			if (err != nil) != test.wantErr {
				t.Fatalf("got err=%v, wantErr=%t", err, test.wantErr)
			}
			if evaluable != test.evaluable || incompatible != test.incompatible {
				t.Fatalf("got evaluable=%t incompatible=%d, want evaluable=%t incompatible=%d", evaluable, incompatible, test.evaluable, test.incompatible)
			}
		})
	}
}
