package model

import "testing"

func TestNormalizeSLOObjective(t *testing.T) {
	tests := []struct {
		raw      string
		expected string
		valid    bool
	}{
		{raw: "99.9", expected: "0.999", valid: true},
		{raw: "99.9%", expected: "0.999", valid: true},
		{raw: "0.999", expected: "0.999", valid: true},
		{raw: "99.95", expected: "0.9995", valid: true},
		{raw: "1%", expected: "0.01", valid: true},
		{raw: "", valid: false},
		{raw: "0", valid: false},
		{raw: "1", valid: false},
		{raw: "100", valid: false},
		{raw: "100%", valid: false},
		{raw: "-99", valid: false},
		{raw: "NaN", valid: false},
		{raw: "+Inf", valid: false},
		{raw: "almost-all", valid: false},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			actual, valid := NormalizeSLOObjective(test.raw)
			if actual != test.expected || valid != test.valid {
				t.Fatalf("NormalizeSLOObjective(%q) = %q, %t; want %q, %t", test.raw, actual, valid, test.expected, test.valid)
			}
		})
	}
}

func TestNormalizeSLOWindow(t *testing.T) {
	tests := []struct {
		raw      string
		expected string
		valid    bool
	}{
		{raw: "5m", expected: "5m0s", valid: true},
		{raw: "6h", expected: "6h0m0s", valid: true},
		{raw: "3d", expected: "72h0m0s", valid: true},
		{raw: "1w", expected: "168h0m0s", valid: true},
		{raw: "1d12h", expected: "36h0m0s", valid: true},
		{raw: "1d 12h", expected: "36h0m0s", valid: true},
		{raw: "", valid: false},
		{raw: "0s", valid: false},
		{raw: "-5m", valid: false},
		{raw: "forever", valid: false},
		{raw: "1d-junk", valid: false},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			actual, _, valid := NormalizeSLOWindow(test.raw)
			if actual != test.expected || valid != test.valid {
				t.Fatalf("NormalizeSLOWindow(%q) = %q, %t; want %q, %t", test.raw, actual, valid, test.expected, test.valid)
			}
		})
	}
}
