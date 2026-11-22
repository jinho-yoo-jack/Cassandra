package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		eco, a, b string
		want      int
	}{
		{"Go", "v1.9.0", "v1.10.0", -1},
		{"Go", "1.9.1", "v1.9.1", 0},
		{"Go", "v0.0.0-20230101000000-abcdef123456", "v0.1.0", -1},
		{"npm", "4.17.20", "4.17.21", -1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"PyPI", "2.25.0", "2.25", 0},
		{"PyPI", "1.0rc1", "1.0", -1},
		{"PyPI", "1.0.post1", "1.0", 1},
		{"PyPI", "1.0rc10", "1.0rc9", 1},
		{"Maven", "2.14.1", "2.17.1", -1},
		{"Maven", "5.3.20.RELEASE", "5.3.20", 0},
		{"Maven", "32.0.0-jre", "31.1-jre", 1},
		{"Maven", "1.0-SNAPSHOT", "1.0", -1},
		{"Process", "1.25.3", "1.25.10", -1},
		{"Process", "2.4.58", "2.4.62", -1},
	}
	for _, tt := range tests {
		t.Run(tt.eco+"/"+tt.a+"_vs_"+tt.b, func(t *testing.T) {
			if got := Compare(tt.eco, tt.a, tt.b); got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if got := Compare(tt.eco, tt.b, tt.a); got != -tt.want {
				t.Errorf("Compare is not antisymmetric for %q, %q", tt.b, tt.a)
			}
		})
	}
}
