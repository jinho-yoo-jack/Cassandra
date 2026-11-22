package cvss

import "testing"

func TestScore3(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		// Log4Shell, CVE-2021-44228.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 2.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
	}
	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := Score3(tt.vector)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("Score3 = %.1f, want %.1f", got, tt.want)
			}
		})
	}
	if _, err := Score3("CVSS:4.0/AV:N"); err == nil {
		t.Error("expected error for non v3 vector")
	}
}
