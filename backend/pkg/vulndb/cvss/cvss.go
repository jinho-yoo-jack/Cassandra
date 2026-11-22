// Package cvss computes CVSS v3.x base scores from vector strings, as
// specified in the CVSS v3.1 specification, section 7.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

var weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// privilegesRequired depends on scope.
var privilegesRequired = map[string]map[bool]float64{
	"N": {false: 0.85, true: 0.85},
	"L": {false: 0.62, true: 0.68},
	"H": {false: 0.27, true: 0.5},
}

// Score3 returns the base score of a "CVSS:3.0/..." or "CVSS:3.1/..." vector.
func Score3(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("malformed metric %q", p)
		}
		m[k] = v
	}
	get := func(metric string) (float64, error) {
		w, ok := weights[metric][m[metric]]
		if !ok {
			return 0, fmt.Errorf("invalid %s value %q", metric, m[metric])
		}
		return w, nil
	}
	changed := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, fmt.Errorf("invalid S value %q", m["S"])
	}
	pr, ok := privilegesRequired[m["PR"]][changed]
	if !ok {
		return 0, fmt.Errorf("invalid PR value %q", m["PR"])
	}
	var vals [6]float64
	for i, metric := range []string{"AV", "AC", "UI", "C", "I", "A"} {
		w, err := get(metric)
		if err != nil {
			return 0, err
		}
		vals[i] = w
	}
	av, ac, ui, c, i, a := vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, nil
	}
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundUp(math.Min(impact+exploitability, 10)), nil
}

// roundUp is the CVSS v3.1 Roundup function, which avoids floating point
// artefacts by working in integers.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
