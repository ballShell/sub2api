package seeds

import _ "embed"

//go:embed probe_suites.v1.json
var defaultSuitesJSON []byte

//go:embed family_maps.v1.json
var defaultFamilyMapsJSON []byte

//go:embed baselines.v1.json
var defaultBaselinesJSON []byte

// LoadDefaultSuites returns a copy of the embedded default probe suite seed JSON.
func LoadDefaultSuites() ([]byte, error) {
	return append([]byte(nil), defaultSuitesJSON...), nil
}

// LoadDefaultFamilyMaps returns a copy of the embedded default model family map seed JSON.
func LoadDefaultFamilyMaps() ([]byte, error) {
	return append([]byte(nil), defaultFamilyMapsJSON...), nil
}

// LoadDefaultBaselines returns a copy of the embedded default baseline seed JSON.
func LoadDefaultBaselines() ([]byte, error) {
	return append([]byte(nil), defaultBaselinesJSON...), nil
}
