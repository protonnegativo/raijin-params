package raijinparams

import "testing"

func TestEnginesHasEveryEngine(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	// raijin-params runs arjun only.
	for _, name := range []string{"arjun"} {
		e, ok := m[name]
		if !ok || e.Version == "" || e.Pip == "" {
			t.Errorf("%s: %+v", name, e)
		}
	}
}
