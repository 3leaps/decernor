package testcorpus

import "testing"

func TestValidatePathsRejectsNonLocal(t *testing.T) {
	ok := Manifest{FixturesRoot: "fixtures-agent", Fixtures: map[string]Fixture{"benign/notes.txt": {}}}
	if err := validatePaths(ok); err != nil {
		t.Fatalf("local paths rejected: %v", err)
	}
	for name, m := range map[string]Manifest{
		"parent root":      {FixturesRoot: "../outside", Fixtures: map[string]Fixture{"a.txt": {}}},
		"absolute root":    {FixturesRoot: "/etc", Fixtures: map[string]Fixture{"a.txt": {}}},
		"empty root":       {FixturesRoot: "", Fixtures: map[string]Fixture{"a.txt": {}}},
		"parent fixture":   {FixturesRoot: "fixtures-agent", Fixtures: map[string]Fixture{"../../a.txt": {}}},
		"absolute fixture": {FixturesRoot: "fixtures-agent", Fixtures: map[string]Fixture{"/etc/hosts": {}}},
	} {
		if err := validatePaths(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
