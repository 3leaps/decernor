package fingerprint

import (
	"strings"
	"testing"
)

const (
	testPrimaryFP = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
	testPrimaryID = "0000111122223333"
	testSubkeyFP  = "1111222233334444555566667777888899990000"
	testSubkeyID  = "7777888899990000"
	testOtherFP   = "BBBBCCCCDDDDEEEEFFFF00001111222233334444"
	testOtherID   = "1111222233334444"
)

func TestParseOpenPGPColonIdentitiesPrimaryAndSubkeyPermutations(t *testing.T) {
	variants := []string{
		colonLines(
			"pub:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"fpr:::::::::"+testPrimaryFP+":",
			"sub:e:3072:1:"+testSubkeyID+":1000::::::s:",
			"fpr:::::::::"+testSubkeyFP+":",
		),
		colonLines(
			"pub:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"uid:::::::::Synthetic Test Key::::",
			"fpr:::::::::"+testPrimaryFP+":",
			"sub:e:3072:1:"+testSubkeyID+":1000::::::s:",
			"uid:::::::::Synthetic Test Sub::::",
			"fpr:::::::::"+testSubkeyFP+":",
		),
		colonLines(
			"tru::1:1000:1:3:",
			"pub:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"fpr:::::::::"+testPrimaryFP+":",
			"uid:::::::::Synthetic Test Key::::",
			"sub:e:3072:1:"+testSubkeyID+":1000::::::s:",
			"fpr:::::::::"+testSubkeyFP+":",
		),
		colonLines(
			"sec:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"fpr:::::::::"+testPrimaryFP+":",
			"ssb:e:3072:1:"+testSubkeyID+":1000::::::s:",
			"fpr:::::::::"+testSubkeyFP+":",
		),
	}
	for i, output := range variants {
		identities, err := parseOpenPGPColonIdentities(output)
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if len(identities) != 2 {
			t.Fatalf("variant %d identities=%#v", i, identities)
		}
		if identities[0].Fingerprint != testPrimaryFP || identities[0].KeyRole != KeyRolePrimary || identities[0].KeyID != testPrimaryID {
			t.Fatalf("variant %d primary=%#v", i, identities[0])
		}
		if identities[1].Fingerprint != testSubkeyFP || identities[1].KeyRole != KeyRoleSubkey || identities[1].KeyID != testSubkeyID {
			t.Fatalf("variant %d subkey=%#v", i, identities[1])
		}
		if identities[0].KeyID != identities[0].Fingerprint[len(identities[0].Fingerprint)-16:] {
			t.Fatalf("variant %d primary key_id is not fingerprint suffix", i)
		}
	}
}

func TestParseOpenPGPColonIdentitiesRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"orphan fpr": colonLines(
			"fpr:::::::::" + testPrimaryFP + ":",
		),
		"missing fpr": colonLines(
			"pub:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"uid:::::::::Synthetic Test Key::::",
		),
		"wrong length": colonLines(
			"pub:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF00001111:",
		),
		"duplicate identity": colonLines(
			"pub:u:3072:1:"+testPrimaryID+":1000:::escaESCA:::::",
			"fpr:::::::::"+testPrimaryFP+":",
			"sub:e:3072:1:"+testPrimaryID+":1000::::::s:",
			"fpr:::::::::"+testPrimaryFP+":",
		),
		"field-5 mismatch": colonLines(
			"pub:u:3072:1:"+testOtherID+":1000:::escaESCA:::::",
			"fpr:::::::::"+testPrimaryFP+":",
		),
	}
	for name, output := range cases {
		if _, err := parseOpenPGPColonIdentities(output); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestParseOpenPGPColonIdentitiesDerivesKeyIDWhenField5Empty(t *testing.T) {
	output := colonLines(
		"pub:u:3072:1::1000:::escaESCA:::::",
		"fpr:::::::::"+testPrimaryFP+":",
	)
	identities, err := parseOpenPGPColonIdentities(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].KeyID != testPrimaryID || identities[0].KeyRole != KeyRolePrimary {
		t.Fatalf("identities=%#v", identities)
	}
}

func colonLines(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}
