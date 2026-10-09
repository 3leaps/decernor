package scanner

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// agentKeyForm is the outer token of a GnuPG agent key file.
type agentKeyForm string

const (
	agentKeyFormNone         agentKeyForm = ""
	agentKeyFormPlain        agentKeyForm = agentKeyTokenPlain
	agentKeyFormProtected    agentKeyForm = agentKeyTokenProtected
	agentKeyFormShadowed     agentKeyForm = agentKeyTokenShadowed
	agentKeyFormUnrecognized agentKeyForm = "unrecognized"
)

// classifyAgentKeyArtifact recognizes GnuPG agent key files by content, in
// both the extended (name: value) and legacy canonical S-expression forms. A
// file under private-keys-v1.d that looks like a key file but cannot be
// recognized fails closed.
func classifyAgentKeyArtifact(path string, data []byte, cfg Config) (Artifact, bool) {
	form := agentKeyFormFor(data)
	if form == agentKeyFormNone && isAgentKeyPath(path) {
		form = agentKeyFormUnrecognized
	}

	switch form {
	case agentKeyFormPlain:
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-AGENT-UNPROTECTED-KEY",
			Priority:       PriorityP0,
			Classification: ClassUnsafeSecret,
			Severity:       SeverityUnsafe,
			Retention:      RetentionRemove,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceHigh,
			Evidence:       "GnuPG agent key file holds an unprotected private key",
			Recommendation: "Remove the file; move the key to hardware or protect it with a passphrase.",
		})
	case agentKeyFormProtected:
		severity := SeverityWarn
		priority := PriorityP3
		if cfg.AllowProtectedSecretKeys {
			severity = SeverityInfo
			priority = PriorityP5
		}
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-AGENT-PROTECTED-KEY",
			Priority:       priority,
			Classification: ClassProtectedSecret,
			Severity:       severity,
			Retention:      RetentionRetainControlled,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceHigh,
			Evidence:       "GnuPG agent key file holds a passphrase-protected private key",
			Recommendation: "Potentially retainable in a live GnuPG home with disk protections; prefer hardware-backed keys when policy requires them.",
		})
	case agentKeyFormShadowed:
		if cfg.Profile == ProfileWorkstation {
			return mustArtifact(Finding{
				Path:           path,
				Code:           "GPG-AGENT-SHADOWED-KEY",
				Priority:       PriorityP5,
				Classification: ClassHardwareStub,
				Severity:       SeverityInfo,
				Retention:      RetentionAllowed,
				Exposure:       ExposureSensitive,
				Confidence:     ConfidenceHigh,
				Evidence:       "GnuPG agent key file is a hardware shadow stub; no private key on disk",
				Recommendation: "No action required; the private key lives on the referenced hardware token.",
			})
		}
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-AGENT-SHADOWED-KEY",
			Priority:       PriorityP3,
			Classification: ClassHardwareStub,
			Severity:       SeverityWarn,
			Retention:      RetentionRemove,
			Exposure:       ExposureSensitive,
			Confidence:     ConfidenceHigh,
			Evidence:       "GnuPG agent key file is a hardware shadow stub; no private key on disk",
			Recommendation: "Not secret, but it names a token and key; keep it out of artifact bundles. If this path is a live GnuPG home, rerun with --profile workstation.",
		})
	case agentKeyFormUnrecognized:
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-AGENT-KEY-UNRECOGNIZED",
			Priority:       PriorityP1,
			Classification: ClassParseError,
			Severity:       SeverityUnsafe,
			Retention:      RetentionInspectManually,
			Exposure:       ExposureUnknown,
			Confidence:     ConfidenceLow,
			Evidence:       "GnuPG agent key file could not be classified as plaintext, protected, or shadowed",
			Recommendation: "Inspect manually; treat as secret until shown otherwise.",
		})
	}
	return Artifact{}, false
}

func isAgentKeyPath(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".key") &&
		filepath.Base(filepath.Dir(path)) == gpgAgentPrivateDir
}

// agentKeyFormFor returns the key form of an agent key file, or
// agentKeyFormNone when data does not look like one. Content counts as an
// agent key only when an S-expression opens with an agent key token; anything
// ambiguous after that returns agentKeyFormUnrecognized.
func agentKeyFormFor(data []byte) agentKeyForm {
	form := agentKeyFormForParsed(data)
	switch form {
	case agentKeyFormProtected, agentKeyFormShadowed:
		// The parser saw one well-formed key. Any other agent key token in
		// the file (comment, other item, dropped continuation) fails closed.
		if agentKeyTokenCount(data) != 1 {
			return agentKeyFormUnrecognized
		}
	case agentKeyFormNone:
		if hasEmbeddedAgentKeyToken(data) {
			return agentKeyFormUnrecognized
		}
	}
	return form
}

func agentKeyFormForParsed(data []byte) agentKeyForm {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	if len(trimmed) == 0 {
		return agentKeyFormNone
	}
	if trimmed[0] == '(' {
		return agentKeyFormForSexp(trimmed)
	}

	keyItems, ok := extendedKeyItems(trimmed)
	if !ok {
		return agentKeyFormNone
	}
	form := agentKeyFormNone
	for _, item := range keyItems {
		next := agentKeyFormForSexp(item)
		switch {
		case next == agentKeyFormNone:
			continue
		case next == agentKeyFormPlain:
			return agentKeyFormPlain
		case form != agentKeyFormNone:
			// A key file holds one Key item.
			form = agentKeyFormUnrecognized
		default:
			form = next
		}
	}
	return form
}

// agentKeyTokenCount counts agent key tokens in raw bytes, case-insensitively.
// Each of the three tokens ends in the plaintext token, so one count covers
// all forms. A token must end at an S-expression delimiter, so prose such as
// the directory name private-keys-v1.d does not count.
func agentKeyTokenCount(data []byte) int {
	return len(agentKeyTokenEnds(bytes.ToLower(data)))
}

// agentKeyTokenEnds returns the start offset of every delimited plaintext
// token occurrence in lower.
func agentKeyTokenEnds(lower []byte) []int {
	var starts []int
	token := []byte(agentKeyTokenPlain)
	for offset := 0; ; {
		idx := bytes.Index(lower[offset:], token)
		if idx < 0 {
			return starts
		}
		start := offset + idx
		end := start + len(token)
		if end == len(lower) || isSexpDelimiter(lower[end]) {
			starts = append(starts, start)
		}
		offset = end
	}
}

func isSexpDelimiter(c byte) bool {
	return c == '(' || c == ')' || c == '"' || c == '#' || c == '|' || c == '[' || c == '{' || unicode.IsSpace(rune(c))
}

// hasEmbeddedAgentKeyToken reports whether an agent key token opens a list
// anywhere in data, in advanced or canonical form, even when the surrounding
// content is not a parseable key file.
func hasEmbeddedAgentKeyToken(data []byte) bool {
	lower := bytes.ToLower(data)
	for _, start := range agentKeyTokenEnds(lower) {
		for _, prefix := range []string{"shadowed-", "protected-"} {
			if bytes.HasSuffix(lower[:start], []byte(prefix)) {
				start -= len(prefix)
				break
			}
		}
		j := start
		if j > 0 && lower[j-1] == ':' {
			j--
			for j > 0 && lower[j-1] >= '0' && lower[j-1] <= '9' {
				j--
			}
		}
		if j > 0 && lower[j-1] == '"' {
			j--
		}
		for j > 0 && unicode.IsSpace(rune(lower[j-1])) {
			j--
		}
		if j > 0 && (lower[j-1] == '(' || lower[j-1] == ']') {
			return true
		}
	}
	return false
}

// agentKeyFormForSexp classifies one S-expression.
func agentKeyFormForSexp(expr []byte) agentKeyForm {
	outer := agentKeyForm(leadingSexpToken(expr))
	switch outer {
	case agentKeyFormPlain, agentKeyFormProtected, agentKeyFormShadowed:
	default:
		return agentKeyFormNone
	}
	heads, end, ok := sexpListHeads(expr)
	if !ok || len(heads) < 2 {
		if outer == agentKeyFormPlain {
			return agentKeyFormPlain
		}
		return agentKeyFormUnrecognized
	}
	// A key holds exactly one expression. Anything after it could hide a
	// second key behind a benign first one.
	if len(bytes.TrimSpace(expr[end:])) != 0 {
		if outer == agentKeyFormPlain {
			return agentKeyFormPlain
		}
		return agentKeyFormUnrecognized
	}

	// Fail closed on mixed forms: plaintext anywhere wins, and protected keys
	// and stubs must not carry plain secret parameters.
	secretParams, knownAlgorithm := agentKeySecretParams[heads[1]]
	nestedProtected, nestedShadowed, sawSecretParam := false, false, false
	for _, head := range heads[1:] {
		switch head {
		case agentKeyTokenPlain:
			return agentKeyFormPlain
		case agentKeyTokenProtected:
			nestedProtected = true
		case agentKeyTokenShadowed:
			nestedShadowed = true
		}
		if _, secret := secretParams[head]; secret {
			sawSecretParam = true
		}
	}
	switch outer {
	case agentKeyFormPlain:
		return agentKeyFormPlain
	case agentKeyFormProtected:
		if sawSecretParam || nestedShadowed || !knownAlgorithm {
			return agentKeyFormUnrecognized
		}
		return agentKeyFormProtected
	default:
		if sawSecretParam || nestedProtected || nestedShadowed || !knownAlgorithm {
			return agentKeyFormUnrecognized
		}
		return agentKeyFormShadowed
	}
}

// leadingSexpToken returns the first atom after the opening parenthesis,
// skipping a display hint, or "" when expr does not open a list with an atom.
func leadingSexpToken(expr []byte) string {
	expr = bytes.TrimLeftFunc(expr, unicode.IsSpace)
	if len(expr) < 2 || expr[0] != '(' {
		return ""
	}
	i := 1
	for i < len(expr) {
		switch {
		case unicode.IsSpace(rune(expr[i])):
			i++
			continue
		case expr[i] == '[':
			end := bytes.IndexByte(expr[i:], ']')
			if end < 0 {
				return ""
			}
			i += end + 1
			continue
		}
		break
	}
	if i >= len(expr) {
		return ""
	}
	atom, _, ok := readSexpAtom(expr, i)
	if !ok {
		return ""
	}
	return atom
}

// extendedKeyItems parses the extended private key format: "Name: value"
// lines with whitespace-led continuation lines. It returns the value of every
// Key item, or false when data is not in that format.
func extendedKeyItems(data []byte) ([][]byte, bool) {
	var items []*bytes.Buffer
	var current *bytes.Buffer
	sawItem, afterBlank := false, false
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			current = nil
			afterBlank = true
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !sawItem || afterBlank {
				return nil, false
			}
			if current != nil {
				// GnuPG joins continuation lines without a separator.
				current.Write(bytes.TrimLeft(line, " \t"))
			}
			continue
		}
		if line[0] == '#' {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validExtendedItemName(line[:colon]) {
			return nil, false
		}
		sawItem = true
		afterBlank = false
		current = nil
		if strings.EqualFold(string(line[:colon]), agentKeyExtendedKeyItem) {
			current = &bytes.Buffer{}
			current.Write(bytes.TrimLeft(line[colon+1:], " \t"))
			items = append(items, current)
		}
	}
	if !sawItem {
		return nil, false
	}
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		out = append(out, item.Bytes())
	}
	return out, true
}

func validExtendedItemName(name []byte) bool {
	for i, c := range name {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// sexpListHeads returns the first atom of every list in an S-expression, in
// order, and the offset just past the closing parenthesis. It accepts canonical (length-prefixed) and advanced atoms, so binary
// payloads never desynchronize the walk.
func sexpListHeads(expr []byte) ([]string, int, bool) {
	var heads []string
	depth := 0
	expectHead := false
	i := 0
	for i < len(expr) {
		switch expr[i] {
		case '(':
			depth++
			expectHead = true
			i++
			continue
		case ')':
			depth--
			if depth < 0 {
				return nil, 0, false
			}
			expectHead = false
			i++
			if depth == 0 {
				return heads, i, true
			}
			continue
		case ' ', '\t', '\r', '\n':
			i++
			continue
		case '[':
			end := bytes.IndexByte(expr[i:], ']')
			if end < 0 {
				return nil, 0, false
			}
			i += end + 1
			continue
		}
		if depth == 0 {
			return nil, 0, false
		}

		atom, next, ok := readSexpAtom(expr, i)
		if !ok {
			return nil, 0, false
		}
		if expectHead {
			heads = append(heads, atom)
			expectHead = false
		}
		i = next
	}
	return nil, 0, false
}

// readSexpAtom reads one atom at expr[i] and returns its decoded value: a
// canonical length-prefixed string, a quoted string, a #hex# or |base64|
// string, or a token.
func readSexpAtom(expr []byte, i int) (string, int, bool) {
	c := expr[i]
	if c >= '0' && c <= '9' {
		j := i
		for j < len(expr) && expr[j] >= '0' && expr[j] <= '9' {
			j++
		}
		if j < len(expr) && expr[j] == ':' {
			n, err := strconv.Atoi(string(expr[i:j]))
			// Compare against the remaining length before adding, so a huge
			// declared length cannot overflow the bounds check.
			if err != nil || n < 0 || n > len(expr)-(j+1) {
				return "", 0, false
			}
			return string(expr[j+1 : j+1+n]), j + 1 + n, true
		}
		if j < len(expr) && (expr[j] == '#' || expr[j] == '|' || expr[j] == '"') {
			return readSexpAtom(expr, j)
		}
	}
	switch c {
	case '"':
		var out strings.Builder
		j := i + 1
		for j < len(expr) && expr[j] != '"' {
			if expr[j] == '\\' && j+1 < len(expr) {
				j++
			}
			out.WriteByte(expr[j])
			j++
		}
		if j >= len(expr) {
			return "", 0, false
		}
		return out.String(), j + 1, true
	case '#', '|':
		end := bytes.IndexByte(expr[i+1:], c)
		if end < 0 {
			return "", 0, false
		}
		body := bytes.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, expr[i+1:i+1+end])
		next := i + 1 + end + 1
		var decoded []byte
		var err error
		if c == '#' {
			decoded, err = hex.DecodeString(string(body))
		} else {
			decoded, err = base64.StdEncoding.DecodeString(string(body))
		}
		if err != nil {
			// Undecodable atoms never match a token; callers fail closed on
			// unknown heads.
			return "\x00", next, true
		}
		return string(decoded), next, true
	}
	j := i
	for j < len(expr) && !bytes.ContainsRune([]byte("()[] \t\r\n\"#|"), rune(expr[j])) {
		j++
	}
	if j == i {
		return "", 0, false
	}
	return string(expr[i:j]), j, true
}
