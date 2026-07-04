package contracts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	fulmenschema "github.com/fulmenhq/gofulmen/schema"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const contractPrefix = "contract:"
const contractManifestName = "contract.json"

type Resolver struct {
	baseDir string
}

type Validator struct {
	schema *jsonschema.Schema
}

func NewResolver(base string) (*Resolver, error) {
	baseDir, err := baseDirFromInput(base)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(baseDir)
	if err != nil {
		return nil, fmt.Errorf("contract base is not readable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("contract base is a symlink")
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("contract base is not a directory")
	}
	return &Resolver{baseDir: baseDir}, nil
}

func (r *Resolver) Resolve(id string) (string, error) {
	contractID, err := ParseID(id)
	if err != nil {
		return "", err
	}
	versionDir := filepath.Join(r.baseDir, contractID.family, contractID.version)
	if contractID.schema != "" {
		schemaFile, err := directSchemaFilename(contractID.schema)
		if err != nil {
			return "", err
		}
		path := filepath.Join(versionDir, schemaFile)
		if !isWithinBase(r.baseDir, path) {
			return "", fmt.Errorf("contract resolves outside contract base")
		}
		return path, nil
	}
	manifest, err := r.loadEntryManifest(filepath.Join(versionDir, contractManifestName))
	if err != nil {
		return "", err
	}
	if manifest.Capability != contractID.Canonical() {
		return "", fmt.Errorf("contract manifest capability mismatch")
	}
	entrySchema, err := entrySchemaFilename(manifest.EntrySchema)
	if err != nil {
		return "", err
	}
	path := filepath.Join(versionDir, entrySchema)
	if !isWithinBase(r.baseDir, path) {
		return "", fmt.Errorf("contract resolves outside contract base")
	}
	return path, nil
}

func (r *Resolver) Validator(id string) (*Validator, error) {
	path, err := r.Resolve(id)
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.LoadURL = r.loadURL
	compiled, err := compiler.Compile(fileURL(path))
	if err != nil {
		return nil, fmt.Errorf("cannot compile contract schema %q: %s", id, sanitizeCompileError(err))
	}
	return &Validator{schema: compiled}, nil
}

type ID struct {
	family  string
	version string
	schema  string
}

func (id ID) Canonical() string {
	if id.schema == "" {
		return fmt.Sprintf("contract: %s/%s", id.family, id.version)
	}
	return fmt.Sprintf("contract: %s/%s/%s", id.family, id.version, id.schema)
}

type entryManifest struct {
	Capability  string `json:"capability"`
	EntrySchema string `json:"entry_schema"`
}

func ParseID(id string) (ID, error) {
	if !strings.HasPrefix(id, contractPrefix) {
		return ID{}, fmt.Errorf("contract id must use %q prefix", contractPrefix)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(id, contractPrefix))
	if rest == "" {
		return ID{}, fmt.Errorf("contract id is empty")
	}
	if strings.ContainsAny(rest, "?#") || strings.Contains(rest, "://") {
		return ID{}, fmt.Errorf("contract id must not include a host, query, or fragment")
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 && len(parts) != 3 {
		return ID{}, fmt.Errorf("contract id must be contract: <family>/<version> or contract: <family>/<version>/<schema>")
	}
	for _, part := range parts {
		if !validSegment(part) {
			return ID{}, fmt.Errorf("contract id must be contract: <family>/<version> or contract: <family>/<version>/<schema>")
		}
	}
	contractID := ID{family: parts[0], version: parts[1]}
	if len(parts) == 3 {
		contractID.schema = parts[2]
	}
	return contractID, nil
}

func (v *Validator) ValidateJSON(data []byte) ([]fulmenschema.Diagnostic, error) {
	var payload interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	err := v.schema.Validate(payload)
	if err == nil {
		return nil, nil
	}
	validationErr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return nil, err
	}
	return diagnosticsFromValidationError(validationErr), nil
}

func (r *Resolver) loadURL(rawURL string) (io.ReadCloser, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("empty schema url")
	}
	u, err := url.Parse(stripFragment(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid schema reference")
	}
	if u.Scheme != "file" {
		return nil, fmt.Errorf("unsupported schema reference scheme %q", u.Scheme)
	}
	path := u.Path
	if runtime.GOOS == "windows" {
		path = strings.TrimPrefix(path, "/")
		path = filepath.FromSlash(path)
	}
	if !isWithinBase(r.baseDir, path) {
		return nil, fmt.Errorf("schema reference resolves outside contract base")
	}
	file, err := openBaseFile(r.baseDir, path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (r *Resolver) loadEntryManifest(path string) (entryManifest, error) {
	file, err := openBaseFile(r.baseDir, path)
	if err != nil {
		return entryManifest{}, err
	}
	defer func() {
		_ = file.Close()
	}()

	var manifest entryManifest
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return entryManifest{}, fmt.Errorf("contract manifest is invalid")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return entryManifest{}, fmt.Errorf("contract manifest is invalid")
	}
	if strings.TrimSpace(manifest.Capability) == "" || strings.TrimSpace(manifest.EntrySchema) == "" {
		return entryManifest{}, fmt.Errorf("contract manifest is invalid")
	}
	return manifest, nil
}

func openBaseFile(base string, path string) (io.ReadCloser, error) {
	info, err := lstatBasePath(base, path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("schema resource is not a regular file")
	}
	file, err := os.Open(path) // #nosec G304 -- Restricted by caller to explicit contract base.
	if err != nil {
		return nil, fmt.Errorf("schema resource is not readable")
	}
	return file, nil
}

func lstatBasePath(base string, path string) (os.FileInfo, error) {
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("schema reference resolves outside contract base")
	}

	current := base
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("schema resource is not readable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("schema resource path contains symlink")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("schema resource is not readable")
		}
		if i == len(parts)-1 {
			return info, nil
		}
	}
	return nil, fmt.Errorf("schema resource is not readable")
}

func baseDirFromInput(base string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", fmt.Errorf("contract base is required")
	}
	if strings.Contains(base, "://") {
		u, err := url.Parse(base)
		if err != nil {
			return "", fmt.Errorf("invalid contract base")
		}
		if u.Scheme != "file" {
			return "", fmt.Errorf("contract base must be a local path or file URI")
		}
		base = u.Path
		if runtime.GOOS == "windows" {
			base = strings.TrimPrefix(base, "/")
			base = filepath.FromSlash(base)
		}
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("invalid contract base")
	}
	return filepath.Clean(abs), nil
}

func validSegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func directSchemaFilename(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("contract schema name is invalid")
	}
	if strings.HasSuffix(value, ".schema.json") {
		return entrySchemaFilename(value)
	}
	if strings.HasSuffix(value, ".json") {
		return "", fmt.Errorf("contract schema name is invalid")
	}
	return entrySchemaFilename(value + ".schema.json")
}

func entrySchemaFilename(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("contract entry schema is invalid")
	}
	if filepath.IsAbs(value) || strings.ContainsAny(value, `/\?#:`) {
		return "", fmt.Errorf("contract entry schema is invalid")
	}
	if !strings.HasSuffix(value, ".schema.json") || strings.TrimSuffix(value, ".schema.json") == "" {
		return "", fmt.Errorf("contract entry schema is invalid")
	}
	if !validSegment(value) {
		return "", fmt.Errorf("contract entry schema is invalid")
	}
	return value, nil
}

func isWithinBase(base string, path string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func fileURL(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String()
}

func stripFragment(raw string) string {
	if idx := strings.IndexRune(raw, '#'); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

func diagnosticsFromValidationError(err *jsonschema.ValidationError) []fulmenschema.Diagnostic {
	if err == nil {
		return nil
	}
	var diags []fulmenschema.Diagnostic
	stack := []*jsonschema.ValidationError{err}
	for len(stack) > 0 {
		current := stack[0]
		stack = stack[1:]
		diags = append(diags, fulmenschema.Diagnostic{
			Pointer:  current.InstanceLocation,
			Keyword:  trimKeyword(current.KeywordLocation),
			Message:  current.Message,
			Severity: fulmenschema.SeverityError,
			Source:   "decernor",
		})
		stack = append(stack, current.Causes...)
	}
	return diags
}

func trimKeyword(keyword string) string {
	if idx := strings.IndexRune(keyword, '#'); idx >= 0 {
		return keyword[idx+1:]
	}
	return keyword
}

func sanitizeCompileError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unsupported schema reference scheme"):
		return "unsupported schema reference"
	case strings.Contains(msg, "schema reference resolves outside contract base"):
		return "schema reference resolves outside contract base"
	case strings.Contains(msg, "schema resource path contains symlink"):
		return "schema resource path contains symlink"
	case strings.Contains(msg, "schema resource is a symlink"):
		return "schema resource is a symlink"
	case strings.Contains(msg, "schema resource is not a regular file"):
		return "schema resource is not a regular file"
	case strings.Contains(msg, "schema resource is not readable"):
		return "schema resource is not readable"
	default:
		return "schema compilation failed"
	}
}
