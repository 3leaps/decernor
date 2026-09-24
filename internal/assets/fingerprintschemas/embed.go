package fingerprintschemas

import _ "embed"

//go:embed fingerprint-record.v0.schema.json
var record []byte

//go:embed fingerprint-verify-result.v0.schema.json
var result []byte

func Record() []byte { return record }
func Result() []byte { return result }
