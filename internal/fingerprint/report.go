package fingerprint

import (
	"encoding/json"
	"io"
)

func WriteNDJSON(w io.Writer, records []Record) error {
	enc := json.NewEncoder(w)
	for _, record := range records {
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func WriteJSON(w io.Writer, records []Record) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(records)
}
