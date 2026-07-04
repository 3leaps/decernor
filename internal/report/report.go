package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/3leaps/decernor/internal/scanner"
)

func WriteJSON(w io.Writer, result scanner.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func WriteText(w io.Writer, result scanner.Result) error {
	findings := append([]scanner.Finding(nil), result.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Rank != findings[j].Rank {
			return findings[i].Rank > findings[j].Rank
		}
		return findings[i].Path < findings[j].Path
	})

	if _, err := fmt.Fprintf(w, "scanned=%d skipped=%d warns=%d unsafes=%d root=%s\n", result.Scanned, result.Skipped, result.Warns, result.Unsafes, result.Root); err != nil {
		return err
	}
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "OK no policy findings")
		return err
	}

	for _, finding := range findings {
		if _, err := fmt.Fprintf(w, "%s %s %s %s %s\n", finding.Priority, finding.Code, finding.Severity, finding.Classification, finding.Path); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  retention: %s exposure: %s sensitivity: %s confidence: %s\n", finding.Retention, finding.Exposure, finding.Sensitivity, finding.Confidence); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  evidence: %s\n", finding.Evidence); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  action: %s\n", finding.Recommendation); err != nil {
			return err
		}
	}
	return nil
}
