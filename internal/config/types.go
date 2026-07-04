package config

// DecernorConfig represents optional application-level defaults.
//
// Current commands are primarily flag driven; these fields preserve the
// microtool config chassis until Decernor has explicit config semantics.
type DecernorConfig struct {
	InputPath  string `yaml:"input_path" env:"INPUT_PATH"`
	OutputPath string `yaml:"output_path" env:"OUTPUT_PATH"`
	MaxDepth   int    `yaml:"max_depth" env:"MAX_DEPTH" default:"10"`
}
