package templates

import (
	"embed"
	"io/fs"
	"strings"
)

// builtinFS embeds the DarkObscura built-in templates AND the curated set of
// official projectdiscovery/nuclei-templates checks under builtin/nuclei/.
//
//go:embed all:builtin
var builtinFS embed.FS

// Builtin returns the templates compiled into the binary (recursively, including
// the bundled official Nuclei set). Templates that fail to parse or use
// unsupported features are skipped.
func Builtin() ([]Template, error) {
	var out []Template
	err := fs.WalkDir(builtinFS, "builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, rerr := builtinFS.ReadFile(path)
		if rerr != nil {
			return nil
		}
		t, perr := Parse(data)
		if perr != nil || !t.Compatible() {
			return nil
		}
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
