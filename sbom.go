package main

import (
	"io"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func getBOM(f io.Reader) *sbom.SBOM {
	dec := syftjson.NewFormatDecoder()
	bom, formatID, version, err := dec.Decode(f)
	if err != nil {
		panic(err)
	}
	_ = formatID
	_ = version
	return bom
}

func findEntrypoint(b *sbom.SBOM, entrypoint string) bool {
	pkgChan := b.Artifacts.Packages.Enumerate()
	pkgs := make([]pkg.Package, 0, 128)
	for pkg := range pkgChan {
		pkgs = append(pkgs, pkg)
	}

	for _, pkg := range pkgs {
		if findEntrypointInMetadata(pkg.Metadata, entrypoint) {
			return true
		}
	}
	return false
}

func findEntrypointInMetadata(m any, entrypoint string) bool {
	switch r := m.(type) {
	case pkg.DpkgDBEntry:
		return inDpkgPath(r, entrypoint)
	}
	return false
}

func inDpkgPath(r pkg.DpkgDBEntry, want string) bool {
	for _, f := range r.Files {
		if f.Path == want {
			return true
		}
	}
	return false
}
