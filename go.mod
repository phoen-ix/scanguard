module github.com/phoen-ix/scanguard

// Traefik interprets this plugin with Yaegi v0.16.1, which exposes the Go 1.22
// standard library. Pinning the language version here makes the toolchain
// reject anything newer. Yaegi also lacks the generic stdlib APIs
// (slices.Sort, atomic.Pointer) and the min/max builtins; those compile under
// 1.22 and fail only at plugin load, so only tools/yaegi-smoke catches them.
go 1.22
