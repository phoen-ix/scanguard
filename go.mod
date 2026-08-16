module github.com/phoen-ix/scanguard

// Traefik interprets this plugin with Yaegi v0.16.1, which exposes the Go 1.22
// standard library. Pinning the language version here makes the local toolchain
// reject Go 1.23+ APIs (slices.Sort*, sync.OnceFunc, atomic.Pointer, min/max)
// that would compile fine locally and then fail inside Traefik.
go 1.22
