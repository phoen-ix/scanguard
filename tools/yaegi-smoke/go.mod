// A separate module on purpose: these dependencies are development-only and must
// never end up in the plugin's own module, which has to stay dependency-free to
// survive the Yaegi interpreter and the plugin catalog's vendoring rules.
module scanguard/tools/yaegi-smoke

go 1.22

require (
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // what Traefik v3.7.14 pins (archived repo, no tag)
	github.com/traefik/yaegi v0.16.1
)
