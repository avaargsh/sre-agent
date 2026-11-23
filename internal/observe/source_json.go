package observe

import "github.com/avaargsh/sre-agent/internal/sourcejson"

// Native-source syntax is shared with the independent SLI verifier.
// This wrapper keeps the observe call-site fail-closed without introducing
// a dependency from verification into observation internals.
func validateSourceJSON(raw []byte) error {
 return sourcejson.Validate(raw)
}
