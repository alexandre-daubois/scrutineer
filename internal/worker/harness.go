package worker

import "github.com/alpha-omega-security/harness"

// The Harness interface, backend implementations, and registry live in
// github.com/alpha-omega-security/harness. These aliases keep the -backend
// flag validation, the container runner, and the web layer's model-list
// wiring unchanged. Adding a fourth backend (copilot) came for free.

type (
	Harness      = harness.Harness
	ModelDefault = harness.ModelDefault

	ClaudeHarness   = harness.ClaudeHarness
	CodexHarness    = harness.CodexHarness
	CopilotHarness  = harness.CopilotHarness
	OpencodeHarness = harness.OpencodeHarness
)

//nolint:ireturn // registry; the concrete type is the registrant's choice
func HarnessByName(name string) (Harness, error) { return harness.ByName(name) }
func HarnessName(h Harness) string               { return harness.Name(h) }
func HarnessNames() string                       { return harness.Names() }

// copilotTopEffort is the strongest level `copilot --effort` accepts.
const copilotTopEffort = "xhigh"

// CappedEffort lowers an effort level the backend's CLI would reject. harness
// forwards Job.Effort straight to `copilot --effort`, whose choices stop at
// xhigh, so scrutineer's "max" fails the scan on flag parsing.
func CappedEffort(h Harness, effort string) string {
	if effort == "max" && HarnessName(h) == "copilot" {
		return copilotTopEffort
	}
	return effort
}
