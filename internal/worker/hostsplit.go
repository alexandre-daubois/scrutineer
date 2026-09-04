package worker

import (
	"context"
	"slices"
)

// HostSplitRunner sends the skills named in HostSkills to Host and every other
// job to Container. It is what the host_skills config key builds: Host is the
// no-isolation LocalClaude, so a skill whose toolchain only exists on the host
// (verify, say) can run there while triage and the deep-dive skills keep their
// profile containers.
type HostSplitRunner struct {
	Container  SkillRunner
	Host       SkillRunner
	HostSkills []string
	// HostAPIBase is the skill API address handed to a job on the host: the
	// loopback form of the worker's APIBase, which in container mode names the
	// runtime's host endpoint and only resolves through the egress proxy.
	HostAPIBase string
}

func (r HostSplitRunner) runsOnHost(skillName string) bool {
	return slices.Contains(r.HostSkills, skillName)
}

//nolint:ireturn // dispatched on the skill name; both sides are SkillRunner
func (r HostSplitRunner) runnerFor(skillName string) SkillRunner {
	if r.runsOnHost(skillName) {
		return r.Host
	}
	return r.Container
}

func (r HostSplitRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	return r.runnerFor(sj.Name).RunSkill(ctx, sj, emit)
}

func (r HostSplitRunner) SkillDir(workRoot, name string) string {
	return r.runnerFor(name).SkillDir(workRoot, name)
}

// Backend is the container side's harness. The host side is LocalClaude, so
// it can only be claude.
func (r HostSplitRunner) Backend() string {
	if br, ok := r.Container.(BackendReporter); ok {
		return br.Backend()
	}
	return HarnessName(ClaudeHarness{})
}
