package worker

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBuildClaudeArgs_NoAllowedTools(t *testing.T) {
	sj := SkillJob{Name: "metadata", Model: "claude-opus-4-7", OutputFile: "report.json"}
	args := buildClaudeArgs(sj, "", 0)

	if got := flagValue(args, "--permission-mode"); got != "bypassPermissions" {
		t.Errorf("permission-mode = %q, want bypassPermissions", got)
	}
	if slices.Contains(args, "--allowedTools") {
		t.Errorf("did not expect --allowedTools in %v", args)
	}
	if got := flagValue(args, "--max-turns"); got != "30" {
		t.Errorf("max-turns = %q, want default 30", got)
	}
	if args[len(args)-1] != buildSkillPrompt("metadata", "report.json") {
		t.Errorf("prompt is not the final arg: %v", args)
	}
}

func TestBuildClaudeArgs_AllowedTools(t *testing.T) {
	sj := SkillJob{
		Name:         "metadata",
		Model:        "claude-sonnet-4-6",
		OutputFile:   "report.json",
		AllowedTools: "Read,Write,WebFetch",
		MaxTurns:     50,
	}
	args := buildClaudeArgs(sj, "high", 0)

	if got := flagValue(args, "--permission-mode"); got != "acceptEdits" {
		t.Errorf("permission-mode = %q, want acceptEdits", got)
	}
	if got := flagValue(args, "--allowedTools"); got != "Read,Write,WebFetch" {
		t.Errorf("allowedTools = %q, want Read,Write,WebFetch", got)
	}
	if got := flagValue(args, "--model"); got != "claude-sonnet-4-6" {
		t.Errorf("model = %q", got)
	}
	if got := flagValue(args, "--effort"); got != "high" {
		t.Errorf("effort = %q, want high", got)
	}
	if got := flagValue(args, "--max-turns"); got != "50" {
		t.Errorf("max-turns = %q, want per-skill 50", got)
	}
}

func TestBuildClaudeArgs_ResumeMode(t *testing.T) {
	sj := SkillJob{
		Name:            "security-deep-dive",
		Model:           "claude-opus-4-7",
		OutputFile:      "report.json",
		ResumeSessionID: "9e4719f0-a952-4263-89fc-cbae9657a600",
		MaxTurns:        200,
	}
	args := buildClaudeArgs(sj, "", 0)

	if got := flagValue(args, "--resume"); got != "9e4719f0-a952-4263-89fc-cbae9657a600" {
		t.Errorf("--resume = %q, want session id", got)
	}
	if got := flagValue(args, "--max-turns"); got != "200" {
		t.Errorf("max-turns = %q, want 200", got)
	}
	last := args[len(args)-1]
	if last == buildSkillPrompt(sj.Name, sj.OutputFile) {
		t.Errorf("resume must not replay the activation prompt; got %q", last)
	}
	if last == "" {
		t.Errorf("resume still needs a positional prompt; got empty")
	}
}

func TestBuildClaudeArgs_ColdStartIsUnchanged(t *testing.T) {
	sj := SkillJob{Name: "metadata", Model: "claude-opus-4-7", OutputFile: "report.json"}
	args := buildClaudeArgs(sj, "", 0)
	if slices.Contains(args, "--resume") {
		t.Errorf("cold start must not include --resume: %v", args)
	}
	if args[len(args)-1] != buildSkillPrompt(sj.Name, sj.OutputFile) {
		t.Errorf("cold start prompt is not last arg: %v", args)
	}
}

func TestLinkResumeSession_SymlinksAcrossCwds(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)

	oldCwd := filepath.Join(t.TempDir(), "scan-1")
	if err := os.MkdirAll(oldCwd, 0o755); err != nil {
		t.Fatal(err)
	}
	sessionID := "abcd-1234"
	oldEncoded := strings.ReplaceAll(oldCwd, "/", "-")
	oldFile := filepath.Join(cfg, "projects", oldEncoded, sessionID+".jsonl")
	if err := os.MkdirAll(filepath.Dir(oldFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldFile, []byte("{conv}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	newCwd := filepath.Join(t.TempDir(), "scan-2")
	if err := os.MkdirAll(newCwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := linkResumeSession(sessionID, newCwd); err != nil {
		t.Fatalf("link: %v", err)
	}
	canon, err := filepath.EvalSymlinks(newCwd)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(cfg, "projects", strings.ReplaceAll(canon, "/", "-"), sessionID+".jsonl")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read linked file: %v", err)
	}
	if string(got) != "{conv}\n" {
		t.Errorf("linked file contents = %q, want original payload", got)
	}
}

func TestLinkResumeSession_MissingSourceErrors(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)
	if err := linkResumeSession("0000aaaa-bbbb-cccc-dddd-eeeeeeeeeeee", t.TempDir()); err == nil {
		t.Fatal("expected error when session jsonl absent")
	}
}

func TestLinkResumeSession_RejectsBadSessionID(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)
	for _, bad := range []string{"", "../etc/passwd", "abcd/efgh", "ZZZZ-0000"} {
		if err := linkResumeSession(bad, t.TempDir()); err == nil {
			t.Errorf("linkResumeSession(%q) must reject invalid id", bad)
		}
	}
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
