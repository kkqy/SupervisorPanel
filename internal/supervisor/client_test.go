package supervisor

import "testing"

func TestParseStatusLineRunningWithPID(t *testing.T) {
	status, pid := parseStatusLine("sp_p1 RUNNING pid 1234, uptime 0:00:05")
	if status != "RUNNING" {
		t.Fatalf("status = %q, want RUNNING", status)
	}
	if pid != 1234 {
		t.Fatalf("pid = %d, want 1234", pid)
	}
}

func TestParseStatusLineStoppedWithoutPID(t *testing.T) {
	status, pid := parseStatusLine("sp_p1 STOPPED Jun 08 12:00 PM")
	if status != "STOPPED" {
		t.Fatalf("status = %q, want STOPPED", status)
	}
	if pid != 0 {
		t.Fatalf("pid = %d, want 0", pid)
	}
}

func TestParseStatusLineUnknownOnMalformedOutput(t *testing.T) {
	status, pid := parseStatusLine("unexpected")
	if status != "UNKNOWN" {
		t.Fatalf("status = %q, want UNKNOWN", status)
	}
	if pid != 0 {
		t.Fatalf("pid = %d, want 0", pid)
	}
}
