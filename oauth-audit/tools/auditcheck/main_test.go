package main

import (
	"os"
	"strings"
	"testing"
)

func TestAuditcheck(t *testing.T) {
	if got := strings.Join(ids("RP-07〜RP-10とRP-01"), ","); got != "RP-07,RP-08,RP-09,RP-10,RP-01" {
		t.Fatalf("ids: %s", got)
	}

	var rows strings.Builder
	rows.WriteString("| ID | 確認項目 | 判定 |\n|---|---|---|\n")
	for _, r := range []string{"AS-01 | a | 不適合。localhost", "AS-02 | b | 対象外", "AS-03 | c | 適合", "AS-04〜AS-10 | d | 未確認"} {
		rows.WriteString("| " + r + " |\n")
	}
	report := rows.String() + "| RP-01 | 確認する場所 | callback |\n" +
		"[a](https://github.com/o/r/blob/main/x.go#L1) [b](https://github.com/o/r/blob/9cb24a0484e87ff676d63a399beae233806a3709/x.go#L2)\n{{IdP名}}\n"
	errs := strings.Join(checkReport(report), "\n")
	for _, want := range []string{"AS-11 が無い", "blob/main", "未記入"} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing %q in:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "RP-") || strings.Contains(errs, "9cb24a0") {
		t.Errorf("false positive:\n%s", errs)
	}

	checklist, err := os.ReadFile("../../checklist-as.md")
	if err != nil {
		t.Fatal(err)
	}
	errs = strings.Join(checkCoverage(string(checklist), "it('exact') it('loopback_port') def test_ipv6_loopback_port(): it('localhost_port')", ids("AS-03")), "\n")
	if errs != "tests: ケース loopback_path が無い" {
		t.Fatalf("coverage: %s", errs)
	}
}
