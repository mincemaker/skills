// Command auditcheck checks an oauth-audit report and its tests mechanically.
//
//	go run ./auditcheck -report dist/x-checklist.md -checklist ../checklist-rp.md -tests dist/security_audit.test.ts [-only RP-02,RP-05]
//
// Report: no unfilled {{...}}, every AS/RP ID of a role that appears in the
// judgment tables is present, every such row carries a judgment word, and
// GitHub links are pinned to a 40-hex commit. Tests: every case name in the
// checklist tables (restricted to -only IDs) appears in the test files.
// Exits 1 when anything is found.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	idRange   = regexp.MustCompile(`(AS|RP)-(\d\d)(?:\s*[〜~-]\s*(?:AS|RP)-(\d\d))?`)
	ghLink    = regexp.MustCompile(`https://github\.com/[^/\s)]+/[^/\s)]+/(?:blob|tree)/([^/\s)#]+)`)
	sha40     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	caseName  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	judgments = []string{"適合", "不適合", "未確認", "対象外", "未判定", "アプリ委任"}
	roleSize  = map[string]int{"AS": 11, "RP": 16}
)

// ids expands "AS-04〜AS-11" and "RP-01とRP-03" style text into IDs.
func ids(s string) []string {
	var out []string
	for _, m := range idRange.FindAllStringSubmatch(s, -1) {
		from, _ := strconv.Atoi(m[2])
		to := from
		if m[3] != "" {
			to, _ = strconv.Atoi(m[3])
		}
		for n := from; n <= to; n++ {
			out = append(out, fmt.Sprintf("%s-%02d", m[1], n))
		}
	}
	return out
}

func cells(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func checkReport(text string) []string {
	var errs []string
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		at := fmt.Sprintf("report:%d: ", i+1)
		if strings.Contains(line, "{{") {
			errs = append(errs, at+"未記入の {{...}} がある")
		}
		for _, m := range ghLink.FindAllStringSubmatch(line, -1) {
			if !sha40.MatchString(m[1]) {
				errs = append(errs, at+"コミットに固定されていないリンク: "+m[0])
			}
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		c := cells(line)
		if !strings.HasPrefix(c[0], "AS-") && !strings.HasPrefix(c[0], "RP-") {
			continue
		}
		rowIDs := ids(c[0])
		hasJudgment := false
		for _, cell := range c[1:] {
			for _, j := range judgments {
				if strings.HasPrefix(cell, j) {
					hasJudgment = true
				}
			}
		}
		if !hasJudgment {
			// rows of the RP fact table in an AS-only report have no judgment column
			continue
		}
		for _, id := range rowIDs {
			seen[id] = true
		}
	}
	for role, n := range roleSize {
		used := false
		for id := range seen {
			used = used || strings.HasPrefix(id, role)
		}
		if !used {
			continue
		}
		for k := 1; k <= n; k++ {
			if id := fmt.Sprintf("%s-%02d", role, k); !seen[id] {
				errs = append(errs, "report: 判定の表に "+id+" が無い")
			}
		}
	}
	return errs
}

// cases returns checklist case names, keyed by the IDs of the section they are in.
func cases(checklist string) map[string][]string {
	out := map[string][]string{}
	var section []string
	for _, line := range strings.Split(checklist, "\n") {
		if strings.HasPrefix(line, "## ") {
			section = ids(line)
			continue
		}
		if !strings.HasPrefix(line, "|") {
			continue
		}
		c := cells(line)
		if !caseName.MatchString(c[0]) {
			continue
		}
		key := strings.Join(section, ",")
		out[key] = append(out[key], c[0])
	}
	return out
}

func checkCoverage(checklist, tests string, only []string) []string {
	var errs []string
	want := map[string]bool{}
	for _, id := range only {
		want[id] = true
	}
	for key, names := range cases(checklist) {
		if len(only) > 0 {
			hit := false
			for _, id := range strings.Split(key, ",") {
				hit = hit || want[id]
			}
			if !hit {
				continue
			}
		}
		for _, n := range names {
			// a suffix such as cross_callback_google_to_x still counts, and so does
			// pytest's test_ prefix (test_state_valid)
			if !regexp.MustCompile(`(\b|test_)` + n + `(\b|_)`).MatchString(tests) {
				errs = append(errs, "tests: ケース "+n+" が無い")
			}
		}
	}
	return errs
}

func read(paths string) string {
	var b strings.Builder
	for _, p := range strings.Split(paths, ",") {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return b.String()
}

func main() {
	report := flag.String("report", "", "report markdown")
	checklist := flag.String("checklist", "", "checklist markdown files, comma separated")
	tests := flag.String("tests", "", "audit test files, comma separated")
	only := flag.String("only", "", "restrict coverage to these IDs, e.g. AS-01,AS-02")
	flag.Parse()

	var errs []string
	if *report != "" {
		errs = append(errs, checkReport(read(*report))...)
	}
	if *checklist != "" && *tests != "" {
		var o []string
		if *only != "" {
			o = ids(*only)
		}
		errs = append(errs, checkCoverage(read(*checklist), read(*tests), o)...)
	}
	for _, e := range errs {
		fmt.Println(e)
	}
	if len(errs) > 0 {
		os.Exit(1)
	}
	fmt.Println("ok")
}
