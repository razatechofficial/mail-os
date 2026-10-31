// Command skipgate fails a CI gate when any test was skipped (copied from
// IAM's scripts/ci/skipgate). It reads `go test -json` on stdin, prints the
// usual test output, and exits non-zero on a failure, a skip, or a run with
// no tests at all.
//
// A skip whose message matches -defer is not a failure here: the test runs
// in a later process (tests that need a process of their own, such as
// scratch-database tests). Its name is written to -deferred-out, one per
// line, and that later run goes through skipgate without -defer, so it
// cannot skip.
//
//	go test -json ./... | go run ./scripts/ci/skipgate
//	go test -tags integration -json ./integration/ | go run ./scripts/ci/skipgate \
//	    -defer 'MAILOS_SCRATCH_' -deferred-out scratch-tests.txt
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

type event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// Result is what one run of go test reported.
type Result struct {
	Passed, Failed int
	// Skipped and Deferred map "package.Test" to the skip message.
	Skipped  map[string]string
	Deferred map[string]string
	// BuildFailed lists packages that failed without a test failing.
	BuildFailed []string
}

// Scan reads go test -json, copies test output to out and classifies skips.
func Scan(in io.Reader, out io.Writer, deferRe *regexp.Regexp) (*Result, error) {
	res := &Result{Skipped: map[string]string{}, Deferred: map[string]string{}}
	output := map[string]*strings.Builder{}
	failedTests := map[string]bool{}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		var ev event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			// Not JSON (a build error printed by go itself): pass it through.
			fmt.Fprintln(out, sc.Text())
			continue
		}
		key := ev.Package + "." + ev.Test
		switch ev.Action {
		case "output":
			fmt.Fprint(out, ev.Output)
			if ev.Test != "" {
				b := output[key]
				if b == nil {
					b = &strings.Builder{}
					output[key] = b
				}
				b.WriteString(ev.Output)
			}
		case "pass":
			if ev.Test != "" {
				res.Passed++
			}
		case "fail":
			if ev.Test != "" {
				res.Failed++
				failedTests[ev.Package] = true
			} else if !failedTests[ev.Package] {
				res.BuildFailed = append(res.BuildFailed, ev.Package)
			}
		case "skip":
			if ev.Test == "" {
				continue // a package with no test files
			}
			msg := ""
			if b := output[key]; b != nil {
				msg = strings.TrimSpace(b.String())
			}
			if deferRe != nil && deferRe.MatchString(msg) {
				res.Deferred[key] = msg
			} else {
				res.Skipped[key] = msg
			}
		}
	}
	return res, sc.Err()
}

func main() {
	deferPat := flag.String("defer", "", "regexp: skips whose message matches run in a later process")
	deferredOut := flag.String("deferred-out", "", "file to write deferred test names to")
	allowEmpty := flag.Bool("allow-empty", false, "pass when no test ran")
	flag.Parse()
	var deferRe *regexp.Regexp
	if *deferPat != "" {
		deferRe = regexp.MustCompile(*deferPat)
	}
	res, err := Scan(os.Stdin, os.Stdout, deferRe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "skipgate: read:", err)
		os.Exit(2)
	}
	if *deferredOut != "" {
		names := make([]string, 0, len(res.Deferred))
		for k := range res.Deferred {
			names = append(names, k[strings.LastIndex(k, ".")+1:])
		}
		sort.Strings(names)
		if err := os.WriteFile(*deferredOut, []byte(strings.Join(names, "\n")), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "skipgate: write deferred:", err)
			os.Exit(2)
		}
	}
	fmt.Printf("\nskipgate: %d passed, %d failed, %d skipped, %d deferred\n", res.Passed, res.Failed, len(res.Skipped), len(res.Deferred))
	bad := false
	if len(res.Skipped) > 0 {
		bad = true
		keys := make([]string, 0, len(res.Skipped))
		for k := range res.Skipped {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println("skipgate: skipped tests fail the gate:")
		for _, k := range keys {
			fmt.Printf("  %s: %s\n", k, strings.ReplaceAll(res.Skipped[k], "\n", " "))
		}
	}
	if res.Failed > 0 || len(res.BuildFailed) > 0 {
		bad = true
		for _, p := range res.BuildFailed {
			fmt.Printf("skipgate: package failed without a test failure (build or TestMain): %s\n", p)
		}
	}
	if res.Passed == 0 && !*allowEmpty {
		bad = true
		fmt.Println("skipgate: no test ran")
	}
	if bad {
		os.Exit(1)
	}
}
