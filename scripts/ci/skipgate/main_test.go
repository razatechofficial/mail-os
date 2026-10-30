package main

import (
	"io"
	"regexp"
	"strings"
	"testing"
)

const run = `{"Action":"run","Package":"p","Test":"TestA"}
{"Action":"output","Package":"p","Test":"TestA","Output":"=== RUN   TestA\n"}
{"Action":"pass","Package":"p","Test":"TestA"}
{"Action":"run","Package":"p","Test":"TestB"}
{"Action":"output","Package":"p","Test":"TestB","Output":"    b_test.go:9: no fixture binary\n"}
{"Action":"skip","Package":"p","Test":"TestB"}
{"Action":"run","Package":"p","Test":"TestC"}
{"Action":"output","Package":"p","Test":"TestC","Output":"    c_test.go:3: MAILOS_SCRATCH_PG_HOST/PORT/DB not set\n"}
{"Action":"skip","Package":"p","Test":"TestC"}
{"Action":"skip","Package":"empty"}
{"Action":"pass","Package":"p"}
`

func TestScanCountsSkipsAndDefers(t *testing.T) {
	res, err := Scan(strings.NewReader(run), io.Discard, regexp.MustCompile(`MAILOS_SCRATCH_`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed != 1 || res.Failed != 0 {
		t.Fatalf("passed %d failed %d", res.Passed, res.Failed)
	}
	if _, ok := res.Skipped["p.TestB"]; !ok || len(res.Skipped) != 1 {
		t.Fatalf("skipped = %v, want only TestB", res.Skipped)
	}
	if _, ok := res.Deferred["p.TestC"]; !ok || len(res.Deferred) != 1 {
		t.Fatalf("deferred = %v, want only TestC", res.Deferred)
	}
}

func TestScanWithoutDeferTreatsEverySkipAsSkipped(t *testing.T) {
	res, _ := Scan(strings.NewReader(run), io.Discard, nil)
	if len(res.Skipped) != 2 || len(res.Deferred) != 0 {
		t.Fatalf("skipped %v deferred %v", res.Skipped, res.Deferred)
	}
}

func TestScanReportsPackageFailureWithoutTestFailure(t *testing.T) {
	in := `{"Action":"output","Package":"q","Output":"FATAL: setup\n"}
{"Action":"fail","Package":"q"}
{"Action":"fail","Package":"r","Test":"TestX"}
{"Action":"fail","Package":"r"}
`
	res, _ := Scan(strings.NewReader(in), io.Discard, nil)
	if len(res.BuildFailed) != 1 || res.BuildFailed[0] != "q" || res.Failed != 1 {
		t.Fatalf("build failed %v, failed %d", res.BuildFailed, res.Failed)
	}
}
