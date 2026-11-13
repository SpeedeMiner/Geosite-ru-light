package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n  %[1]s build    <17 positional arguments, see build.go>\n  %[1]s validate output.dat hydra_append_categories.txt\n", os.Args[0])
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var err error
	exactRUPositiveHosts, err = loadExactRUPositiveHosts(os.Getenv("RU_APPROVED_MANIFEST"))
	if err != nil {
		fatalf("cannot load approved exact RU hosts: %v", err)
	}

	approvedExactByAncestor = indexExactAncestors(exactRUPositiveHosts)

	switch os.Args[1] {
	case "build":
		runBuild(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	default:
		usage()
	}
}
