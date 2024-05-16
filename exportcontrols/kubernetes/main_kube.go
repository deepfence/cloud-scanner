package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/turbot/steampipe/pkg/steampipeconfig/modconfig"
	"github.com/turbot/steampipe/pkg/workspace"
)

var BenchmarksMap = map[string]string{
	"nsa-cisa": "nsa_cisa_v1",
}

var bLock sync.Mutex
var cLock sync.Mutex

type Benchmark struct {
	BenchmarkId   string            `json:"benchmark_id"`
	Description   string            `json:"description"`
	Title         string            `json:"title"`
	Tags          map[string]string `json:"tags"`
	Documentation string            `json:"documentation"`
	Children      []string          `json:"children"`
}

type Control struct {
	CategoryBreadcrumb      string            `json:"category_breadcrumb"`
	CategoryHierarchy       []string          `json:"category_hierarchy"`
	ControlId               string            `json:"control_id"`
	Description             string            `json:"description"`
	Title                   string            `json:"title"`
	Tags                    map[string]string `json:"tags"`
	Documentation           string            `json:"documentation"`
	ParentControlHierarchy  []string          `json:"parent_control_hierarchy"`
	ParentControlBreadcrumb string            `json:"parent_control_breadcrumb"`
	Executable              bool              `json:"executable"`
}

func main() {
	argsWithoutProg := os.Args[1:]
	workspacePath := argsWithoutProg[0]
	w, errAndWarnings := workspace.Load(context.Background(), workspacePath)
	if errAndWarnings.GetError() != nil {
		fmt.Printf("\n\n\nError while loading workspace: %+v", errAndWarnings)
		return
	}

	rMaps := w.GetResourceMaps()
	fmt.Printf("Got resource maps for Kubernetes: %+v", rMaps)

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("\n\n\nError getting current working dir: %+v", err)
		return
	}

	for benchmarkName, benchmark := range rMaps.Benchmarks {
		benchmarkProcessingNeeded := false
		benchmarkFilename := benchmarkName
		for filename, benchmarkToBeParsed := range BenchmarksMap {
			if benchmarkName == fmt.Sprintf("kubernetes_compliance.benchmark.%s", benchmarkToBeParsed) {
				benchmarkProcessingNeeded = true
				benchmarkFilename = filename
			}
		}
		if !benchmarkProcessingNeeded {
			continue
		}
		var controlList []Control
		benchmarkList := []Benchmark{
			{
				BenchmarkId:   benchmarkName,
				Description:   benchmark.GetDescription(),
				Title:         benchmark.GetTitle(),
				Tags:          benchmark.GetTags(),
				Documentation: benchmark.GetDocumentation(),
				Children:      benchmark.ChildNameStrings,
			},
		}
		iterateOverChildren(benchmark, []string{benchmark.GetTitle()}, &benchmarkList, &controlList, []string{benchmarkName})
		k, _ := json.MarshalIndent(benchmarkList, "", "  ")
		s, _ := json.MarshalIndent(controlList, "", "  ")
		err := os.WriteFile(fmt.Sprintf("%s/%s_benchmarks.json", cwd, benchmarkFilename), k, 0644)
		if err != nil {
			fmt.Printf("Error writing file for benchmarks %s: %+v", benchmarkFilename, err)
		}
		err = os.WriteFile(fmt.Sprintf("%s/%s.json", cwd, benchmarkFilename), s, 0644)
		if err != nil {
			fmt.Printf("Error writing file for benchmark controls %s: %+v", benchmarkFilename, err)
		}
	}
}

func iterateOverChildren(benchmark *modconfig.Benchmark, benchmarkHierarchy []string, benchmarkList *[]Benchmark,
	controlList *[]Control, controlIdHierarchy []string) {
	categoryBreadcrumb := strings.Join(benchmarkHierarchy, " > ")
	controlBreadcrumb := strings.Join(controlIdHierarchy, "/")
	for _, benchmarkChild := range benchmark.GetChildren() {
		fmt.Printf("%s %s -> %s %d\n", benchmark.BlockType(), benchmark.Name(), benchmarkChild.Name(), len(benchmarkChild.GetChildren()))
		//if benchmarkChild.Name() == "aws_compliance.control.iam_account_password_policy_min_length_14" {
		//	fmt.Printf("OutPrint %s \t %s -> %+v \t %+v\n", categoryBreadcrumb, controlBreadcrumb, benchmarkHierarchy, controlIdHierarchy)
		//}
		if benchmarkChild.BlockType() == modconfig.BlockTypeBenchmark && len(benchmarkChild.GetChildren()) > 0 {
			benchmarkParent := Benchmark{
				BenchmarkId:   benchmarkChild.Name(),
				Description:   benchmarkChild.GetDescription(),
				Title:         benchmarkChild.GetTitle(),
				Tags:          benchmarkChild.GetTags(),
				Documentation: benchmarkChild.GetDocumentation(),
				Children:      benchmarkChild.(*modconfig.Benchmark).ChildNameStrings,
			}
			bLock.Lock()
			*benchmarkList = append(*benchmarkList, benchmarkParent)
			bLock.Unlock()
			iterateOverChildren(benchmarkChild.(*modconfig.Benchmark), append(benchmarkHierarchy,
				benchmarkChild.GetTitle()), benchmarkList, controlList, append(controlIdHierarchy, benchmarkChild.Name()))
		} else {
			control := Control{
				Title:                   benchmarkChild.GetTitle(),
				Description:             benchmarkChild.GetDescription(),
				CategoryBreadcrumb:      categoryBreadcrumb,
				CategoryHierarchy:       strings.Split(categoryBreadcrumb, " > "),
				ControlId:               benchmarkChild.Name(),
				Tags:                    benchmarkChild.GetTags(),
				Documentation:           benchmarkChild.GetDocumentation(),
				ParentControlHierarchy:  strings.Split(controlBreadcrumb, "/"),
				ParentControlBreadcrumb: controlBreadcrumb,
				Executable:              strings.HasPrefix(strings.Split(benchmarkChild.Name(), ".")[len(strings.Split(benchmarkChild.Name(), "."))-1], strings.Split(benchmark.Name(), ".")[len(strings.Split(benchmark.Name(), "."))-1]),
			}
			cLock.Lock()
			*controlList = append(*controlList, control)
			cLock.Unlock()
		}
	}
}
