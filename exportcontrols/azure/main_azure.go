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
	"cis":   "cis_v200",
	"hipaa": "hipaa_hitrust_v92",
	"nist":  "nist_sp_800_53_rev_5",
	"pci":   "pci_dss_v321",
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
	CategoryHierarchyShort  string            `json:"category_hierarchy_short"`
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

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("\n\n\nError getting current working dir: %+v", err)
		return
	}

	for benchmarkName, benchmark := range rMaps.Benchmarks {
		benchmarkProcessingNeeded := false
		benchmarkFilename := benchmarkName
		for filename, benchmarkToBeParsed := range BenchmarksMap {
			if benchmarkName == fmt.Sprintf("azure_compliance.benchmark.%s", benchmarkToBeParsed) {
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
		iterateOverChildren(
			benchmark,
			[]string{benchmark.GetTitle()},
			&benchmarkList,
			&controlList,
			[]string{benchmarkName},
		)
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

func iterateOverChildren(
	benchmark *modconfig.Benchmark,
	benchmarkHierarchy []string,
	benchmarkList *[]Benchmark,
	controlList *[]Control,
	controlIdHierarchy []string,
) {
	categoryBreadcrumb := strings.Join(benchmarkHierarchy, " > ")
	controlBreadcrumb := strings.Join(controlIdHierarchy, "/")
	for _, benchmarkChild := range benchmark.GetChildren() {
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

			iterateOverChildren(
				benchmarkChild.(*modconfig.Benchmark),
				append(benchmarkHierarchy, benchmarkChild.GetTitle()),
				benchmarkList,
				controlList,
				append(controlIdHierarchy, benchmarkChild.Name()),
			)

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
				Executable: strings.HasPrefix(
					strings.Split(benchmarkChild.Name(), ".")[len(strings.Split(benchmarkChild.Name(), "."))-1],
					strings.Split(benchmark.Name(), ".")[len(strings.Split(benchmark.Name(), "."))-1]),
			}
			control.SetCategoryHierarchyShort()

			cLock.Lock()
			*controlList = append(*controlList, control)
			cLock.Unlock()
		}
	}
}

func (c *Control) SetCategoryHierarchyShort() {
	bmType := c.CategoryHierarchy[0]

	switch {
	case strings.Contains(bmType, "CIS v2.0.0"):
		c.CategoryHierarchyShort = fmt.Sprintf("CIS v2.0.0 - %s", c.Tags["cis_item_id"])

	case strings.Contains(bmType, "NIST SP 800-53 Revision 5"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("NIST SP 800-53 Rev 5 - %s", controlNum[len(controlNum)-1])

	case strings.Contains(bmType, "PCI DSS 3.2.1"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("PCI DSS v3.2.1 - %s", controlNum[len(controlNum)-1])

	case strings.Contains(bmType, "HIPAA HITRUST 9.2"):
		c.CategoryHierarchyShort = fmt.Sprintf("HIPPA 9.2 - %s", c.CategoryHierarchy[1])

	default:
		c.CategoryHierarchyShort = ""
	}

}
