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
	"cis":                       "cis_v200",
	"nist":                      "nist_800_171_rev_2",
	"pci":                       "pci_dss_v321",
	"gdpr":                      "gdpr",
	"hipaa":                     "hipaa_final_omnibus_security_rule_2013",
	"soc_2":                     "soc_2",
	"aws_foundational_security": "foundational_security",
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
			if benchmarkName == fmt.Sprintf("aws_compliance.benchmark.%s", benchmarkToBeParsed) {
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
	for _, child := range benchmark.GetChildren() {
		fmt.Printf("%s %s -> %s %d\n",
			benchmark.BlockType(), benchmark.Name(), child.Name(), len(child.GetChildren()))
		if child.Name() == "aws_compliance.control.iam_account_password_policy_min_length_14" {
			fmt.Printf("OutPrint %s \t %s -> %+v \t %+v\n",
				categoryBreadcrumb, controlBreadcrumb, benchmarkHierarchy, controlIdHierarchy)
		}
		if child.BlockType() == modconfig.BlockTypeBenchmark && len(child.GetChildren()) > 0 {
			benchmarkParent := Benchmark{
				BenchmarkId:   child.Name(),
				Description:   child.GetDescription(),
				Title:         child.GetTitle(),
				Tags:          child.GetTags(),
				Documentation: child.GetDocumentation(),
				Children:      child.(*modconfig.Benchmark).ChildNameStrings,
			}
			bLock.Lock()
			*benchmarkList = append(*benchmarkList, benchmarkParent)
			bLock.Unlock()
			iterateOverChildren(
				child.(*modconfig.Benchmark),
				append(benchmarkHierarchy, child.GetTitle()),
				benchmarkList,
				controlList,
				append(controlIdHierarchy, child.Name()),
			)
		} else {
			control := Control{
				Title:                   child.GetTitle(),
				Description:             child.GetDescription(),
				CategoryBreadcrumb:      categoryBreadcrumb,
				CategoryHierarchy:       strings.Split(categoryBreadcrumb, " > "),
				ControlId:               child.Name(),
				Tags:                    child.GetTags(),
				Documentation:           child.GetDocumentation(),
				ParentControlHierarchy:  strings.Split(controlBreadcrumb, "/"),
				ParentControlBreadcrumb: controlBreadcrumb,
				Executable: strings.HasPrefix(
					strings.Split(child.Name(), ".")[len(strings.Split(child.Name(), "."))-1],
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

	case strings.Contains(bmType, "NIST 800-171 Revision 2"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("NIST 800-171 Rev 2 - %s", strings.TrimSuffix(controlNum[0], "."))

	case strings.Contains(bmType, "PCI DSS v3.2.1"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("PCI DSS v3.2.1 - %s", controlNum[0])

	case strings.Contains(bmType, "General Data Protection Regulation (GDPR)"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("GDPR - %s", strings.Join(controlNum[:2], " "))

	case strings.Contains(bmType, "HIPAA Final Omnibus Security Rule 2013"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("HIPPA - %s", controlNum[0])

	case strings.Contains(bmType, "SOC 2"):
		controlNum := strings.Split(c.CategoryHierarchy[len(c.CategoryHierarchy)-1], " ")
		c.CategoryHierarchyShort = fmt.Sprintf("SOC 2 - %s", controlNum[0])

	case strings.Contains(bmType, "AWS Foundational Security Best Practices"):
		c.CategoryHierarchyShort = fmt.Sprintf("AWS - %s", c.CategoryHierarchy[len(c.CategoryHierarchy)-1])

	default:
		c.CategoryHierarchyShort = ""
	}

}
