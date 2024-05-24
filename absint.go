package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/sbom"
	"github.com/xlab/treeprint"
)

type pathtree struct {
	parent   *pathtree // nil means root
	name     string
	children map[string]*pathtree
}

func (p *pathtree) String() string {
	tree := treeprint.New()
	p.addbranch(tree)
	return tree.String()
}

func (p *pathtree) addbranch(branch treeprint.Tree) {
	for _, child := range p.children {
		if len(child.children) == 0 {
			branch.AddNode(child.name)
		} else {
			subbranch := branch.AddBranch(child.name)
			child.addbranch(subbranch)
		}
	}
}

func newPathtree(name string, parent *pathtree) *pathtree {
	p := &pathtree{
		parent:   parent,
		name:     name,
		children: make(map[string]*pathtree),
	}
	if parent != nil {
		parent.children[name] = p
	}
	return p
}

type mutFn func(s *State, args ...string) error

type thunk struct {
	mutFn
	args []string
}

// State is a representation the cloudbuild container as the steps are being abstractly interpreted.
type State struct {
	root *pathtree
	cwd  *pathtree

	containers map[string]*sbom.SBOM
}

func NewState() *State {
	root := newPathtree("root", nil)
	newPathtree("workspace", root)
	return &State{
		root: root,
		cwd:  root,

		containers: make(map[string]*sbom.SBOM),
	}
}

// ensureSteps ensures that all the images are pulled to local machine. TODO: only pull metadata. We only need entrypoint, cmd, and the sbom.
func (ai *State) ensureSteps(steps []Step) error {
	for i, step := range steps {
		if ai.containers[step.Name] != nil {
			continue
		}
		cmd := exec.Command("docker", "pull", step.Name)
		err := cmd.Run()
		if err != nil {
			return errors.Join(fmt.Errorf("Unable to ensure %v", step.Name), err, cmd.Err)
		}

		// now that we have pulled the image, we can inspect it
		if err = ai.inspectImage(&steps[i]); err != nil {
			return err
		}

		// compile the SBOM
		if err = ai.compileSBOM(step); err != nil {
			return err
		}

		// check that the entrypoint is found in the SBOM

	}

	return nil
}

func (ai *State) inspectImage(step *Step) (err error) {
	cmd := exec.Command("docker", "inspect", step.Name)
	out, err := cmd.Output()
	if err != nil {
		return errors.Join(fmt.Errorf("Unable to inspect %v", step.Name), err, cmd.Err)
	}
	var inspection []Inspection
	err = json.Unmarshal(out, &inspection)
	if err != nil {
		return err
	}
	if len(inspection) != 1 {
		return fmt.Errorf("Expected 1 inspection, got %d", len(inspection))
	}
	// setting value - use the convention `steps[i]` instead of `step`
	// because sideeffects are cool bro (that was sarcasm)
	step.cmd = inspection[0].Config.Cmd[0]
	if step.Entrypoint == "" {
		step.Entrypoint = inspection[0].Config.Entrypoint[0]
	}
	if step.Entrypoint == "" {
		step.Entrypoint = step.cmd
	}
	if step.Entrypoint == "" {
		return fmt.Errorf("No entrypoint or cmd found for %v", step.Name)
	}
	return nil
}

func (ai *State) compileSBOM(step Step) (err error) {
	// now we compile SBOM
	filename := step.Name + ".json"
	cmd := exec.Command("docker", "sbom", step.Name, "--format", "syft-json", "-o", filename)
	if err = cmd.Run(); err != nil {
		return errors.Join(fmt.Errorf("Unable to fetch SBOM for %v", step.Name), err)
	}

	f, err := os.Open(filename)
	if err != nil {
		return errors.Join(fmt.Errorf("Unable to open SBOM file %v", filename), err)
	}

	bom := getBOM(f)
	ai.containers[step.Name] = bom
	return f.Close()
}

func (ai *State) checkEntrypoint(step Step) error {
	bom := ai.containers[step.Name]
	if !findEntrypoint(bom, step.Entrypoint) {
		return fmt.Errorf("Entrypoint %v not found in %v", step.Entrypoint, step.Name)
	}

	return nil
}

func (ai *State) execute(s Step) error {
	// directory related ones are executed
	if isShell(s.Entrypoint) {
		ts := parseShellArgs(s.Args)
		for _, t := range ts {
			if t.mutFn == nil {
				continue
			}
			if err := t.mutFn(ai, t.args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func isShell(entrypoint string) bool {
	switch entrypoint {
	case "/bin/bash", "/bin/sh", "sh":
		return true
	default:
		return false
	}
}

func parseShellArgs(args []string) (retVal []thunk) {
	if args[0] == "-c" {
		args = strings.Split(args[1], "\n")
	}
	for _, arg := range args {
		s := strings.Split(arg, " ")
		fn := dirCmds[s[0]]
		args := s[1:]
		retVal = append(retVal, thunk{fn, args})
	}
	return retVal
}

var dirCmds = map[string]mutFn{
	"mkdir": mkdir,
	"cd":    cd,
}

func mkdir(ai *State, args ...string) error {
	// clean args of \n first
	for i := range args {
		args[i] = strings.Trim(args[i], "\n")
	}

	var dashp bool
	for _, arg := range args {
		if arg == "-p" {
			dashp = true
		}
	}
	p := args[len(args)-1]
	l := strings.Split(p, "/")
	idx := 1
	switch l[0] {
	case "":
		ai.cwd = ai.root
	case ".":
	case "..":
		ai.cwd = ai.cwd.parent
	default:
		idx = 0
	}
	l = l[idx:]

	for i, x := range l {
		if i == len(l)-1 {

			newPathtree(x, ai.cwd)
			return nil
		}
		if err := cd(ai, x); err != nil {
			if !dashp {
				return errors.Join(fmt.Errorf("Cannot mkdir %v. Perhaps you didn't pass in -p?", p), err)
			}
			mkdir(ai, x) // no error will occur
			cd(ai, x)    // no error will occur
		}
	}
	return nil

}

func cd(ai *State, args ...string) error {
	p := args[0]
	l := filepath.SplitList(p)
	for _, x := range l {
		cwd, ok := ai.cwd.children[x]
		if !ok {
			return fmt.Errorf("path not found: %v", p)
		}
		ai.cwd = cwd
	}
	return nil
}

func gitclone(ai *State, args ...string) error {
	return nil
}

func gitfetch(ai *State, args ...string) error {
	return nil
}
