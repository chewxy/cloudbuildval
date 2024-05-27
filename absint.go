package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

	replacements map[string]string
}

func NewState(replacements map[string]string) *State {
	root := newPathtree("root", nil)
	newPathtree("workspace", root)
	return &State{
		root: root,
		cwd:  root,

		containers:   make(map[string]*sbom.SBOM),
		replacements: replacements,
	}
}

// ensureSteps ensures that all the images are pulled to local machine. TODO: only pull metadata. We only need entrypoint, cmd, and the sbom.
func (ai *State) ensureSteps(steps []Step) error {

	for i := range steps {
		step := &steps[i]
		// string replacements need to happen first
		ai.stringReplacement(&steps[i])

		if ai.containers[step.Name] != nil {
			continue
		}
		log.Printf("Pulling %v", step.Name)
		cmd := exec.Command("docker", "pull", step.Name)
		err := cmd.Run()
		if err != nil {
			return errors.Join(fmt.Errorf("Unable to ensure %v", step.Name), err, cmd.Err)
		}

		log.Printf("Inspecting %v", step.Name)
		// now that we have pulled the image, we can inspect it
		if err = ai.inspectImage(&steps[i]); err != nil {
			return err
		}

		log.Printf("Compiling SBOM for %v", step.Name)

		// compile the SBOM
		if err = ai.compileSBOM(step); err != nil {
			return err
		}

	}
	// check paths
	for _, step := range steps {
		if step.Dir != "" {
			ai.setDir(step)
		}
	}
	for _, step := range steps {
		ai.checkEntrypoint(step)
	}

	return nil
}

func (ai *State) stringReplacement(step *Step) {
	log.Printf("Replacing %v with %v", step.Name, ai.replaceStr(step.Name))
	step.Name = ai.replaceStr(step.Name)

	step.Entrypoint = ai.replaceStr(step.Entrypoint)
	for i, arg := range step.Args {
		step.Args[i] = ai.replaceStr(arg)
	}
	step.Dir = ai.replaceStr(step.Dir)
}

func (ai *State) replaceStr(s string) string {
	for k, v := range ai.replacements {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
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
	if len(step.cmd) > 0 {
		step.cmd = inspection[0].Config.Cmd[0]
	}
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

func (ai *State) compileSBOM(step *Step) (err error) {
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

// workspaceDir is a method that takes a raw directory string and spits out a list of directories to traverse through.
//
// PLENTY OF SIDE EFFECTS
func (ai *State) workspaceDir(raw string, setWorkspace bool) []string {
	dir := strings.Split(raw, "/")
	idx := 1
	switch dir[0] {
	case "":
		ai.cwd = ai.root
	case ".":
	case "..":
		ai.cwd = ai.cwd.parent
	default:
		if setWorkspace {
			ai.cwd = ai.root.children["workspace"]
		}
		idx = 0
	}
	dir = dir[idx:]
	return dir
}

func (ai *State) setDir(s Step) {
	if s.Dir == "" {
		return // cwd it is!
	}
	dir := ai.workspaceDir(s.Dir, true)
	for _, d := range dir {
		mkdir(ai, d)
		cd(ai, d)
	}
}

func (ai *State) execute(s Step) error {
	// directory related ones are executed
	ai.setDir(s)
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
	l := ai.workspaceDir(p, false)

	for i, x := range l {
		if i == len(l)-1 {
			if _, ok := ai.cwd.children[x]; ok {
				return nil
			}
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
