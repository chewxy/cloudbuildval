// cloudbuildval is a program that validates cloudbuild.yaml files
package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"

	flag "github.com/spf13/pflag"
)

var (
	projectIDFlag     = flag.String("project", "", "The project ID to use for the cloudbuild.yaml file")
	projectNumberFlag = flag.String("project-number", "", "The project number to use for the cloudbuild.yaml file")
	repoNameFlag      = flag.String("repo-name", "", "The repo name to use for the cloudbuild.yaml file")
	branchNameFlag    = flag.String("branch-name", "", "The branch name to use for the cloudbuild.yaml file")
	tagNameFlag       = flag.String("tag-name", "", "The tag name to use for the cloudbuild.yaml file")
)

type Cloudbuild struct {
	Steps []Step
}

// Step represents a step in a cloudbuild.yaml file
type Step struct {
	Name       string   `yaml:"name"`
	ID         string   `yaml:"id"`
	Entrypoint string   `yaml:"entrypoint"`
	Args       []string `yaml:"args"`
	Dir        string   `yaml:"dir"`

	cmd string // the CMD of the image, if found.
}

// Inspection is the output of `docker inspect`
type Inspection struct {
	Id      string `json:"Id"`
	Created string `json:"Created"`
	Name    string `json:"Name"`
	Config  struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"Config"`
	Architecture string `json:"Architecture"`
	Os           string `json:"Os"`
}

func readCloudbuildYAML(filename string) (*Cloudbuild, error) {
	// open file
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Unable to open configuration file %v. Error %v", filename, err)
	}
	defer f.Close()

	// read file
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("Unable to read configuration file %v. Error %v", filename, err)
	}
	// validate yaml file
	cb := new(Cloudbuild)
	err = yaml.Unmarshal(b, cb)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode YAML configuration: %v", err)
	}
	return cb, nil
}

func buildReplacements() map[string]string {
	filename := flag.Arg(0)
	dir := filepath.Dir(filename)

	m := make(map[string]string)
	if *projectIDFlag != "" {
		m["$PROJECT_ID"] = *projectIDFlag
	} else {
		if projectID := os.Getenv("PROJECT_ID"); projectID != "" {
			m["$PROJECT_ID"] = projectID
		}

	}

	if *projectNumberFlag != "" {
		m["$PROJECT_NUMBER"] = *projectNumberFlag
	}

	if *repoNameFlag != "" {
		m["$REPO_NAME"] = *repoNameFlag
	} else {
		// get from the filename

		m["$REPO_NAME"] = filepath.Base(dir)
	}

	// branch name
	if *branchNameFlag != "" {
		m["$BRANCH_NAME"] = *branchNameFlag
	} else {
		// try to get from git
		cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		m["$BRANCH_NAME"] = string(out)
	}

	// tag name
	if *tagNameFlag != "" {
		m["$TAG_NAME"] = *tagNameFlag
	}

	// try to get commit hash
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		return m
	}
	m["$COMMIT"] = string(out)
	m["$SHORT_SHA"] = string(out)[:7]
	return m
}

func main() {
	flag.Parse()
	// preliminary stuff: get project ID from environment or from flags
	replacements := buildReplacements()
	log.Printf("Replacements: %v", replacements)

	filename := flag.Arg(0)

	cb, err := readCloudbuildYAML(filename)
	if err != nil {
		log.Fatal(err)
	}

	s := NewState(replacements)
	steps := cb.Steps
	// ensure that the steps have all the relevant information
	if err := s.ensureSteps(steps); err != nil {
		log.Fatal(err)
	}

	for _, step := range steps {
		if err := s.execute(step); err != nil {
			log.Fatal(errors.Join(fmt.Errorf("Failed to run %v", step.Name), err))
		}
	}
	log.Printf("Final state:\n%v", s.root)

}
