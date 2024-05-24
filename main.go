// cloudbuildval is a program that validates cloudbuild.yaml files
package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	yaml "gopkg.in/yaml.v2"
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

func main() {

	filename := os.Args[1]
	cb, err := readCloudbuildYAML(filename)
	if err != nil {
		log.Fatal(err)
	}

	s := NewState()
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
