package marshaller

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/markwallsgrove/ec2.cli/logging"
)

var log = logging.Log

// FileMarshaller Loading and saving of objects to file
type FileMarshaller interface {
	Unmarshall(string) error
	Marshall(string) error
}

// JSONFile JSON file operations
type JSONFile struct{}

func (jf *JSONFile) mkdirAll(location string) error {
	base := filepath.Base(location)
	return os.MkdirAll(fmt.Sprintf("%s/config", base), 0700)
}

// Unmarshall a json object from a file
func (jf *JSONFile) Unmarshall(location string) error {
	bytes, err := ioutil.ReadFile(location)
	if err != nil {
		log.Error("could not load file", err)
		return err
	}

	if err = json.Unmarshal(bytes, &jf); err != nil {
		log.Error("could not unmarshal file", err)
		return err
	}

	log.Debug("loaded file successfully", fmt.Sprintf("%+v", jf))
	return nil
}

// Marshall to json object to a file
func (jf *JSONFile) Marshall(location string) error {
	err := jf.mkdirAll(location)
	if err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(jf, "", "    ")
	log.Debug("saving file to", location)

	if err != nil {
		return err
	}

	return ioutil.WriteFile(location, bytes, 0775)
}
