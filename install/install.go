package install

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/kardianos/osext"
	"github.com/markwallsgrove/ec2.cli/logging"
	"github.com/markwallsgrove/ec2.cli/profile"
)

var log = logging.Log

var bashrcCall = []byte(`
if [ -f ~/.ec2.cli/completion.bash ]; then
	export PATH="$PATH:$HOME/.ec2.cli"
    . ~/.ec2.cli/completion.bash
fi
`)

var bashAutoComplete = []byte(`#! /bin/bash
_cli_bash_autocomplete() {
     local cur opts base
     COMPREPLY=()
     cur="${COMP_WORDS[COMP_CWORD]}"
     opts=$( ${COMP_WORDS[@]:0:$COMP_CWORD} --generate-bash-completion )
     COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
     return 0
}

complete -F _cli_bash_autocomplete ec2.cli
`)

var zshAutoComplete = []byte(`
autoload -U compinit && compinit
autoload -U bashcompinit && bashcompinit

export PATH="$PATH:$HOME/.ec2.cli"
if [ -f ~/.ec2.cli/completion.bash ]; then
	source ~/.ec2.cli/completion.bash
fi
`)

// Install the required bashrc/zshrc hooks & binaries
func Install(profile *profile.Profile) error {
	aeCompletionLoc := fmt.Sprintf("%s/completion.bash", profile.BaseDir())
	aeExecLoc := fmt.Sprintf("%s/ec2.cli", profile.BaseDir())
	bashrcLoc := fmt.Sprintf("%s/.bashrc", profile.HomeDir())
	bashProfileLoc := fmt.Sprintf("%s/.bash_profile", profile.HomeDir())
	zshrcLoc := fmt.Sprintf("%s/.zshrc", profile.HomeDir())

	if err := os.Mkdir(profile.BaseDir(), 0775); os.IsExist(err) {
		return fmt.Errorf("ec2.cli is already installed, remove %s and try again", profile.BaseDir())
	} else if err != nil {
		return err
	} else {
		log.Debug(fmt.Sprintf("created %s", profile.BaseDir()))
	}

	currExecLoc, _ := osext.Executable()
	if err := cp(currExecLoc, aeExecLoc); err != nil {
		return err
	}

	if err := os.Chmod(aeExecLoc, 0775); err != nil {
		return err
	}

	if err := ioutil.WriteFile(aeCompletionLoc, bashAutoComplete, 0775); err != nil {
		return err
	}

	if _, err := os.Stat(bashProfileLoc); err == nil {
		if err := writeConfig(bashProfileLoc, bashrcCall); err != nil {
			return err
		}
	} else if err := writeConfig(bashrcLoc, bashrcCall); err != nil {
		return err
	}

	if _, err := os.Stat(zshrcLoc); err == nil {
		if err = writeConfig(zshrcLoc, zshAutoComplete); err != nil {
			return err
		}
	}

	return nil
}

func writeConfig(loc string, content []byte) error {
	if _, err := os.Stat(loc); os.IsNotExist(err) {
		ioutil.WriteFile(loc, content, 0770)
		fmt.Println(fmt.Sprintf("created %s", loc))
		return nil
	}

	config, err := os.OpenFile(loc, os.O_APPEND|os.O_WRONLY, 0770)
	if err != nil {
		return err
	}

	defer config.Close()

	if _, err = config.Write(content); err != nil {
		return err
	}

	if err = os.Chmod(loc, 0770); err != nil {
		return err
	}

	fmt.Println(fmt.Sprintf("appended to %s", loc))
	return nil
}

func cp(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}

	defer s.Close()
	d, err := os.Create(dst)

	if err != nil {
		return err
	}

	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}

	return d.Close()
}
