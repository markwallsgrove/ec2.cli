package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/codegangsta/cli"
	"github.com/kardianos/osext"
	"github.com/olekukonko/tablewriter"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
)

var bashrcCall = []byte(`
if [ -f ~/.ae-completion.bash ]; then
	export PATH="$PATH:$HOME/.ae"
    . ~/.ae-completion.bash
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

complete -F _cli_bash_autocomplete ae
`)

var zshAutoComplete = []byte(`
autoload -U compinit && compinit
autoload -U bashcompinit && bashcompinit

export PATH="$PATH:$HOME/.ae"
script_dir=$(dirname $0)
if [ -f ~/.ae-completion.bash ]; then
	source ~/.ae-completion.bash
fi
`)

var regexWhiteChars = regexp.MustCompile("[^a-zA-Z0-9]")

type Instance struct {
	name          string
	addr          string
	id            string
	publicDnsName string
	instanceType  string
	certName      string
}

func (i *Instance) getNormalisedName() string {
	return fmt.Sprintf("%s_%s", regexWhiteChars.ReplaceAllString(i.name, "_"), i.id)
}

func exit(msg string) {
	fmt.Fprint(os.Stderr, msg)
	os.Exit(1)
}

func getInstances(region string) (error, map[string]*Instance) {
	config := aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}

	svc := ec2.New(session.New(), &config)
	resp, err := svc.DescribeInstances(nil)

	if err != nil {
		return err, nil
	}

	instances := make(map[string]*Instance)
	for _, res := range resp.Reservations {
		for _, inst := range res.Instances {
			instance := new(Instance)

			for _, keys := range inst.Tags {
				if *keys.Key == "Name" {
					instance.name = *keys.Value
					instance.id = *inst.InstanceId
					break
				}
			}

			instance.publicDnsName = *inst.PublicDnsName
			instance.instanceType = *inst.InstanceType
			instance.certName = *inst.KeyName

			if inst.PublicIpAddress != nil {
				instance.addr = *inst.PublicIpAddress
			} else if inst.PrivateIpAddress != nil {
				instance.addr = *inst.PrivateIpAddress
			}

			if instance.name != "" && instance.addr != "" {
				instances[instance.getNormalisedName()] = instance
			}
		}
	}

	return nil, instances
}

func main() {
	app := cli.NewApp()
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "region",
			Value:  "eu-west-1",
			EnvVar: "AWS_DEFAULT_REGION",
			Usage:  "AWS region",
		},
		cli.StringFlag{
			Name:   "user",
			Usage:  "SSH username",
			EnvVar: "SSH_USER,USER",
		},
		cli.StringFlag{
			Name:   "cert",
			Value:  "~/.ssh/id_rsa",
			Usage:  "Certificate used when ssh'ing",
			EnvVar: "SSH_CERTIFICATE",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "setup-auto-complete",
			Usage:  "Setup auto complete (requires sudo)",
			Action: actionSetup,
		},
		{
			Name:  "alias",
			Usage: "generate aliases for all ec2 instances",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "prefix",
					Usage:  "Prefix for the alias name",
					EnvVar: "SSH_ALIAS_PREFIX",
				},
			},
			Action: actionAlias,
		},
		{
			Name:   "status",
			Usage:  "display the status of all ec2 instances",
			Action: actionStatus,
		},
		{
			Name:   "ssh",
			Usage:  "ssh to a given machine",
			Action: actionSSH,
			BashComplete: func(c *cli.Context) {
				if len(c.Args()) > 0 {
					return
				}

				err, instances := getInstances(c.GlobalString("region"))
				if err != nil {
					panic(err)
				}

				for name := range instances {
					fmt.Println(name)
				}
			},
		},
	}

	app.Run(os.Args)
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

func actionSetup(c *cli.Context) {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	aeDirectory := fmt.Sprintf("%s/.ae", user.HomeDir)
	aeCompletionLoc := fmt.Sprintf("%s/ae-completion.bash", aeDirectory)
	aeExecLoc := fmt.Sprintf("%s/ae", aeDirectory)
	bashrcLoc := fmt.Sprintf("%s/.bashrc", user.HomeDir)
	zshrcLoc := fmt.Sprintf("%s/.zshrc", user.HomeDir)

	if err = os.Mkdir(aeDirectory, 0775); os.IsExist(err) {
		exit("ae is already installed, remove ~/.ae and try again")
	} else if err != nil {
		panic(err)
	} else {
		fmt.Println(fmt.Sprintf("created %s", aeDirectory))
	}

	currExecLoc, _ := osext.Executable()
	if err = cp(currExecLoc, aeExecLoc); err != nil {
		panic(err)
	}

	if err = os.Chmod(aeExecLoc, 0775); err != nil {
		panic(err)
	}

	if err = ioutil.WriteFile(aeCompletionLoc, bashAutoComplete, 0775); err != nil {
		panic(err)
	}

	if err = writeConfig(bashrcLoc, bashrcCall); err != nil {
		panic(err)
	}

	if _, err := os.Stat(zshrcLoc); err == nil {
		if err = writeConfig(zshrcLoc, zshAutoComplete); err != nil {
			panic(err)
		}
	}
}

func actionSSH(c *cli.Context) {
	if len(c.Args()) != 1 {
		exit("ssh <instance-name>")
	}

	err, instances := getInstances(c.GlobalString("region"))
	if err != nil {
		panic(err)
	}

	var host string
	if instance, ok := instances[c.Args().First()]; ok {
		host = instance.addr
	} else {
		exit(fmt.Sprintf("Unknown instance: %s\n%+v", c.Args().First(), instances))
	}

	cmd := exec.Command(
		"ssh", "-i", c.GlobalString("cert"),
		fmt.Sprintf("%s@%s", c.GlobalString("user"), host),
	)

	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	err = cmd.Wait()
	if err != nil {
		exit(err.Error())
	}
}

func actionStatus(c *cli.Context) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Name", "Cert", "Type", "URL"})

	err, instances := getInstances(c.GlobalString("region"))
	if err != nil {
		panic(err)
	}

	for _, instance := range instances {
		table.Append([]string{
			instance.id, instance.name,
			instance.certName, instance.instanceType,
			instance.publicDnsName,
		})
	}

	table.Render()
}

func actionAlias(c *cli.Context) {
	user := c.GlobalString("user")

	sshCertificateLocation := ""
	if c.GlobalString("cert") != "" {
		if _, err := os.Stat(c.GlobalString("cert")); err != nil {
			exit("Cannot find certificate")
		}

		sshCertificateLocation = fmt.Sprintf(" -i %s", c.GlobalString("cert"))
	}

	err, instances := getInstances(c.GlobalString("region"))
	if err != nil {
		panic(err)
	}

	for _, instance := range instances {
		name := fmt.Sprintf("%s_%s", instance.name, instance.id)
		name = regexWhiteChars.ReplaceAllString(name, "_")

		fmt.Println(fmt.Sprintf(
			"alias %s%s=\"ssh%s %s@%s\"", c.String("prefix"), strings.ToLower(name),
			sshCertificateLocation, user, instance.addr,
		))
	}
}
