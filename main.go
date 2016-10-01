package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/kardianos/osext"
	"github.com/markwallsgrove/ec2.cli/instances"
	"github.com/markwallsgrove/ec2.cli/profile"
	"github.com/markwallsgrove/ec2.cli/update"
	"github.com/olekukonko/tablewriter"
	"github.com/op/go-logging"
	"github.com/toumorokoshi/go-fuzzy/fuzzy"
)

var version = "0.5.3"
var homeDir string
var currentUsername string
var baseDir string

var log = logging.MustGetLogger("ec2.cli")
var logFormat = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)
var backend = logging.NewLogBackend(os.Stderr, "", 0)
var formatter = logging.NewBackendFormatter(backend, logFormat)

func init() {
	logging.SetBackend(formatter)

	currentUser, err := user.Current()
	if err != nil {
		log.Error("Cannot retrieve current user", err)
		os.Exit(1)
	}

	currentUsername = currentUser.Username
	homeDir = currentUser.HomeDir
	baseDir = fmt.Sprintf("%s/.ec2.cli", currentUser.HomeDir)
	log.Debug("base directory", baseDir)
	log.Debug("current user", currentUsername)
}

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

func trimSurroundingQuotes(str string) string {
	if str == "" {
		return str
	}

	lastChar := len(str) - 1
	if str[0] == '\'' && str[lastChar] == '\'' || str[0] == '"' && str[lastChar] == '"' {
		str = str[1:lastChar]
	}

	return str
}

func exit(msg ...interface{}) {
	if len(msg) == 1 && msg[0] == nil {
		os.Exit(0)
	} else {
		log.Error(msg)
		os.Exit(1)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "ec2.cli"
	app.Usage = "quickly gain access to EC2 machines"
	app.EnableBashCompletion = true
	app.Version = version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "region",
			EnvVar: "AE_AWS_DEFAULT_REGION",
			Usage:  "AWS region",
		},
		cli.StringFlag{
			Name:   "user",
			Usage:  "SSH username",
			EnvVar: "AE_SSH_USER",
		},
		cli.StringFlag{
			Name:   "cert",
			Usage:  "Certificate that will be used with ssh",
			EnvVar: "AE_SSH_CERTIFICATE",
		},
		cli.IntFlag{
			Name:   "maxCacheAge",
			Value:  -1,
			Usage:  "Maximum cache age in seconds",
			EnvVar: "AE_MAX_CACHE_AGE",
		},
		cli.BoolFlag{
			Name:  "flushCache",
			Usage: "Flush the cache",
		},
		cli.StringFlag{
			Name:   "profile",
			Value:  "default",
			Usage:  "profile.Load to use",
			EnvVar: "AE_DEFAULT_PROFILE",
		},
		cli.StringFlag{
			Name: "awsprofile.Load",
			Usage: "Use a certain AWS profile.Load when communicating with AWS. " +
				"This will be used if awsAccessKey and/or awsSecretKey are not defined",
		},
		cli.StringFlag{
			Name: "awsAccessKey",
			Usage: "AWS Access Key to use when communicating with AWS. If awsAccessKey " +
				"and awsSecretKey are defined, they override awsprofile.Load",
		},
		cli.StringFlag{
			Name: "awsSecretKey",
			Usage: "AWS Secret Key to use when communicating with AWS. If awsAccessKey" +
				"and awsSecretKey are defined, they ovveride awsprofile.Load",
		},
		cli.StringFlag{
			Name:   "baseDir",
			Value:  baseDir,
			Usage:  "Location where ec2.cli is stored",
			EnvVar: "AE_BASE_DIR",
		},
		cli.StringFlag{
			Name:   "homeDir",
			Usage:  "User's home directory",
			EnvVar: "AE_HOME_DIR",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "set",
			Usage: "Set a property or view all values of a profile (provide no key/value)",
			Action: func(context *cli.Context) {
				actionViewConfig(profile.Load(currentUsername, context, true))
			},
			Subcommands: []cli.Command{
				{
					Name:  "awsSecretKey",
					Usage: "Set the AWS Secret Key to use within this profile",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsprofile.Load")
						}

						profile.SetAWSSecretKey(context.Args().First())
						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "awsAccessKey",
					Usage: "Set the AWS Access Key to use within this profile",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsprofile.Load")
						}

						profile.SetAWSAccessKey(context.Args().First())
						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "awsprofile.Load",
					Usage: "AWS profile to use",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsprofile.Load")
						}

						profile.SetAWSProfile(context.Args().First())
						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "envvars",
					Usage: "Special command to save the environment variables into the configuration file",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, true)

						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "region",
					Usage: "Set AWS region to connect to",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected region")
						}

						profile.SetRegion(context.Args().First())
						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "user",
					Usage: "Set the SSH username to connect to the machine with",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected user")
						}

						profile.SetUser(context.Args().First())
						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "cert",
					Usage: "Location of the certificate to use when connecting to a machine",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)
						profile.SetCertLocation(context.Args().First())

						if _, err := os.Stat(profile.CertLocation()); os.IsNotExist(err) {
							exit("cannot find certificate file", profile.CertLocation)
						} else {
							exit(profile.Save())
						}
					},
				},
				{
					Name:  "maxCacheAge",
					Usage: "Maximum age in seconds to cache a AWS API call",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)
						profile.SetMaxCacheAge(context.Args().First())
						exit(profile.Save())
					},
				},
				{
					Name:  "prefix",
					Usage: "Prefix to append to the alias name when generating aliases",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)
						profile.SetAliasPrefix(context.Args().First())
						exit(profile.Save())
					},
				},
			},
		},
		{
			Name:  "update",
			Usage: "Update to a later version",
			Action: func(context *cli.Context) {
				exit(update.Patch(context.Bool("downgrade")))
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "downgrade",
					Usage: "Downgrade to a earlier version",
				},
			},
		},
		{
			Name:  "setup",
			Usage: "Setup auto complete",
			Action: func(context *cli.Context) {
				exit(actionSetup())
			},
		},
		{
			Name:  "alias",
			Usage: "generate aliases for all ec2 instances",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "prefix",
					Usage:  "Prefix for the alias name",
					EnvVar: "AE_SSH_ALIAS_PREFIX",
				},
			},
			Action: func(context *cli.Context) {
				exit(actionAlias(profile.Load(currentUsername, context, true)))
			},
		},
		{
			Name:  "status",
			Usage: "display the status of all ec2 instances",
			Action: func(context *cli.Context) {
				exit(actionStatus(profile.Load(currentUsername, context, true)))
			},
		},
		{
			Name:  "ssh",
			Usage: "ssh to a given machine",
			Action: func(context *cli.Context) {
				profile := profile.Load(currentUsername, context, true)
				if len(context.Args()) != 1 {
					exit(actionListInstances(profile, ""))
				} else {
					exit(actionSSH(profile, context.Args().First()))
				}
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "tag",
					Usage: "fuzzy find against a machine's tags",
				},
			},
			BashComplete: func(c *cli.Context) {
				if len(c.Args()) > 0 {
					return
				}

				profile := profile.Load(currentUsername, c, true)
				tag := c.String("tag")
				exit(actionListInstances(profile, tag))
			},
		},
	}

	app.Run(os.Args)
}

func actionListInstances(profile profile.Profile, fuzzyTag string) error {
	instances, err := instances.GetAll(profile)
	for name := range instances {
		if fuzzyTag == "" || fuzzy.SequenceMatch(fuzzyTag, name) {
			fmt.Println(name)
		}
	}

	return err
}

func actionViewConfig(profile profile.Profile) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Key", "Value"})

	table.Append([]string{"Name", profile.Name()})
	table.Append([]string{"Region", profile.Region()})
	table.Append([]string{"User", profile.User()})
	table.Append([]string{"Cert", profile.CertLocation()})
	table.Append([]string{"MaxCacheAge", fmt.Sprintf("%d", profile.MaxCacheAge())})
	table.Append([]string{"Alias", profile.AliasPrefix()})
	table.Append([]string{"AWSProfile", profile.AWSProfile()})
	table.Append([]string{"AWSAccessKey", profile.AWSSecretKey()})
	table.Append([]string{"AWSSecretKey", profile.AWSAccessKey()})
	table.Append([]string{"BaseDir", profile.BaseDir()})

	table.Render()
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

func actionSetup() error {
	aeCompletionLoc := fmt.Sprintf("%s/completion.bash", baseDir)
	aeExecLoc := fmt.Sprintf("%s/ec2.cli", baseDir)
	bashrcLoc := fmt.Sprintf("%s/.bashrc", homeDir)
	bashProfileLoc := fmt.Sprintf("%s/.bash_profile", homeDir)
	zshrcLoc := fmt.Sprintf("%s/.zshrc", homeDir)

	if err := os.Mkdir(baseDir, 0775); os.IsExist(err) {
		return fmt.Errorf("ec2.cli is already installed, remove %s and try again", baseDir)
	} else if err != nil {
		return err
	} else {
		log.Debug(fmt.Sprintf("created %s", baseDir))
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

func templateSSHUsernameAtHost(user string, host string) string {
	return fmt.Sprintf("%s@%s", user, host)
}

func createSSHCmd(profile profile.Profile, instance *instances.Instance) *exec.Cmd {
	var cmd *exec.Cmd
	usernameAtHost := templateSSHUsernameAtHost(profile.User(), instance.PublicDNSName)

	if certLocation := profile.CertLocation(); certLocation != "" {
		cmd = exec.Command("ssh", "-i", certLocation, usernameAtHost)
	} else {
		cmd = exec.Command("ssh", usernameAtHost)
	}

	log.Debug("created command", cmd)
	return cmd
}

func actionSSH(profile profile.Profile, hostName string) error {
	instance, err := instances.FindByHostname(profile, trimSurroundingQuotes(hostName))

	if err == nil {
		cmd := createSSHCmd(profile, instance)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout

		log.Info("connecting..")
		if err = cmd.Start(); err == nil {
			err = cmd.Wait()
		}
	}

	return err
}

func actionStatus(profile profile.Profile) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Name", "Cert", "Type", "URL"})

	instances, err := instances.GetAll(profile)
	for _, instance := range instances {
		table.Append([]string{
			instance.ID, instance.Name,
			instance.CertName, instance.InstanceType,
			instance.PublicDNSName,
		})
	}

	if err != nil {
		table.Render()
	}

	return err
}

func templateSSHCertLocation(profile profile.Profile) (string, error) {
	location := ""

	if certLocation := profile.CertLocation(); certLocation != "" {
		if _, err := os.Stat(certLocation); err != nil {
			log.Error("Cannot find certificate", certLocation)
			return "", err
		}

		location = fmt.Sprintf(" -i %s", certLocation)
	}

	return location, nil
}

func actionAlias(profile profile.Profile) error {
	sshCertificateLocation, err := templateSSHCertLocation(profile)
	if err != nil {
		return err
	}

	user := profile.User()
	prefix := profile.AliasPrefix()
	instances, err := instances.GetAll(profile)

	for _, instance := range instances {
		name := fmt.Sprintf("%s_%s", instance.Name, instance.ID)

		fmt.Println(fmt.Sprintf(
			"alias %s%s=\"ssh%s %s@%s\"", prefix, strings.ToLower(name),
			sshCertificateLocation, user, instance.PublicDNSName,
		))
	}

	return err
}
