package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/codegangsta/cli"
	"github.com/inconshreveable/go-update"
	"github.com/kardianos/osext"
	"github.com/olekukonko/tablewriter"
	"github.com/op/go-logging"
	"github.com/toumorokoshi/go-fuzzy/fuzzy"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var releasesAPI string = "https://api.github.com/repos/markwallsgrove/ssh_alias_ec2/releases"
var version string = "0.5.3"
var baseDir string
var homeDir string
var currentUsername string

var log = logging.MustGetLogger("example")
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

var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvbKUOY+q3YFsJXCbPeT5VsVj69+K
lc/qbJVx/ZsbbPOTiMoWdQ7vENoMcqPgB7O6ouHoLo1FlOazHEnQVcFXoA==
-----END PUBLIC KEY-----
`)

var regexWhiteChars = regexp.MustCompile("[^a-zA-Z0-9]")

var forwardAssetFilePattern = regexp.MustCompile(fmt.Sprintf(
	"/f-%s-%s\\.(hash|sig|diff)$", runtime.GOOS, runtime.GOARCH,
))

var backwardsAssetFilePattern = regexp.MustCompile(fmt.Sprintf(
	"/b-%s-%s\\.(hash|sig|diff)$", runtime.GOOS, runtime.GOARCH,
))

func downloadFile(uri string, loc string, errChannel chan error) {
	log.Debug("downloading", uri, "to", loc)

	output, err := os.Create(loc)
	if err != nil {
		errChannel <- err
		return
	}

	defer output.Close()

	response, err := http.Get(uri)
	if err != nil {
		errChannel <- err
		return
	}

	defer response.Body.Close()

	_, err = io.Copy(output, response.Body)
	if err != nil {
		errChannel <- err
		return
	}

	errChannel <- errors.New("")
}

type Release struct {
	Version string  `json:"tag_name"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
}

func (release *Release) DownloadAssets(pattern regexp.Regexp, location string) error {
	if len(release.Assets) == 0 {
		return errors.New("Release contains zero assets")
	}

	downloading := 0
	errChannel := make(chan error)
	for _, asset := range release.Assets {
		if pattern.MatchString(asset.DownloadUrl) == false {
			continue
		}

		go downloadFile(asset.DownloadUrl, path.Join(location, asset.Name), errChannel)
		downloading += 1
	}

	var err error
	for i := 0; i < downloading; i++ {
		err = <-errChannel
		if err.Error() != "" {
			break
		}
	}

	close(errChannel)
	if err.Error() != "" {
		return err
	}

	return nil
}

type Asset struct {
	Name        string `json:"name"`
	DownloadUrl string `json:"browser_download_url"`
}

type Instance struct {
	Name          string
	Addr          string
	Id            string
	PublicDnsName string
	InstanceType  string
	CertName      string
	Tags          []string
}

type Profile struct {
	Name         string `json:"-"`
	Region       string `json:"region,omitempty"`
	User         string `json:"user,omitempty"`
	CertLocation string `json:"certLocation,omitempty"`
	MaxCacheAge  int    `json:"maxCacheAge,omitempty"`
	AliasPrefix  string `json:"aliasPrefix,omitempty"`
	AWSProfile   string `json:"awsProfile,omitempty"`
	AWSAccessKey string `json:"awsAccessKey,omitempty"`
	AWSSecretKey string `json:"awsSecretKey,omitempty"`
}

func loadProfileFromFile(location string) (error, Profile) {
	var profile Profile

	log.Debug("loading profile from", location)

	if _, err := os.Stat(location); err != nil {
		return err, Profile{}
	}

	profileBytes, err := ioutil.ReadFile(location)
	if err != nil {
		return err, Profile{}
	}

	if err = json.Unmarshal(profileBytes, &profile); err != nil {
		return err, Profile{}
	}

	return nil, profile
}

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

func loadProfile(context *cli.Context, useEnvValues bool) Profile {
	location := fmt.Sprintf("%s/config/%s.json", baseDir, context.GlobalString("profile"))
	err, profile := loadProfileFromFile(location)
	if err != nil {
		log.Error("Cannot load profile from", location, "due to", err)
	}

	profile.Name = trimSurroundingQuotes(context.GlobalString("profile"))

	if useEnvValues == false {
		return profile
	}

	if region := trimSurroundingQuotes(context.GlobalString("region")); region != "" {
		profile.Region = region
	} else if profile.Region == "" {
		profile.Region = "eu-west-1"
	}

	if user := trimSurroundingQuotes(context.GlobalString("user")); user != "" {
		profile.User = user
	} else if profile.User == "" {
		profile.User = currentUsername
	}

	if cert := trimSurroundingQuotes(context.GlobalString("cert")); cert != "" {
		profile.CertLocation = cert
	}

	if context.GlobalBool("flushCache") == true {
		profile.MaxCacheAge = 0
	} else if maxCacheAge := context.GlobalInt("maxCacheAge"); maxCacheAge != -1 {
		profile.MaxCacheAge = maxCacheAge
	} else if profile.MaxCacheAge == 0 {
		profile.MaxCacheAge = 300
	}

	if prefix := trimSurroundingQuotes(context.String("prefix")); prefix != "" {
		profile.AliasPrefix = prefix
	}

	if awsProfile := trimSurroundingQuotes(context.GlobalString("awsProfile")); awsProfile != "" {
		profile.AWSProfile = awsProfile
	}

	if awsAccessKey := trimSurroundingQuotes(context.GlobalString("awsAccessKey")); awsAccessKey != "" {
		profile.AWSAccessKey = awsAccessKey
	}

	if awsSecretKey := trimSurroundingQuotes(context.GlobalString("awsSecretKey")); awsSecretKey != "" {
		profile.AWSSecretKey = awsSecretKey
	}

	log.Debug("constructed profile", fmt.Sprintf("%+v\n", profile))
	return profile
}

func (profile *Profile) save() error {
	if profile.Name == "" {
		return errors.New("Profile name is not set")
	}

	if err := os.MkdirAll(fmt.Sprintf("%s/config", baseDir), 0770); err != nil {
		return err
	}

	configLoc := fmt.Sprintf("%s/config/%s.json", baseDir, profile.Name)
	configBytes, err := json.MarshalIndent(profile, "", "    ")
	log.Debug("saving profile to", configLoc)

	if err != nil {
		return err
	}

	return ioutil.WriteFile(configLoc, configBytes, 0775)
}

func (i *Instance) getNormalisedName() string {
	return fmt.Sprintf("%s_%s", regexWhiteChars.ReplaceAllString(i.Name, "_"), i.Id)
}

func exit(msg ...interface{}) {
	if len(msg) == 1 && msg[0] == nil {
		os.Exit(0)
	} else {
		log.Error(msg)
		os.Exit(1)
	}
}

func getInstanceCache(profile Profile) map[string]*Instance {
	cache := map[string]*Instance{}

	cacheLocation := fmt.Sprintf("%s/cache/%s_%s.cache", baseDir, profile.Name, profile.Region)
	log.Debug("loading cache from", cacheLocation)

	if info, err := os.Stat(cacheLocation); err != nil {
		log.Debug("could not load cache", err)
		return cache
	} else if profile.MaxCacheAge == 0 {
		log.Debug("cache expiry set to zero, removing")
		os.Remove(cacheLocation)
		return cache
	} else if int(time.Since(info.ModTime()).Seconds()) > profile.MaxCacheAge {
		log.Debug("cache has expired, removing")
		return cache
	}

	contents, err := ioutil.ReadFile(cacheLocation)
	if err != nil {
		log.Error("cannot read cache, ignoring, ", err)
		return cache
	}

	buffer := bytes.Buffer{}
	buffer.Write(contents)

	d := gob.NewDecoder(&buffer)
	err = d.Decode(&cache)

	if err != nil {
		log.Error("cannot decode cache,", err)
	}

	return cache
}

func storeInstanceCache(profile Profile, cache map[string]*Instance) error {
	if err := os.MkdirAll(fmt.Sprintf("%s/cache", baseDir), 0770); err != nil {
		log.Error("cannot create cache directory,", err)
		return err
	}

	cacheLocation := fmt.Sprintf("%s/cache/%s_%s.cache", baseDir, profile.Name, profile.Region)

	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(cache)

	if err != nil {
		log.Error("cannot encode cache,", err)
		return err
	}

	log.Debug("writing cache to", cacheLocation)
	return ioutil.WriteFile(cacheLocation, buffer.Bytes(), 0770)
}

func getInstances(profile Profile) (error, map[string]*Instance) {
	instances := getInstanceCache(profile)
	awsCredentialsLoc := fmt.Sprintf("%s/.aws/credentials", homeDir)

	if len(instances) > 0 {
		log.Debug("loaded instances from cache")
		return nil, instances
	}

	var creds *credentials.Credentials
	if profile.AWSAccessKey != "" && profile.AWSSecretKey != "" {
		log.Debug("using access/secret keys from profile")
		creds = credentials.NewStaticCredentials(
			profile.AWSAccessKey,
			profile.AWSSecretKey,
			"",
		)
	} else if profile.AWSProfile != "" {
		log.Debug("loading shared credentials from", awsCredentialsLoc)
		creds = credentials.NewSharedCredentials(
			awsCredentialsLoc,
			profile.AWSProfile,
		)
	} else {
		log.Debug("using environmental aws access/secret keys")
		creds = credentials.NewEnvCredentials()
	}

	config := aws.Config{Credentials: creds}

	if profile.Region != "" {
		log.Debug("using region", profile.Region)
		config.Region = aws.String(profile.Region)
	}

	svc := ec2.New(session.New(), &config)
	resp, err := svc.DescribeInstances(nil)

	if err != nil {
		log.Error("cannot describe instances", err)
		return err, instances
	}

	for _, res := range resp.Reservations {
		for _, inst := range res.Instances {
			instance := new(Instance)

			instance.Tags = make([]string, len(inst.Tags))
			for index, keys := range inst.Tags {
				instance.Tags[index] = *keys.Value
				if *keys.Key == "Name" {
					instance.Name = *keys.Value
					instance.Id = *inst.InstanceId
				}
			}

			instance.PublicDnsName = *inst.PublicDnsName
			instance.InstanceType = *inst.InstanceType
			instance.CertName = *inst.KeyName

			if inst.PublicIpAddress != nil {
				instance.Addr = *inst.PublicIpAddress
			} else if inst.PrivateIpAddress != nil {
				instance.Addr = *inst.PrivateIpAddress
			}

			if instance.Name != "" && instance.Addr != "" {
				instances[instance.getNormalisedName()] = instance
			} else {
				log.Debug("instance has no name or address", fmt.Sprintf("%+v\n", instance))
			}
		}
	}

	return storeInstanceCache(profile, instances), instances
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
			Usage:  "Profile to use",
			EnvVar: "AE_DEFAULT_PROFILE",
		},
		cli.StringFlag{
			Name: "awsProfile",
			Usage: "Use a certain AWS Profile when communicating with AWS. " +
				"This will be used if awsAccessKey and/or awsSecretKey are not defined",
		},
		cli.StringFlag{
			Name: "awsAccessKey",
			Usage: "AWS Access Key to use when communicating with AWS. If awsAccessKey " +
				"and awsSecretKey are defined, they override awsProfile",
		},
		cli.StringFlag{
			Name: "awsSecretKey",
			Usage: "AWS Secret Key to use when communicating with AWS. If awsAccessKey" +
				"and awsSecretKey are defined, they ovveride awsProfile",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "set",
			Usage: "Set a property or view all values of a profile (provide no key/value)",
			Action: func(context *cli.Context) {
				actionViewConfig(loadProfile(context, true))
			},
			Subcommands: []cli.Command{
				{
					Name:  "awsSecretKey",
					Usage: "Set the AWS Secret Key to use within this profile",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsProfile")
						}

						profile.AWSSecretKey = trimSurroundingQuotes(context.Args().First())
						if err := profile.save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "awsAccessKey",
					Usage: "Set the AWS Access Key to use within this profile",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsProfile")
						}

						profile.AWSAccessKey = trimSurroundingQuotes(context.Args().First())
						if err := profile.save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "awsProfile",
					Usage: "AWS profile to use",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsProfile")
						}

						profile.AWSProfile = trimSurroundingQuotes(context.Args().First())
						if err := profile.save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "envvars",
					Usage: "Special command to save the environment variables into the configuration file",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, true)

						if err := profile.save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "region",
					Usage: "Set AWS region to connect to",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected region")
						}

						profile.Region = trimSurroundingQuotes(context.Args().First())
						if err := profile.save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "user",
					Usage: "Set the SSH username to connect to the machine with",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected user")
						}

						profile.User = trimSurroundingQuotes(context.Args().First())
						if err := profile.save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "cert",
					Usage: "Location of the certificate to use when connecting to a machine",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)
						profile.CertLocation = trimSurroundingQuotes(context.Args().First())

						if _, err := os.Stat(profile.CertLocation); os.IsNotExist(err) {
							exit("cannot find certificate file", profile.CertLocation)
						} else {
							exit(profile.save())
						}
					},
				},
				{
					Name:  "maxCacheAge",
					Usage: "Maximum age in seconds to cache a AWS API call",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)

						maxCacheAge, err := strconv.Atoi(trimSurroundingQuotes(context.Args().First()))
						if err != nil {
							maxCacheAge = 300
						}

						profile.MaxCacheAge = maxCacheAge
						exit(profile.save())
					},
				},
				{
					Name:  "prefix",
					Usage: "Prefix to append to the alias name when generating aliases",
					Action: func(context *cli.Context) {
						profile := loadProfile(context, false)
						profile.AliasPrefix = trimSurroundingQuotes(context.Args().First())
						exit(profile.save())
					},
				},
			},
		},
		{
			Name:  "update",
			Usage: "Update to a later version",
			Action: func(context *cli.Context) {
				exit(actionUpdate(context.Bool("downgrade")))
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
				exit(actionAlias(loadProfile(context, true)))
			},
		},
		{
			Name:  "status",
			Usage: "display the status of all ec2 instances",
			Action: func(context *cli.Context) {
				exit(actionStatus(loadProfile(context, true)))
			},
		},
		{
			Name:  "ssh",
			Usage: "ssh to a given machine",
			Action: func(context *cli.Context) {
				profile := loadProfile(context, true)
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

				profile := loadProfile(c, true)
				tag := c.String("tag")
				exit(actionListInstances(profile, tag))
			},
		},
	}

	app.Run(os.Args)
}

func actionListInstances(profile Profile, fuzzyTag string) error {
	err, instances := getInstances(profile)
	for name := range instances {
		if fuzzyTag == "" || fuzzy.SequenceMatch(fuzzyTag, name) {
			fmt.Println(name)
		}
	}

	return err
}

func actionViewConfig(profile Profile) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Key", "Value"})

	table.Append([]string{"Name", profile.Name})
	table.Append([]string{"Region", profile.Region})
	table.Append([]string{"User", profile.User})
	table.Append([]string{"Cert", profile.CertLocation})
	table.Append([]string{"MaxCacheAge", fmt.Sprintf("%d", profile.MaxCacheAge)})
	table.Append([]string{"Alias", profile.AliasPrefix})
	table.Append([]string{"AWSProfile", profile.AWSProfile})
	table.Append([]string{"AWSAccessKey", profile.AWSSecretKey})
	table.Append([]string{"AWSSecretKey", profile.AWSAccessKey})

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
		return errors.New(fmt.Sprintf("ec2.cli is already installed, remove %s and try again", baseDir))
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

func findInstanceByHostname(profile Profile, hostName string) (error, *Instance) {
	err, instances := getInstances(profile)
	instance := &Instance{}

	if err == nil {
		log.Debug("looking for instance", hostName)
		instance, found := instances[trimSurroundingQuotes(hostName)]

		if !found {
			err = errors.New(fmt.Sprintf("unknown instance: %s", hostName))
		}

		return err, instance
	}

	return err, instance
}

func createSSHCmd(profile Profile, instance *Instance) *exec.Cmd {
	var cmd *exec.Cmd
	usernameAtHost := templateSSHUsernameAtHost(profile.User, instance.Addr)
	if profile.CertLocation != "" {
		cmd = exec.Command("ssh", "-i", profile.CertLocation, usernameAtHost)
	} else {
		cmd = exec.Command("ssh", usernameAtHost)
	}

	log.Debug("created command", cmd)
	return cmd
}

func actionSSH(profile Profile, hostName string) error {
	err, instance := findInstanceByHostname(profile, hostName)

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

func actionStatus(profile Profile) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Name", "Cert", "Type", "URL"})

	err, instances := getInstances(profile)
	for _, instance := range instances {
		table.Append([]string{
			instance.Id, instance.Name,
			instance.CertName, instance.InstanceType,
			instance.PublicDnsName,
		})
	}

	if err != nil {
		table.Render()
	}

	return err
}

func templateSSHCertLocation(profile Profile) (error, string) {
	location := ""

	if profile.CertLocation != "" {
		if _, err := os.Stat(profile.CertLocation); err != nil {
			return err, ""
		}

		location = fmt.Sprintf(" -i %s", profile.CertLocation)
	}

	return nil, location
}

func actionAlias(profile Profile) error {
	err, sshCertificateLocation := templateSSHCertLocation(profile)
	if err != nil {
		return err
	}

	err, instances := getInstances(profile)
	for _, instance := range instances {
		name := fmt.Sprintf("%s_%s", instance.Name, instance.Id)
		name = regexWhiteChars.ReplaceAllString(name, "_")

		fmt.Println(fmt.Sprintf(
			"alias %s%s=\"ssh%s %s@%s\"", profile.AliasPrefix, strings.ToLower(name),
			sshCertificateLocation, profile.User, instance.Addr,
		))
	}

	return err
}

func getReleases() ([]Release, error) {
	res, err := http.Get(releasesAPI)
	if err != nil {
		return []Release{}, err
	}

	defer res.Body.Close()

	var releases []Release
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&releases)
	return releases, err
}

func getNextRelease(releases []Release, version string, downgrade bool) (Release, bool, bool) {
	for index, release := range releases {
		if release.Version == version {
			earliestRelease := index+1 == len(releases)
			if index == 0 {
				return releases[0], true, earliestRelease
			} else if downgrade {
				return releases[index], false, earliestRelease
			} else {
				return releases[index-1], false, earliestRelease
			}
		}
	}

	return Release{}, false, false
}

func actionUpdate(downgrade bool) error {
	releases, err := getReleases()
	if err != nil {
		return err
	}

	if len(releases) < 2 {
		return errors.New("Zero new releases are available")
	}

	release, latest, earliest := getNextRelease(releases, version, downgrade)
	if release.Version == "" {
		// TODO: could this happen after many updates? Does Github use pagination?
		return errors.New("ERROR: cannot find version information. Please re-download")
	} else if latest == true && downgrade == false {
		return errors.New("Latest version already installed")
	} else if downgrade == true && earliest == true {
		return errors.New("ec2.cli is already at the earliest available release")
	}

	if downgrade {
		err = release.DownloadAssets(*backwardsAssetFilePattern, "/tmp")
	} else {
		err = release.DownloadAssets(*forwardAssetFilePattern, "/tmp")
	}

	if err != nil {
		return err
	}

	if err = applyPatch("/tmp", downgrade); err != nil {
		return err
	} else if downgrade == true {
		log.Info("successfully downgraded from", release.Version)
	} else {
		log.Info("successfully updated from", release.Version)
	}

	return nil
}

func removePatchFiles(files []string) {
	for _, file := range files {
		os.Remove(file)
	}
}

func applyPatch(filesLoc string, downgrade bool) error {
	log.Debug("patching...")

	var direction string
	if downgrade == true {
		direction = "b"
	} else {
		direction = "f"
	}

	hashLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.hash", direction, runtime.GOOS, runtime.GOARCH))
	sigLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.sig", direction, runtime.GOOS, runtime.GOARCH))
	diffLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.diff", direction, runtime.GOOS, runtime.GOARCH))

	defer removePatchFiles([]string{hashLoc, sigLoc, diffLoc})

	_, hashLocErr := os.Stat(hashLoc)
	_, sigLocErr := os.Stat(sigLoc)
	_, diffErr := os.Stat(diffLoc)

	if hashLocErr != nil || sigLocErr != nil || diffErr != nil {
		return errors.New("No all required files are available for download")
	}

	file, err := os.Open(diffLoc)
	if err != nil {
		return err
	}

	// Signature of the new executable, signed by the private cert
	signature, err := ioutil.ReadFile(sigLoc)
	if err != nil {
		return err
	}

	// SHA-256 hash of the patch file
	hash, err := ioutil.ReadFile(hashLoc)
	if err != nil {
		return err
	}

	// Remove newline from the file
	checksum, err := hex.DecodeString(strings.TrimSpace(string(hash)))
	if err != nil {
		return err
	}

	opts := update.Options{
		Patcher:   update.NewBSDiffPatcher(),
		Checksum:  checksum,
		Signature: signature,
	}

	err = opts.SetPublicKeyPEM(publicKey)
	if err != nil {
		return err
	}

	return update.Apply(file, opts)
}
