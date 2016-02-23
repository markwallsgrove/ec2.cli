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
var version string = "0.5.2"
var baseDir string
var homeDir string
var currentUsername string

func init() {
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}

	currentUsername = currentUser.Username
	homeDir = currentUser.HomeDir
	baseDir = fmt.Sprintf("%s/.ec2.cli", currentUser.HomeDir)
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
script_dir=$(dirname $0)
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

		fmt.Println("Downloading", asset.DownloadUrl, "to", path.Join(location, asset.Name))
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
	if _, err := os.Stat(location); os.IsNotExist(err) {
		return nil, Profile{}
	}

	profileBytes, err := ioutil.ReadFile(location)
	if err != nil {
		return err, Profile{}
	}

	var profile Profile
	err = json.Unmarshal(profileBytes, &profile)
	if err != nil {
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

func loadProfile(context *cli.Context, useEnvValues bool) (error, Profile) {
	location := fmt.Sprintf("%s/config/%s.json", baseDir, context.GlobalString("profile"))
	err, profile := loadProfileFromFile(location)
	if err != nil {
		return err, profile
	}

	profile.Name = trimSurroundingQuotes(context.GlobalString("profile"))

	if useEnvValues == false {
		return nil, profile
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

	if maxCacheAge := context.GlobalInt("maxCacheAge"); maxCacheAge != -1 {
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

	return nil, profile
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
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configLoc, configBytes, 0775)
}

func (i *Instance) getNormalisedName() string {
	return fmt.Sprintf("%s_%s", regexWhiteChars.ReplaceAllString(i.Name, "_"), i.Id)
}

func exit(msg string) {
	fmt.Fprint(os.Stderr, msg)
	os.Exit(1)
}

func getInstanceCache(region string, profile string, maxAge int) map[string]*Instance {
	cacheLocation := fmt.Sprintf("%s/cache/%s_%s.cache", baseDir, profile, region)
	if info, err := os.Stat(cacheLocation); err != nil {
		return nil
	} else if maxAge == 0 {
		os.Remove(cacheLocation)
		return nil
	} else if int(time.Since(info.ModTime()).Seconds()) > maxAge {
		return nil
	}

	contents, err := ioutil.ReadFile(cacheLocation)
	if err != nil {
		return nil
	}

	buffer := bytes.Buffer{}
	buffer.Write(contents)

	cache := map[string]*Instance{}
	d := gob.NewDecoder(&buffer)
	err = d.Decode(&cache)

	if err != nil {
		return nil
	}

	return cache
}

func storeInstanceCache(region string, profile string, cache map[string]*Instance) error {
	if err := os.MkdirAll(fmt.Sprintf("%s/cache", baseDir), 0770); err != nil {
		return err
	}

	cacheLocation := fmt.Sprintf("%s/cache/%s_%s.cache", baseDir, profile, region)

	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(cache)

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(cacheLocation, buffer.Bytes(), 0770)
	if err != nil {
		return err
	}

	return nil
}

func getInstances(region string, maxCacheAge int, profile Profile) (error, map[string]*Instance) {
	instances := getInstanceCache(region, profile.Name, maxCacheAge)
	if instances != nil {
		return nil, instances
	}

	var creds *credentials.Credentials
	if profile.AWSAccessKey != "" && profile.AWSSecretKey != "" {
		creds = credentials.NewStaticCredentials(
			profile.AWSAccessKey,
			profile.AWSSecretKey,
			"",
		)
	} else if profile.AWSProfile != "" {
		creds = credentials.NewSharedCredentials(
			fmt.Sprintf("%s/.aws/credentials", homeDir),
			profile.AWSProfile,
		)
	} else {
		creds = credentials.NewEnvCredentials()
	}

	config := aws.Config{Credentials: creds}

	if region != "" {
		config.Region = aws.String(region)
	}

	svc := ec2.New(session.New(), &config)
	resp, err := svc.DescribeInstances(nil)

	if err != nil {
		return err, nil
	}

	instances = make(map[string]*Instance)
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
			}
		}
	}

	if err = storeInstanceCache(region, profile.Name, instances); err != nil {
		return err, nil
	}

	return nil, instances
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
			Name:   "set",
			Usage:  "Set a property or view all values of a profile (provide no key/value)",
			Action: actionViewConfig,
			Subcommands: []cli.Command{
				{
					Name:  "awsSecretKey",
					Usage: "Set the AWS Secret Key to use within this profile",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected awsProfile.")
						}

						profile.AWSSecretKey = trimSurroundingQuotes(context.Args().First())
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "awsAccessKey",
					Usage: "Set the AWS Access Key to use within this profile",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected awsProfile.")
						}

						profile.AWSAccessKey = trimSurroundingQuotes(context.Args().First())
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "awsProfile",
					Usage: "AWS profile to use",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected awsProfile.")
						}

						profile.AWSProfile = trimSurroundingQuotes(context.Args().First())
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "envvars",
					Usage: "Special command to save the environment variables into the configuration file",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, true)
						if err != nil {
							panic(err)
						}

						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "region",
					Usage: "Set AWS region to connect to",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected region.")
						}

						profile.Region = trimSurroundingQuotes(context.Args().First())
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "user",
					Usage: "Set the SSH username to connect to the machine with",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected user.")
						}

						profile.User = trimSurroundingQuotes(context.Args().First())
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "cert",
					Usage: "Location of the certificate to use when connecting to a machine",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected certicate location.")
						}

						profile.CertLocation = trimSurroundingQuotes(context.Args().First())

						if _, err := os.Stat(profile.CertLocation); os.IsNotExist(err) {
							exit("Cannot find file")
						}

						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "maxCacheAge",
					Usage: "Maximum age in seconds to cache a AWS API call",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected maximum cache age.")
						}

						maxCacheAge, err := strconv.Atoi(trimSurroundingQuotes(context.Args().First()))
						if err != nil {
							exit("First argument must be a integer")
						}

						profile.MaxCacheAge = maxCacheAge
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
				{
					Name:  "prefix",
					Usage: "Prefix to append to the alias name when generating aliases",
					Action: func(context *cli.Context) {
						err, profile := loadProfile(context, false)
						if err != nil {
							panic(err)
						}

						if len(context.Args()) != 1 {
							exit("Invalid amount of arguments. Expected SSH alias prefix.")
						}

						profile.AliasPrefix = trimSurroundingQuotes(context.Args().First())
						if err = profile.save(); err != nil {
							panic(err)
						}
					},
				},
			},
		},
		{
			Name:   "update",
			Usage:  "Update to a later version",
			Action: actionUpdate,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "downgrade",
					Usage: "Downgrade to a earlier version",
				},
			},
		},
		{
			Name:   "setup",
			Usage:  "Setup auto complete",
			Action: actionSetup,
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

				err, profile := loadProfile(c, true)
				if err != nil {
					panic(err)
				}

				maxCacheAge := profile.MaxCacheAge
				if c.GlobalBool("flushCache") == true {
					maxCacheAge = 0
				}

				err, instances := getInstances(profile.Region, maxCacheAge, profile)
				if err != nil {
					panic(err)
				}

				fuzzyTag := c.String("tag")
				for name := range instances {
					if fuzzyTag == "" || fuzzy.SequenceMatch(fuzzyTag, name) {
						fmt.Println(name)
					}
				}
			},
		},
	}

	app.Run(os.Args)
}

func actionViewConfig(c *cli.Context) {
	err, profile := loadProfile(c, true)
	if err != nil {
		panic(err)
	}

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

func actionSetup(c *cli.Context) {
	aeCompletionLoc := fmt.Sprintf("%s/completion.bash", baseDir)
	aeExecLoc := fmt.Sprintf("%s/ec2.cli", baseDir)
	bashrcLoc := fmt.Sprintf("%s/.bashrc", homeDir)
	bashProfileLoc := fmt.Sprintf("%s/.bash_profile", homeDir)
	zshrcLoc := fmt.Sprintf("%s/.zshrc", homeDir)

	if err := os.Mkdir(baseDir, 0775); os.IsExist(err) {
		exit(fmt.Sprintf("ec2.cli is already installed, remove %s and try again", baseDir))
	} else if err != nil {
		panic(err)
	} else {
		fmt.Println(fmt.Sprintf("created %s", baseDir))
	}

	currExecLoc, _ := osext.Executable()
	if err := cp(currExecLoc, aeExecLoc); err != nil {
		panic(err)
	}

	if err := os.Chmod(aeExecLoc, 0775); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(aeCompletionLoc, bashAutoComplete, 0775); err != nil {
		panic(err)
	}

	if _, err := os.Stat(bashProfileLoc); err == nil {
		if err := writeConfig(bashProfileLoc, bashrcCall); err != nil {
			panic(err)
		}
	} else if err := writeConfig(bashrcLoc, bashrcCall); err != nil {
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

	err, profile := loadProfile(c, true)
	if err != nil {
		panic(err)
	}

	maxCacheAge := profile.MaxCacheAge
	if c.GlobalBool("flushCache") == true {
		maxCacheAge = 0
	}

	err, instances := getInstances(profile.Region, maxCacheAge, profile)

	var host string
	if instance, ok := instances[trimSurroundingQuotes(c.Args().First())]; ok {
		host = instance.Addr
	} else {
		exit(fmt.Sprintf("Unknown instance: %s\n%+v", c.Args().First(), instances))
	}

	var cmd *exec.Cmd
	if profile.CertLocation != "" {
		cmd = exec.Command(
			"ssh", "-i", profile.CertLocation,
			fmt.Sprintf("%s@%s", profile.User, host),
		)
	} else {
		cmd = exec.Command(
			"ssh", fmt.Sprintf("%s@%s", profile.User, host),
		)
	}

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
	err, profile := loadProfile(c, true)
	if err != nil {
		panic(err)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Name", "Cert", "Type", "URL"})

	maxCacheAge := profile.MaxCacheAge
	if c.GlobalBool("flushCache") == true {
		maxCacheAge = 0
	}

	err, instances := getInstances(profile.Region, maxCacheAge, profile)
	if err != nil {
		panic(err)
	}

	for _, instance := range instances {
		table.Append([]string{
			instance.Id, instance.Name,
			instance.CertName, instance.InstanceType,
			instance.PublicDnsName,
		})
	}

	table.Render()
}

func actionAlias(c *cli.Context) {
	err, profile := loadProfile(c, true)
	if err != nil {
		panic(err)
	}

	sshCertificateLocation := ""
	if profile.CertLocation != "" {
		if _, err := os.Stat(profile.CertLocation); err != nil {
			exit("Cannot find certificate")
		}

		sshCertificateLocation = fmt.Sprintf(" -i %s", profile.CertLocation)
	}

	maxCacheAge := profile.MaxCacheAge
	if c.GlobalBool("flushCache") == true {
		maxCacheAge = 0
	}

	err, instances := getInstances(profile.Region, maxCacheAge, profile)
	if err != nil {
		panic(err)
	}

	for _, instance := range instances {
		name := fmt.Sprintf("%s_%s", instance.Name, instance.Id)
		name = regexWhiteChars.ReplaceAllString(name, "_")

		fmt.Println(fmt.Sprintf(
			"alias %s%s=\"ssh%s %s@%s\"", profile.AliasPrefix, strings.ToLower(name),
			sshCertificateLocation, profile.User, instance.Addr,
		))
	}
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
	if err != nil {
		return []Release{}, err
	}

	return releases, nil
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

func actionUpdate(c *cli.Context) {
	releases, err := getReleases()
	if err != nil {
		panic(err)
	}

	if len(releases) < 2 {
		exit("Zero new releases are available")
	}

	downgrade := c.Bool("downgrade")

	release, latest, earliest := getNextRelease(releases, version, downgrade)
	if release.Version == "" {
		// TODO: could this happen after many updates? Does Github use pagination?
		exit("ERROR: cannot find version information. Please re-download")
	} else if latest == true && downgrade == false {
		exit("Latest version already installed")
	} else if downgrade == true && earliest == true {
		exit("ec2.cli is already at the earliest available release")
	}

	if downgrade {
		err = release.DownloadAssets(*backwardsAssetFilePattern, "/tmp")
	} else {
		err = release.DownloadAssets(*forwardAssetFilePattern, "/tmp")
	}

	if err != nil {
		panic(err)
	}

	err = applyPatch("/tmp", downgrade)
	if err != nil {
		panic(err)
	}

	if downgrade == true {
		fmt.Println("successfully downgraded from", release.Version)
	} else {
		fmt.Println("successfully updated from", release.Version)
	}
}

func applyPatch(filesLoc string, downgrade bool) error {
	fmt.Println("patching...")

	var direction string
	if downgrade == true {
		direction = "b"
	} else {
		direction = "f"
	}

	hashLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.hash", direction, runtime.GOOS, runtime.GOARCH))
	sigLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.sig", direction, runtime.GOOS, runtime.GOARCH))
	diffLoc := path.Join(filesLoc, fmt.Sprintf("%s-%s-%s.diff", direction, runtime.GOOS, runtime.GOARCH))

	_, hashLocErr := os.Stat(hashLoc)
	_, sigLocErr := os.Stat(sigLoc)
	_, diffErr := os.Stat(diffLoc)

	if hashLocErr != nil || sigLocErr != nil || diffErr != nil {
		return errors.New("No all required files are available for download")
	}

	file, err := os.Open(diffLoc)
	if err != nil {
		panic(err)
	}

	// Signature of the new executable, signed by the private cert
	signature, err := ioutil.ReadFile(sigLoc)
	if err != nil {
		panic(err)
	}

	// SHA-256 hash of the patch file
	hash, err := ioutil.ReadFile(hashLoc)
	if err != nil {
		panic(err)
	}

	// Remove newline from the file
	checksum, err := hex.DecodeString(strings.TrimSpace(string(hash)))
	if err != nil {
		panic(err)
	}

	opts := update.Options{
		Patcher:   update.NewBSDiffPatcher(),
		Checksum:  checksum,
		Signature: signature,
	}

	err = opts.SetPublicKeyPEM(publicKey)
	if err != nil {
		panic(err)
	}

	err = update.Apply(file, opts)
	if err != nil {
		panic(err)
	}

	return nil
}
