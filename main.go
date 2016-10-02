package main

import (
	"fmt"
	"os"
	"os/user"

	"github.com/codegangsta/cli"
	"github.com/markwallsgrove/ec2.cli/actions"
	"github.com/markwallsgrove/ec2.cli/install"
	"github.com/markwallsgrove/ec2.cli/logging"
	"github.com/markwallsgrove/ec2.cli/profile"
	"github.com/markwallsgrove/ec2.cli/update"
)

var version = "0.5.3"
var homeDir string
var currentUsername string
var baseDir string

var log = logging.Log

func init() {
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
			Usage:  "profile to use",
			EnvVar: "AE_DEFAULT_PROFILE",
		},
		cli.StringFlag{
			Name: "awsProfile",
			Usage: "Use a certain AWS profile when communicating with AWS. " +
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
				actions.ViewConfig(profile.Load(currentUsername, context, true))
			},
			Subcommands: []cli.Command{
				{
					Name:  "awsSecretKey",
					Usage: "Set the AWS Secret Key to use within this profile",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected aws secret key")
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
							exit("invalid amount of arguments, expected aws access key")
						}

						profile.SetAWSAccessKey(context.Args().First())
						if err := profile.Save(); err != nil {
							exit("cannot save profile", err)
						}
					},
				},
				{
					Name:  "awsProfile",
					Usage: "AWS profile to use",
					Action: func(context *cli.Context) {
						profile := profile.Load(currentUsername, context, false)

						if len(context.Args()) != 1 {
							exit("invalid amount of arguments, expected awsProfile")
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
				exit(install.Install(profile.Load(currentUsername, context, true)))
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
				exit(actions.Alias(profile.Load(currentUsername, context, true)))
			},
		},
		{
			Name:  "status",
			Usage: "display the status of all ec2 instances",
			Action: func(context *cli.Context) {
				exit(actions.Status(profile.Load(currentUsername, context, true)))
			},
		},
		{
			Name:  "ssh",
			Usage: "ssh to a given machine",
			Action: func(context *cli.Context) {
				profile := profile.Load(currentUsername, context, true)
				if len(context.Args()) != 1 {
					exit(actions.ListInstances(profile, ""))
				} else {
					exit(actions.SSH(profile, trimSurroundingQuotes(context.Args().First())))
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
				exit(actions.ListInstances(profile, tag))
			},
		},
	}

	app.Run(os.Args)
}
