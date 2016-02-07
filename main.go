package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/codegangsta/cli"
	"github.com/olekukonko/tablewriter"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var regexWhiteChars = regexp.MustCompile("[^a-zA-Z0-9]")

type Instance struct {
	name          string
	addr          string
	id            string
	publicDnsName string
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
	// TODO: status of a machine

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
			Flags:  []cli.Flag{},
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
	table.SetHeader([]string{"Id", "Name", "Address", "Public DNS Name"})

	err, instances := getInstances(c.GlobalString("region"))
	if err != nil {
		panic(err)
	}

	for _, instance := range instances {
		table.Append([]string{
			instance.id, instance.name,
			instance.addr, instance.publicDnsName,
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
