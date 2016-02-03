package main

import (
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"os"
	"regexp"
	"strings"
)

func main() {
	certificateLocation := flag.String("cert", "", "SSH certificate location")
	awsRegion := flag.String("region", "eu-west-1", "AWS region")

	flag.Usage = func() {
		fmt.Printf("Usage %s [OPTION] [USER]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 || flag.Arg(0) == "" {
		flag.Usage()
		os.Exit(1)
	}

	user := flag.Arg(0)

	sshCertificateLocation := ""
	if *certificateLocation != "" {
		if _, err := os.Stat(*certificateLocation); os.IsNotExist(err) {
			panic("SSH certificate location is invalid")
		}

		sshCertificateLocation = fmt.Sprintf(" -i %s", *certificateLocation)
	}

	svc := ec2.New(session.New(), &aws.Config{Region: aws.String(*awsRegion)})

	resp, err := svc.DescribeInstances(nil)
	if err != nil {
		panic(err)
	}

	regexWhiteChars, err := regexp.Compile("[^a-zA-Z0-9]")
	if err != nil {
		panic(err)
	}

	for _, res := range resp.Reservations {
		for _, inst := range res.Instances {
			name := ""
			for _, keys := range inst.Tags {
				if *keys.Key == "Name" {
					name = *keys.Value
					break
				}
			}

			addr := inst.PublicIpAddress
			if addr == nil {
				addr = inst.PrivateIpAddress
			}

			if name != "" && addr != nil {
				name = regexWhiteChars.ReplaceAllString(name, "_")
				fmt.Println(fmt.Sprintf("alias %s=\"ssh%s %s@%s\"", strings.ToLower(name), sshCertificateLocation, user, *addr))
			}
		}
	}
}
