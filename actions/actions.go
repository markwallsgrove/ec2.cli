package actions

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/markwallsgrove/ec2.cli/instances"
	"github.com/markwallsgrove/ec2.cli/logging"
	"github.com/markwallsgrove/ec2.cli/profile"
	"github.com/olekukonko/tablewriter"
	"github.com/toumorokoshi/go-fuzzy/fuzzy"
)

var log = logging.Log

// ListInstances list all ec2 instances that match the given tag
func ListInstances(profile *profile.Profile, fuzzyTag string) error {
	instances, err := instances.GetAll(profile)
	for name := range instances {
		if fuzzyTag == "" || fuzzy.SequenceMatch(fuzzyTag, name) {
			fmt.Println(name)
		}
	}

	return err
}

// ViewConfig display the configuration within the profile in table format
func ViewConfig(profile *profile.Profile) {
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

func templateSSHUsernameAtHost(user string, host string) string {
	return fmt.Sprintf("%s@%s", user, host)
}

func createSSHCmd(profile *profile.Profile, instance *instances.Instance) *exec.Cmd {
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

// SSH connect to an ec2 instance using the SSH protocol
func SSH(profile *profile.Profile, hostName string) error {
	instance, err := instances.FindByHostname(profile, hostName)

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

// Status display the status of the ec2 machines
func Status(profile *profile.Profile) error {
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

	if err == nil {
		table.Render()
	} else {
		log.Error("Unable to retrieve instances", err)
	}

	return err
}

func templateSSHCertLocation(profile *profile.Profile) (string, error) {
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

// Alias generate a list of bash aliases for connecting to the ec2 instances
func Alias(profile *profile.Profile) error {
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
