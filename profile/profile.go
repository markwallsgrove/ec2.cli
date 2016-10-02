package profile

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/codegangsta/cli"
	"github.com/markwallsgrove/ec2.cli/logging"
)

var log = logging.Log

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

// Profile structure to hold the context and profile data
type Profile struct {
	context *cli.Context
	data    *Data
}

// Data structure holds all the relevant information
// reguarding the users configuration
type Data struct {
	Region       string `json:"region,omitempty"`
	User         string `json:"user,omitempty"`
	CertLocation string `json:"certLocation,omitempty"`
	MaxCacheAge  int    `json:"maxCacheAge,omitempty"`
	AliasPrefix  string `json:"aliasPrefix,omitempty"`
	AWSProfile   string `json:"awsProfile,omitempty"`
	AWSAccessKey string `json:"awsAccessKey,omitempty"`
	AWSSecretKey string `json:"awsSecretKey,omitempty"`
	HomeDir      string `json:"homeDir,omitempty"`
}

// BaseDir is the directory where ec2 is located
func (p *Profile) BaseDir() string {
	return trimSurroundingQuotes(p.context.GlobalString("baseDir"))
}

// Name of the profile that this object represents
func (p *Profile) Name() string {
	return trimSurroundingQuotes(p.context.GlobalString("profile"))
}

// HomeDir representing the user's home directory
func (p *Profile) HomeDir() string {
	if homeDir := trimSurroundingQuotes(p.context.GlobalString("homeDir")); homeDir != "" {
		return homeDir
	}

	return p.data.HomeDir
}

// SetHomeDir set the user's home directory
func (p *Profile) SetHomeDir(homeDir string) {
	p.data.HomeDir = trimSurroundingQuotes(homeDir)
}

// Region that aws will located the ec2 instance within
func (p *Profile) Region() string {
	if region := trimSurroundingQuotes(p.context.GlobalString("region")); region != "" {
		return region
	}

	return p.data.Region
}

// SetRegion define the region to use when retreiving
// AWS meta data
func (p *Profile) SetRegion(region string) {
	p.data.Region = trimSurroundingQuotes(region)
}

// User to use when connecting to the ec2 instance
func (p *Profile) User() string {
	if user := trimSurroundingQuotes(p.context.GlobalString("user")); user != "" {
		return user
	}

	return p.data.User
}

// SetUser define the username to use when connecting to
// a ec2 instance
func (p *Profile) SetUser(user string) {
	p.data.User = trimSurroundingQuotes(user)
}

// MaxCacheAge the maximum amount of time to pass before
// flushing the cache and retrievIng the ec2 meta data again
func (p *Profile) MaxCacheAge() int {
	if p.context.GlobalBool("flushCache") == true {
		return 0
	} else if maxCacheAge := p.context.GlobalInt("maxCacheAge"); maxCacheAge != -1 {
		return maxCacheAge
	}

	return p.data.MaxCacheAge
}

// SetMaxCacheAge define the maximum amount of time
// to cache meta data retreived from AWS
func (p *Profile) SetMaxCacheAge(maxCacheAge string) {
	maxCacheAgeInt, err := strconv.Atoi(trimSurroundingQuotes(maxCacheAge))

	if err != nil {
		maxCacheAgeInt = 300
	}

	p.data.MaxCacheAge = maxCacheAgeInt
}

// CertLocation location of the RSA certificate to use when
// connecting to an ec2 instance
func (p *Profile) CertLocation() string {
	return p.getGlobalContextValue("cert", p.data.CertLocation)
}

// SetCertLocation define the certificate file location
// to use when connecting to a ec2 instance
func (p *Profile) SetCertLocation(certLocation string) {
	p.data.CertLocation = trimSurroundingQuotes(certLocation)
}

// AliasPrefix value to append to the front of the alias
// name
func (p *Profile) AliasPrefix() string {
	return p.getGlobalContextValue("prefix", p.data.AliasPrefix)
}

// SetAliasPrefix define the string to prefix to a alias
func (p *Profile) SetAliasPrefix(aliasPrefix string) {
	p.data.AliasPrefix = trimSurroundingQuotes(aliasPrefix)
}

// AWSProfile name of the AWSProfile to use when connecting
// to AWS (Metadata collection), optional
func (p *Profile) AWSProfile() string {
	return p.getGlobalContextValue("awsProfile", p.data.AWSProfile)
}

// SetAWSProfile define the AWS profile name to use when retreiving
// AWS metadata
func (p *Profile) SetAWSProfile(awsProfile string) {
	p.data.AWSProfile = trimSurroundingQuotes(awsProfile)
}

// AWSAccessKey access key used when retrieving AWS metadata
// (optional)
func (p *Profile) AWSAccessKey() string {
	return p.getGlobalContextValue("awsAccessKey", p.data.AWSAccessKey)
}

// SetAWSAccessKey set the AWS access key to use when
// retreiving meta data
func (p *Profile) SetAWSAccessKey(awsAccessKey string) {
	p.data.AWSAccessKey = trimSurroundingQuotes(awsAccessKey)
}

// AWSSecretKey secret key used when retrieving AWS metadata
// (optional)
func (p *Profile) AWSSecretKey() string {
	return p.getGlobalContextValue("awsSecretKey", p.data.AWSSecretKey)
}

// SetAWSSecretKey set the AWS secret key used when retreiving
// meta data
func (p *Profile) SetAWSSecretKey(awsSecretKey string) {
	p.data.AWSSecretKey = trimSurroundingQuotes(awsSecretKey)
}

func (p *Profile) getGlobalContextValue(name string, defaultValue string) string {
	if value := trimSurroundingQuotes(p.context.String(name)); value != "" {
		log.Debug("found", value, "for", name, "in command line parameters")
		return value
	}

	log.Debug("defaulting", name, "as", fmt.Sprintf("'%s'", defaultValue))
	return defaultValue
}

// Save the current profile values to a profile held within the base
// directory
func (p *Profile) Save() error {
	if err := os.MkdirAll(fmt.Sprintf("%s/config", p.BaseDir()), 0770); err != nil {
		return err
	}

	configLoc := fmt.Sprintf("%s/config/%s.json", p.BaseDir(), p.Name())
	configBytes, err := json.MarshalIndent(p, "", "    ")
	log.Debug("saving profile to", configLoc)

	if err != nil {
		return err
	}

	return ioutil.WriteFile(configLoc, configBytes, 0775)
}

func loadProfileFromFile(location string, currentUsername string, context *cli.Context) (Profile, error) {
	profile := Data{
		Region:      "eu-west-1",
		User:        currentUsername,
		MaxCacheAge: 300,
	}

	log.Debug("loading profile from", location)

	if _, err := os.Stat(location); err != nil {
		return Profile{}, err
	}

	profileBytes, err := ioutil.ReadFile(location)
	if err != nil {
		log.Error("could not load profile", err)
		return Profile{}, err
	}

	// TODO: this is not working
	log.Debug("profile data from file", string(profileBytes))
	if err = json.Unmarshal(profileBytes, &profile); err != nil {
		log.Error("could not unmarshal profile", err)
		return Profile{}, err
	}

	log.Debug("loaded profile successfully", fmt.Sprintf("%+v", profile))
	return Profile{data: &profile, context: context}, nil
}

// Load the user's profile by mixing environment variables, saved JSON
// data && command line specified attributes.
func Load(username string, context *cli.Context, useEnvValues bool) *Profile {
	location := fmt.Sprintf("%s/config/%s.json", context.GlobalString("baseDir"), context.GlobalString("profile"))
	profile, err := loadProfileFromFile(location, username, context)

	if err != nil {
		log.Error("Cannot load profile from", location, "due to", err)
	}

	if useEnvValues == false {
		return &profile
	}

	log.Debug("constructed profile", fmt.Sprintf("%+v\n", profile))
	return &profile
}
