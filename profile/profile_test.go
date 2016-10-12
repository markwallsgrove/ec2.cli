package profile

import (
	"fmt"
	"testing"
)

type UserContextTest struct {
	responses map[string]interface{}
}

func (u UserContextTest) GlobalString(name string) string {
	fmt.Println(name)
	return u.responses[name].(string)
}
func (u UserContextTest) GlobalInt(name string) int {
	return u.responses[name].(int)
}
func (u UserContextTest) GlobalBool(name string) bool {
	return u.responses[name].(bool)
}
func (u UserContextTest) String(name string) string {
	return u.responses[name].(string)
}

type MockMarshaller struct {
	Unmarshalled       bool
	UnmarshallLocation string
	Marshalled         bool
	MarshallLocation   string
}

// Unmarshall
func (m *MockMarshaller) Unmarshall(location string) error {
	m.UnmarshallLocation = location
	m.Unmarshalled = true
	return nil
}

// Marshall
func (m *MockMarshaller) Marshall(location string) error {
	m.MarshallLocation = location
	m.Marshalled = true
	return nil
}

func TestBaseDir(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "/home/smoky/.ec2.cli", r: "/home/smoky/.ec2.cli"},
		{v: "/home/Smoky/.ec2.cli", r: "/home/Smoky/.ec2.cli"},
		{v: "'/home/smoky/.ec2.cli'", r: "/home/smoky/.ec2.cli"},
		{v: "\"/home/smoky/.ec2\"", r: "/home/smoky/.ec2"},
		{v: "", r: ""},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"baseDir": c.v,
		}

		profile := Profile{data: &Data{}, context: context}
		if profile.BaseDir() != c.r {
			t.Errorf("Expected baseDir value was not returned, expected: %q, actual: %s", c.r, profile.BaseDir())
		}
	}
}

func TestName(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "fred", r: "fred"},
		{v: "FRED", r: "FRED"},
		{v: "'Tom'", r: "Tom"},
		{v: "\"Fred\"", r: "Fred"},
		{v: "", r: ""},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"profile": c.v,
		}

		profile := Profile{data: &Data{}, context: context}
		if profile.Name() != c.r {
			t.Errorf("Expected name value was not returned, expected: %q, actual: %s", c.r, profile.Name())
		}
	}
}

func TestHomeDir(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "/home/fred", r: "/home/fred"},
		{v: "/home/Fred", r: "/home/Fred"},
		{v: "'/home/fred'", r: "/home/fred"},
		{v: "\"/home/fred\"", r: "/home/fred"},
		{v: "", r: "/home/default"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"homeDir": c.v,
		}

		data := Data{
			HomeDir: "/home/default",
		}

		profile := Profile{data: &data, context: context}
		if profile.HomeDir() != c.r {
			t.Errorf("Expected homeDir value was not returned, expected: %q, actual: %s", c.r, profile.HomeDir())
		}
	}
}

func TestSetHomeDir(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "/home/fred", d: "/home/default", r: "/home/fred"},
		{v: "/home/Fred", d: "/home/default", r: "/home/Fred"},
		{v: "'/home/fred'", d: "/home/default", r: "/home/fred"},
		{v: "\"/home/fred\"", d: "/home/default", r: "/home/fred"},
		{v: "", d: "/home/default", r: "/home/default"},
		{v: "", d: "'/home/default'", r: "/home/default"},
		{v: "", d: "\"/home/default\"", r: "/home/default"},
		{v: "", d: "\"/home/Default\"", r: "/home/Default"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"homeDir": c.v,
		}

		data := Data{HomeDir: "default"}

		profile := Profile{data: &data, context: context}
		profile.SetHomeDir(c.d)

		if profile.HomeDir() != c.r {
			t.Errorf("Expected homeDir value was not returned, expected: %q, actual: %s", c.r, profile.HomeDir())
		}
	}
}

func TestRegion(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "ap-northeast-2", d: "eu-west-1", r: "ap-northeast-2"},
		{v: "us-east-1", d: "eu-west-1", r: "us-east-1"},
		{v: "AP-northeast-2", d: "eu-west-1", r: "ap-northeast-2"},
		{v: "'us-east-1'", d: "eu-west-1", r: "us-east-1"},
		{v: "\"us-east-1\"", d: "eu-west-1", r: "us-east-1"},
		{v: "\"us-east-1\"", d: "eu-west-1", r: "us-east-1"},
		{v: "", d: "eu-west-1", r: "eu-west-1"},
		{v: "", d: "EU-west-1", r: "eu-west-1"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"region": c.v,
		}

		data := Data{
			Region: c.d,
		}

		profile := Profile{data: &data, context: context}
		if profile.Region() != c.r {
			t.Errorf("Expected region value was not returned, expected: %q, actual: %s", c.r, profile.Region())
		}
	}
}

func TestSetRegion(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "ap-northeast-2", d: "eu-west-1", r: "ap-northeast-2"},
		{v: "us-east-1", d: "eu-west-1", r: "us-east-1"},
		{v: "AP-northeast-2", d: "eu-west-1", r: "ap-northeast-2"},
		{v: "'us-east-1'", d: "eu-west-1", r: "us-east-1"},
		{v: "\"us-east-1\"", d: "eu-west-1", r: "us-east-1"},
		{v: "\"us-east-1\"", d: "eu-west-1", r: "us-east-1"},
		{v: "", d: "eu-west-1", r: "eu-west-1"},
		{v: "", d: "EU-west-1", r: "eu-west-1"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"region": c.v,
		}

		data := Data{Region: "default"}

		profile := Profile{data: &data, context: context}
		profile.SetRegion(c.d)
		if profile.Region() != c.r {
			t.Errorf("Expected region value was not returned, expected: %q, actual: %s", c.r, profile.Region())
		}
	}
}

func TestUser(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "ab", d: "rh", r: "ab"},
		{v: "AB", d: "rh", r: "AB"},
		{v: "'AB'", d: "rh", r: "AB"},
		{v: "\"AB\"", d: "rh", r: "AB"},
		{v: "", d: "rh", r: "rh"},
		{v: "", d: "Rh", r: "Rh"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"user": c.v,
		}

		data := Data{
			User: c.d,
		}

		profile := Profile{data: &data, context: context}
		if profile.User() != c.r {
			t.Errorf("Expected user value was not returned, expected: %q, actual: %s", c.r, profile.User())
		}
	}
}

func TestSetUser(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "ab", d: "rh", r: "ab"},
		{v: "AB", d: "rh", r: "AB"},
		{v: "'AB'", d: "rh", r: "AB"},
		{v: "\"AB\"", d: "rh", r: "AB"},
		{v: "", d: "rh", r: "rh"},
		{v: "", d: "Rh", r: "Rh"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"user": c.v,
		}

		data := Data{User: "default"}

		profile := Profile{data: &data, context: context}
		profile.SetUser(c.d)

		if profile.User() != c.r {
			t.Errorf("Expected user value was not returned, expected: %q, actual: %s", c.r, profile.User())
		}
	}
}

func TestMaxCacheAge(t *testing.T) {
	testCases := []struct {
		v int
		d int
		f bool
		r int
	}{
		{v: -1, d: 300, f: false, r: 300},
		{v: 300, d: 1, f: false, r: 300},
		{v: 300, d: 1, f: true, r: 0},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"flushCache":  c.f,
			"maxCacheAge": c.v,
		}

		data := Data{
			MaxCacheAge: c.d,
		}

		profile := Profile{data: &data, context: context}
		if profile.MaxCacheAge() != c.r {
			t.Errorf("Expected maxCacheAge value was not returned, expected: %v, actual: %v", c.r, profile.MaxCacheAge())
		}
	}
}

func TestSetMaxCacheAge(t *testing.T) {
	testCases := []struct {
		v string
		d int
		r int
	}{
		{v: "-1", r: -1},
		{v: "301", r: 301},
		{v: "1.1", r: 300},
		{v: "fred", r: 300},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"flushCache":  false,
			"maxCacheAge": -1,
		}

		data := Data{}

		profile := Profile{data: &data, context: context}
		profile.SetMaxCacheAge(c.v)

		if profile.MaxCacheAge() != c.r {
			t.Errorf("Expected maxCacheAge value was not returned, expected: %v, actual: %v", c.r, profile.MaxCacheAge())
		}
	}
}

func TestCertLocation(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "/test/cert.cert", d: "/test2/cert.cert", r: "/test2/cert.cert"},
		{v: "/test/cert.cert", d: "", r: "/test/cert.cert"},
		{v: "/test/MIDDLE/Cert.cert", d: "", r: "/test/MIDDLE/Cert.cert"},
		{v: "/test/Cert.crt", d: "", r: "/test/Cert.crt"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"cert": c.d,
		}

		data := Data{
			CertLocation: c.v,
		}

		profile := Profile{data: &data, context: context}
		if profile.CertLocation() != c.r {
			t.Errorf("Expected cert value was not returned, expected: %v, actual: %v", c.r, profile.CertLocation())
		}
	}
}

func TestSetCertLocation(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "/test/cert.crt", r: "/test/cert.crt"},
		{v: "/test/Cert.crt", r: "/test/Cert.crt"},
		{v: "'/test/Cert.crt'", r: "/test/Cert.crt"},
		{v: "\"/test/Cert.crt\"", r: "/test/Cert.crt"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"cert": "",
		}

		data := Data{}

		profile := Profile{data: &data, context: context}
		profile.SetCertLocation(c.v)

		if profile.CertLocation() != c.r {
			t.Errorf("Expected cert value was not returned, expected: %v, actual: %v", c.r, profile.CertLocation())
		}
	}
}

func TestAliasPrefix(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "prefix1", d: "prefix2", r: "prefix2"},
		{v: "prefix1", d: "", r: "prefix1"},
		{v: "PREFIX1-", d: "", r: "PREFIX1-"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"prefix": c.d,
		}

		data := Data{
			AliasPrefix: c.v,
		}

		profile := Profile{data: &data, context: context}
		if profile.AliasPrefix() != c.r {
			t.Errorf("Expected alias prefix value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestSetAliasPrefix(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "prefix", r: "prefix"},
		{v: "Prefix", r: "Prefix"},
		{v: "'prefix'", r: "prefix"},
		{v: "\"prefix\"", r: "prefix"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"prefix": "",
		}

		data := Data{}

		profile := Profile{data: &data, context: context}
		profile.SetAliasPrefix(c.v)

		if profile.AliasPrefix() != c.r {
			t.Errorf("Expected alias prefix value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestAWSProfile(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "devops", d: "dev", r: "dev"},
		{v: "default", d: "", r: "default"},
		{v: "Default1-", d: "", r: "Default1-"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"awsProfile": c.d,
		}

		data := Data{
			AWSProfile: c.v,
		}

		profile := Profile{data: &data, context: context}
		if profile.AWSProfile() != c.r {
			t.Errorf("Expected AWS profile value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestSetAWSProfile(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "devops", r: "devops"},
		{v: "Main-Account", r: "Main-Account"},
		{v: "'default'", r: "default"},
		{v: "\"devops\"", r: "devops"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"awsProfile": "",
		}

		data := Data{}

		profile := Profile{data: &data, context: context}
		profile.SetAWSProfile(c.v)

		if profile.AWSProfile() != c.r {
			t.Errorf("Expected AWS profile value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestAWSAccessKey(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "546789232423fsdfsdgdfgsd", d: "sflkhsdf34fsdfdfs", r: "sflkhsdf34fsdfdfs"},
		{v: "4kjl;fj324o82sdklfjsdlf", d: "", r: "4kjl;fj324o82sdklfjsdlf"},
		{v: ",sdjfFSFASDfwaklerj3432432", d: "", r: ",sdjfFSFASDfwaklerj3432432"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"awsAccessKey": c.d,
		}

		data := Data{
			AWSAccessKey: c.v,
		}

		profile := Profile{data: &data, context: context}
		if profile.AWSAccessKey() != c.r {
			t.Errorf("Expected AWS Access Key value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestSetAWSAccessKey(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "testaccesskey", r: "testaccesskey"},
		{v: "DFSDGDGHD45454fdgdfsg£$@£$", r: "DFSDGDGHD45454fdgdfsg£$@£$"},
		{v: "'dfjsdfl;ksjdlflj34'", r: "dfjsdfl;ksjdlflj34"},
		{v: "\"dsjfsdlkfjsl;kdjl45453kljal;k\"", r: "dsjfsdlkfjsl;kdjl45453kljal;k"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"awsAccessKey": "",
		}

		data := Data{}

		profile := Profile{data: &data, context: context}
		profile.SetAWSAccessKey(c.v)

		if profile.AWSAccessKey() != c.r {
			t.Errorf("Expected AWS Access Key value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestAWSSecretKey(t *testing.T) {
	testCases := []struct {
		v string
		d string
		r string
	}{
		{v: "546789232423fsdfsdgdfgsd", d: "sflkhsdf34fsdfdfs", r: "sflkhsdf34fsdfdfs"},
		{v: "4kjl;fj324o82sdklfjsdlf", d: "", r: "4kjl;fj324o82sdklfjsdlf"},
		{v: ",sdjfFSFASDfwaklerj3432432", d: "", r: ",sdjfFSFASDfwaklerj3432432"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"awsSecretKey": c.d,
		}

		data := Data{
			AWSSecretKey: c.v,
		}

		profile := Profile{data: &data, context: context}
		if profile.AWSSecretKey() != c.r {
			t.Errorf("Expected AWS Access Key value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestSetAWSSecretKey(t *testing.T) {
	testCases := []struct {
		v string
		r string
	}{
		{v: "testaccesskey", r: "testaccesskey"},
		{v: "DFSDGDGHD45454fdgdfsg£$@£$", r: "DFSDGDGHD45454fdgdfsg£$@£$"},
		{v: "'dfjsdfl;ksjdlflj34'", r: "dfjsdfl;ksjdlflj34"},
		{v: "\"dsjfsdlkfjsl;kdjl45453kljal;k\"", r: "dsjfsdlkfjsl;kdjl45453kljal;k"},
	}

	for _, c := range testCases {
		context := UserContextTest{}
		context.responses = map[string]interface{}{
			"awsSecretKey": "",
		}

		data := Data{}

		profile := Profile{data: &data, context: context}
		profile.SetAWSSecretKey(c.v)

		if profile.AWSSecretKey() != c.r {
			t.Errorf("Expected AWS Secret Key value was not returned, expected: %v, actual: %v", c.r, profile.AliasPrefix())
		}
	}
}

func TestCreate(t *testing.T) {
	testCases := []struct {
		r string
		u string
		c int
	}{
		{r: "eu-west-1", u: "user1", c: 300},
		{r: "eu-west-1", u: "User1", c: 300},
	}

	context := UserContextTest{}
	context.responses = map[string]interface{}{
		"user":        "",
		"region":      "",
		"maxCacheAge": -1,
		"flushCache":  false,
	}

	for _, c := range testCases {
		profile := Create(c.u, context)

		if profile.Region() != c.r {
			t.Errorf("Expected region value was not returned, expected: %v, actual: %v", c.r, profile.Region())
		}

		if profile.User() != c.u {
			t.Errorf("Expected user value was not returned, expected: %v, actual: %v", c.u, profile.User())
		}

		if profile.MaxCacheAge() != c.c {
			t.Errorf("Expected max cache age value was not returned, expected: %v, actual: %v", c.c, profile.MaxCacheAge())
		}
	}
}

func TestSave(t *testing.T) {
	context := UserContextTest{}
	context.responses = map[string]interface{}{
		"user":    "",
		"baseDir": "/tmp",
		"profile": "test",
	}

	marshaller := MockMarshaller{}

	data := Data{
		Region:      "eu-west-1",
		User:        "test",
		MaxCacheAge: 300,
	}

	profile := Profile{
		&marshaller,
		context,
		&data,
	}

	err := profile.Save()
	if err != nil {
		t.Errorf("Unexpected error when saving profile, %v", err)
	}

	if marshaller.Marshalled != true || marshaller.Unmarshalled != false {
		t.Errorf("Unexpected marshaller state, marshalled: %v, unmarshalled: %v", marshaller.Marshalled, marshaller.Unmarshalled)
	}

	if marshaller.MarshallLocation != "/tmp/config/test.json" {
		t.Errorf("Unexpected save location, '%v'", marshaller.MarshallLocation)
	}
}

func TestLoad(t *testing.T) {
	context := UserContextTest{}
	context.responses = map[string]interface{}{
		"user":    "",
		"baseDir": "/tmp",
		"profile": "test",
	}

	marshaller := MockMarshaller{}

	data := Data{
		Region:      "eu-west-1",
		User:        "test",
		MaxCacheAge: 300,
	}

	profile := Profile{
		&marshaller,
		context,
		&data,
	}

	err := profile.Load()
	if err != nil {
		t.Errorf("Unexpected error when loading profile, %v", err)
	}

	if marshaller.Marshalled != false || marshaller.Unmarshalled != true {
		t.Errorf("Unexpected marshaller state, marshalled: %v, unmarshalled: %v", marshaller.Marshalled, marshaller.Unmarshalled)
	}

	if marshaller.UnmarshallLocation != "/tmp/config/test.json" {
		t.Errorf("Unexpected load location, '%v'", marshaller.UnmarshallLocation)
	}
}
