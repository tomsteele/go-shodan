package shodan

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestAPIInfo(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	i, err := c.APIInfo()
	if err != nil {
		t.Error("error returned from APIInfo")
		t.Log(err)
	}
	if i.QueryCredits == 0 {
		t.Error("QueryCredits is 0")
	}
}

func TestHostCount(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	hc, err := c.HostCount("apache", []string{})
	if err != nil {
		t.Error("error returned from HoustCount")
		t.Log(err)
	}
	if len(hc.Matches) < 1 {
		t.Error("HostCount returned 0 matches")
	}
}

func TestHostSearch(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	hs, err := c.HostSearch("apache", []string{}, url.Values{})
	if err != nil {
		t.Error("error returned HostSearch")
		t.Log(err)
	}
	if len(hs.Matches) < 1 {
		t.Error("HostSearch returned 0 matches")
	}
}

func TestHostSearchTokens(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	if _, err := c.HostSearchTokens("apache"); err != nil {
		t.Error("error returned HostSearchTokens")
		t.Log(err)
	}
}

func TestProtocols(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	p, err := c.Protocols()
	if err != nil {
		t.Error("error returned from Protocols")
		t.Log(err)
	}
	if len(p) < 1 {
		t.Error("no protocols returned from Protocols")
	}
}

func TestServices(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	s, err := c.Services()
	if err != nil {
		t.Error("error returned from Services")
		t.Log(err)
	}
	if len(s) < 1 {
		t.Error("no services returned from Services")
	}
}

func TestQuery(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	if _, err := c.Query(url.Values{}); err != nil {
		t.Error("error returned from Query")
		t.Log(err)
	}
}

func TestQuerySearch(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	if _, err := c.QuerySearch("apache", url.Values{}); err != nil {
		t.Error("error returned from QuerySearch")
		t.Log(err)
	}
}

func TestQueryTags(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	if _, err := c.QueryTags(url.Values{}); err != nil {
		t.Error("error returned form QueryTags")
		t.Log(err)
	}
}

func TestExploits(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)
	e, err := c.Exploits("apache", []string{})
	if err != nil {
		t.Error("error returned from Exploits")
		t.Log(err)
	}
	if len(e.Matches) < 1 {
		t.Error("Exploits returned 0 matches")
	}
}

func TestHost(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)

	result, err := c.Host("104.131.56.170", url.Values{})
	if err != nil {
		t.Error("error returned from Host")
		t.Log(err)
	}
	if len(result.Ports) < 0 {
		t.Error("no ports returned")
	}
}

func TestResolve(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)

	result, err := c.DNSResolve([]string{"stacktitan.com"})
	if err != nil {
		t.Error("error returned from DNSResolve")
		t.Log(err)
	}
	found := false
	for _, r := range result {
		if r.IP == "104.131.56.170" {
			found = true
		}
	}
	if !found {
		t.Error("ip not found")
	}
}

func TestReverse(t *testing.T) {
	k := os.Getenv("SHODAN_API_KEY")
	if k == "" {
		t.Fatal("SHODAN_API_KEY environment variable not set")
	}
	c := New(k)

	result, err := c.DNSReverse([]string{"104.131.56.170"})
	if err != nil {
		t.Error("error returned from DNSReverse")
		t.Log(err)
	}
	found := false
	for _, r := range result {
		for _, h := range r.Hostnames {
			if strings.Contains(h, "stacktitan.com") {
				found = true
			}
		}
	}
	if !found {
		t.Error("hostname not found")
	}
}
