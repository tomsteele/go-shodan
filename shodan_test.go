package shodan

import (
	"os"
	"strings"
	"testing"
)

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
