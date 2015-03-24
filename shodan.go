/*Package shodan is an interface for the Shodan API*/
package shodan

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// APIHost is the URL of the Shodan API.
// Debug toggles debug information.
var (
	APIHost = "https://api.shodan.io"
	Debug   = false
)

// Client stores shared data that is used to interact with the API.
// Key is our Shodan API Key.
type Client struct {
	Key string
}

// Host is used to unmarshal the JSON response from '/shodan/host/{ip}'.
type Host struct {
	RegionCode  string   `json:"region_code"`
	IP          int      `json:"ip"`
	AreaCode    int      `json:"area_code"`
	Latitude    float64  `json:"latitude"`
	Hostnames   []string `json:"hostnames"`
	PostalCode  string   `json:"postal_code"`
	DmaCode     int      `json:"dma_code"`
	CountryCode string   `json:"country_code"`
	Org         string   `json:"org"`
	Data        []struct {
		Product string `json:"product"`
		Title   string `json:"title"`
		Opts    struct {
		} `json:"opts"`
		Timestamp string   `json:"timestamp"`
		Isp       string   `json:"isp"`
		Cpe       []string `json:"cpe"`
		Data      string   `json:"data"`
		HTML      string   `json:"html"`
		Location  struct {
			City         string  `json:"city"`
			RegionCode   string  `json:"region_code"`
			AreaCode     int     `json:"area_code"`
			Longitude    float64 `json:"longitude"`
			CountryCode3 string  `json:"country_code3"`
			Latitude     float64 `json:"latitude"`
			PostalCode   string  `json:"postal_code"`
			DmaCode      int     `json:"dma_code"`
			CountryCode  string  `json:"country_code"`
			CountryName  string  `json:"country_name"`
		} `json:"location"`
		IP        int         `json:"ip"`
		Domains   []string    `json:"domains"`
		Org       string      `json:"org"`
		Os        interface{} `json:"os"`
		Port      int         `json:"port"`
		Hostnames []string    `json:"hostnames"`
		IPStr     string      `json:"ip_str"`
	} `json:"data"`
	City         string      `json:"city"`
	Isp          string      `json:"isp"`
	Longitude    float64     `json:"longitude"`
	LastUpdate   string      `json:"last_update"`
	CountryCode3 string      `json:"country_code3"`
	CountryName  string      `json:"country_name"`
	IPStr        string      `json:"ip_str"`
	Os           interface{} `json:"os"`
	Ports        []int       `json:"ports"`
}

// HostCount is used to unmarshal the JSON response from '/shodan/host/count'.
type HostCount struct {
	Matches []interface{} `json:"matches"`
	Facets  struct {
		Org []struct {
			Count int    `json:"count"`
			Value string `json:"value"`
		} `json:"org"`
	} `json:"facets"`
	Total int `json:"total"`
}

// HostSearch is used to unmarshal the JSON response from '/shodan/host/search'.
type HostSearch struct {
	Matches []struct {
		Os        interface{}   `json:"os"`
		Timestamp string        `json:"timestamp"`
		Isp       string        `json:"isp"`
		Asn       string        `json:"asn"`
		Hostnames []interface{} `json:"hostnames"`
		Location  struct {
			City         interface{} `json:"city"`
			RegionCode   interface{} `json:"region_code"`
			AreaCode     interface{} `json:"area_code"`
			Longitude    int         `json:"longitude"`
			CountryCode3 string      `json:"country_code3"`
			CountryName  string      `json:"country_name"`
			PostalCode   interface{} `json:"postal_code"`
			DmaCode      interface{} `json:"dma_code"`
			CountryCode  string      `json:"country_code"`
			Latitude     int         `json:"latitude"`
		} `json:"location"`
		IP      int64         `json:"ip"`
		Domains []interface{} `json:"domains"`
		Data    string        `json:"data"`
		Org     string        `json:"org"`
		Port    int           `json:"port"`
		IPStr   string        `json:"ip_str"`
	} `json:"matches"`
	Facets struct {
		Org []struct {
			Count int    `json:"count"`
			Value string `json:"value"`
		} `json:"org"`
	} `json:"facets"`
	Total int `json:"total"`
}

// HostSearchTokens is used to unmarshal the JSON response from '/shodan/host/search/tokens'.
type HostSearchTokens struct {
	Attributes struct {
		Ports []int `json:"ports"`
	} `json:"attributes"`
	Errors  []interface{} `json:"errors"`
	String  string        `json:"string"`
	Filters []string      `json:"filters"`
}

// Scan is used to unmarshal the JSON response from '/shodan/scan'.
type Scan struct {
	ID          string `json:"id"`
	Count       int    `json:"count"`
	CreditsLeft int    `json:"credits_left"`
}

// ScanInternet is used to unmarshal the JSON response from '/shodan/scan/internet'.
type ScanInternet struct {
	ID string `json:"id"`
}

// Query is used to unmarshal the JSON response from '/shodan/query/{search}'.
type Query struct {
	Total   int `json:"total"`
	Matches []struct {
		Votes       int      `json:"votes"`
		Description string   `json:"description"`
		Title       string   `json:"title"`
		Timestamp   string   `json:"timestamp"`
		Tags        []string `json:"tags"`
		Query       string   `json:"query"`
	} `json:"matches"`
}

// QueryTags is used to unmarshal the JSON response from '/shodan/query/tags'.
type QueryTags struct {
	Total   int `json:"total"`
	Matches []struct {
		Value string `json:"value"`
		Count int    `json:"count"`
	} `json:"matches"`
}

// APIInfo is used to unmarshal the JSON response from '/shodan/api-info'.
type APIInfo struct {
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	Telnet       bool   `json:"telnet"`
	Plan         string `json:"plan"`
	HTTPS        bool   `json:"https"`
	Unlocked     bool   `json:"unlocked"`
}

// DNSResolve is used to transform the map[string]string response from '/dns/resolve'
// into a struct that is a bit easier to work with.
type DNSResolve struct {
	Hostname string
	IP       string
}

// DNSReverse is used to transform the map[string][]string response from '/dns/reverse'
// into a struct that is a bit easier to work with.
type DNSReverse struct {
	IP        string
	Hostnames []string
}

// Error used to unmarshal the JSON response of an error.
type Error struct {
	Error string `json:"error"`
}

// New returns a new Client.
func New(key string) *Client {
	return &Client{
		Key: key,
	}
}

// Host calls '/shodan/host/{ip}' and returns the unmarshaled response.
// ip is the IP address to search for and opts are all query paramters to pass
// in the request. You do not have to provide your API key.
func (c *Client) Host(ip string, opts url.Values) (*Host, error) {
	h := &Host{}
	opts.Set("key", c.Key)
	req, err := http.NewRequest("GET", APIHost+"/shodan/host/"+ip+"?"+opts.Encode(), nil)
	debug("GET " + req.URL.String())
	if err != nil {
		return h, err
	}
	if err := doRequestAndUnmarshal(req, &h); err != nil {
		return h, err
	}
	return h, nil
}

// DNSResolve calls '/dns/resolve' and returns the unmarshaled response.
func (c *Client) DNSResolve(hostnames []string) ([]DNSResolve, error) {
	d := []DNSResolve{}
	req, err := http.NewRequest("GET", APIHost+"/dns/resolve?key="+c.Key+"&hostnames="+strings.Join(hostnames, ","), nil)
	debug("GET " + req.URL.String())
	if err != nil {
		return d, err
	}
	m := make(map[string]string)
	if err := doRequestAndUnmarshal(req, &m); err != nil {
		return d, err
	}
	for k, v := range m {
		d = append(d, DNSResolve{
			Hostname: k,
			IP:       v,
		})
	}
	return d, nil
}

// DNSReverse calls '/dns/reverse' and returns the unmarshaled response.
func (c *Client) DNSReverse(ips []string) ([]DNSReverse, error) {
	d := []DNSReverse{}
	req, err := http.NewRequest("GET", APIHost+"/dns/reverse?key="+c.Key+"&ips="+strings.Join(ips, ","), nil)
	debug("GET " + req.URL.String())
	if err != nil {
		return d, err
	}
	m := make(map[string][]string)
	if err := doRequestAndUnmarshal(req, &m); err != nil {
		return d, err
	}
	for k, v := range m {
		r := DNSReverse{IP: k}
		for _, n := range v {
			r.Hostnames = append(r.Hostnames, n)
		}
		d = append(d, r)
	}
	return d, nil
}

func doRequestAndUnmarshal(req *http.Request, thing interface{}) error {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := checkError(resp, data); err != nil {
		return err
	}
	err = json.Unmarshal(data, &thing)
	return err
}

func checkError(resp *http.Response, data []byte) error {
	if resp.StatusCode >= 300 {
		debug("Non 2XX response")
		e := &Error{}
		if err := json.Unmarshal(data, &e); err != nil {
			debug("Error parsing JSON")
			return err
		}
		return errors.New(e.Error)
	}
	return nil
}

func debug(msg string) {
	if Debug {
		log.Println(msg)
	}
}
