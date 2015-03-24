/*Package shodan is an interface for the Shodan API*/
package shodan

// Client stores shared data that is used to interact with the API.
// Key is our Shodan API Key.
type Client struct {
	Key string
}

// HostOptions are used to pass parameters to the Host function.
type HostOptions struct {
	IP      string
	History bool
	Minify  bool
}

// Host is used to unmarshal the JSON response from '/shodan/host/{ip}'.
type Host struct {
	RegionCode  interface{}   `json:"region_code"`
	IP          string        `json:"ip"`
	AreaCode    interface{}   `json:"area_code"`
	CountryName string        `json:"country_name"`
	Hostnames   []interface{} `json:"hostnames"`
	PostalCode  interface{}   `json:"postal_code"`
	DmaCode     interface{}   `json:"dma_code"`
	CountryCode string        `json:"country_code"`
	Data        []struct {
		Product    string        `json:"product"`
		Os         interface{}   `json:"os"`
		Timestamp  string        `json:"timestamp"`
		Isp        string        `json:"isp"`
		Asn        string        `json:"asn"`
		Banner     string        `json:"banner"`
		Hostnames  []interface{} `json:"hostnames"`
		Devicetype string        `json:"devicetype"`
		Location   struct {
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
		IP      string        `json:"ip"`
		Domains []interface{} `json:"domains"`
		Org     string        `json:"org"`
		Port    int           `json:"port"`
		Opts    struct {
		} `json:"opts"`
	} `json:"data"`
	City         interface{} `json:"city"`
	Longitude    int         `json:"longitude"`
	CountryCode3 string      `json:"country_code3"`
	Latitude     int         `json:"latitude"`
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

// Error used to unmarshal the JSOn response of an error.
type Error struct {
	Error string `json:"error"`
}

// New returns a new Client.
func New(key string) *Client {
	return &Client{
		Key: key,
	}
}

// Host calls '/shodan/host/{ip}'.
func (c *Client) Host(*HostOptions) {
}
