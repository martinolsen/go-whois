package whois

import (
	"testing"
)

func TestWhois(t *testing.T) {
	var tests = [][3]string{
		{"66.226.11.227", "66.226.0.0/19", "US"},
		{"190.15.209.109", "190.15.192.0/19", "AR"},
		{"195.26.52.231", "195.26.52.224/29", "GB"},
		{"213.160.146.140", "213.160.146.136/29", "UA"},
		{"173.219.189.95", "173.216.0.0/14", "US"},
		{"62.117.81.136", "62.117.81.136/29", "RU"},
		{"177.223.18.77", "", "BR"},
		{"190.77.179.162", "", "VE"},
		{"91.240.224.54", "", "GB"},
		// TODO {"54.204.5.88", "", "US"}, - returns references to multiple networks...
	}

	for _, test := range tests {
		r, err := Lookup(test[0])
		if err != nil {
			t.Errorf("Whosis: %s", err)
		} else if country := r.Get("country"); country != test[2] {
			t.Errorf("expected country of %q, got %q", test[2], country)
		}

		//t.Logf("%s: %#v", test[0], r)
	}
}
