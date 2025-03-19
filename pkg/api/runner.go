package api

import (
	"bufio"
	"encoding/json"
	"github.com/oneaudit/katana-ng/pkg/engine"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/networkpolicy"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"go.uber.org/multierr"
	"os"
	"strings"
)

// Runner creates the required resources for crawling
// and executes the crawl process.
type Runner struct {
	CrawlerOptions *types.CrawlerOptions
	Stdin          bool
	Crawler        engine.Engine
	Options        *types.Options
	State          *RunnerState
	Networkpolicy  *networkpolicy.NetworkPolicy
}

type RunnerState struct {
	InFlightUrls *mapsutil.SyncLockMap[string, struct{}]
}

// Close closes the runner releasing resources
func (r *Runner) Close() error {
	return multierr.Combine(
		r.Crawler.Close(),
		r.CrawlerOptions.Close(),
	)
}

func (r *Runner) SaveState(resumeFilename string) error {
	runnerState := r.State
	data, _ := json.Marshal(runnerState)
	return os.WriteFile(resumeFilename, data, os.ModePerm)
}

// parseInputs parses the inputs returning a slice of URLs
func (r *Runner) parseInputs() []string {
	values := make(map[string]struct{})
	for _, url := range r.Options.URLs {
		if url == "" {
			continue
		}
		value := normalizeInput(url)
		if _, ok := values[value]; !ok {
			values[value] = struct{}{}
		}
	}
	if r.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			value := normalizeInput(scanner.Text())
			if _, ok := values[value]; !ok {
				values[value] = struct{}{}
			}
		}
	}
	final := make([]string, 0, len(values))
	for k := range values {
		final = append(final, k)
	}
	return final
}

func normalizeInput(value string) string {
	return strings.TrimSpace(value)
}

func expandCIDRInputValue(value string) []string {
	var ips []string
	ipsCh, _ := mapcidr.IPAddressesAsStream(value)
	for ip := range ipsCh {
		ips = append(ips, ip)
	}
	return ips
}

func ExpandASNInputValue(value string) []string {
	var ips []string
	cidrs, _ := asn.GetCIDRsForASNNum(value)
	for _, cidr := range cidrs {
		ips = append(ips, expandCIDRInputValue(cidr.String())...)
	}
	return ips
}
