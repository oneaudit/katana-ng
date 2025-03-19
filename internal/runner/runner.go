package runner

import (
	"encoding/json"
	"github.com/oneaudit/katana-ng/pkg/api"
	"os"
	"strconv"

	"github.com/oneaudit/katana-ng/pkg/engine"
	"github.com/oneaudit/katana-ng/pkg/engine/hybrid"
	"github.com/oneaudit/katana-ng/pkg/engine/parser"
	"github.com/oneaudit/katana-ng/pkg/engine/standard"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/networkpolicy"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	mapsutil "github.com/projectdiscovery/utils/maps"
	updateutils "github.com/projectdiscovery/utils/update"
)

// New returns a new crawl runner structure
func New(options *types.Options) (*api.Runner, error) {
	// create the resume configuration structure
	if options.ShouldResume() {
		gologger.Info().Msg("Resuming from save checkpoint")

		file, err := os.ReadFile(options.Resume)
		if err != nil {
			return nil, err
		}

		runnerState := &api.RunnerState{}
		err = json.Unmarshal(file, runnerState)
		if err != nil {
			return nil, err
		}
		options.URLs = mapsutil.GetKeys(runnerState.InFlightUrls.GetAll())
	}
	options.ConfigureOutput()
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current version: %s", version)
		return nil, nil
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("katana-ng", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("katana-ng version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current katana-ng version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if err := initExampleFormFillConfig(); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not init default config")
	}
	if err := validateOptions(options); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not validate options")
	}
	if options.FormConfig != "" {
		if err := readCustomFormConfig(options.FormConfig); err != nil {
			return nil, err
		}
	}
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create crawler options")
	}

	parser.InitWithOptions(options)

	var crawler engine.Engine

	switch {
	case options.Headless:
		crawler, err = hybrid.New(crawlerOptions)
	default:
		crawler, err = standard.New(crawlerOptions)
	}
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create standard crawler")
	}

	var npOptions networkpolicy.Options

	for _, exclude := range options.Exclude {
		switch {
		case exclude == "cdn":
			//implement cdn check in netoworkpolicy pkg??
			continue
		case exclude == "private-ips":
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv4Denylist...)
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv4DenylistRanges...)
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv6Denylist...)
			npOptions.DenyList = append(npOptions.DenyList, networkpolicy.DefaultIPv6DenylistRanges...)
		case iputil.IsCIDR(exclude):
			npOptions.DenyList = append(npOptions.DenyList, exclude)
		case asn.IsASN(exclude):
			// update this to use networkpolicy pkg once https://github.com/projectdiscovery/networkpolicy/pull/55 is merged
			ips := api.ExpandASNInputValue(exclude)
			npOptions.DenyList = append(npOptions.DenyList, ips...)
		case iputil.IsPort(exclude):
			port, _ := strconv.Atoi(exclude)
			npOptions.DenyPortList = append(npOptions.DenyPortList, port)
		default:
			npOptions.DenyList = append(npOptions.DenyList, exclude)
		}
	}

	np, _ := networkpolicy.New(npOptions)
	runner := &api.Runner{
		Options:        options,
		Stdin:          fileutil.HasStdin(),
		CrawlerOptions: crawlerOptions,
		Crawler:        crawler,
		State:          &api.RunnerState{InFlightUrls: mapsutil.NewSyncLockMap[string, struct{}]()},
		Networkpolicy:  np,
	}

	return runner, nil
}
