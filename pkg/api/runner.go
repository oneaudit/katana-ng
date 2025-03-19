package api

import (
	"bufio"
	"github.com/oneaudit/katana-ng/pkg/engine"
	"github.com/oneaudit/katana-ng/pkg/engine/hybrid"
	"github.com/oneaudit/katana-ng/pkg/engine/parser"
	"github.com/oneaudit/katana-ng/pkg/engine/standard"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/oneaudit/katana-ng/pkg/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/networkpolicy"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func RunKatana(options *types.Options, cfgFile string) error {
	// Configuration
	flagSet := MakeFlagSet(options, cfgFile)
	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return errorutil.NewWithErr(err).Msgf("could not read config file")
		}
	}
	if err := initExampleFormFillConfig(); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not init default config")
	}
	if err := validateOptions(options); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not validate options")
	}
	if options.FormConfig != "" {
		if err := readCustomFormConfig(options.FormConfig); err != nil {
			return err
		}
	}
	// Initialization
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not create crawler options")
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
		return errorutil.NewWithErr(err).Msgf("could not create standard crawler")
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
		case iputil.IsPort(exclude):
			port, _ := strconv.Atoi(exclude)
			npOptions.DenyPortList = append(npOptions.DenyPortList, port)
		default:
			npOptions.DenyList = append(npOptions.DenyList, exclude)
		}
	}

	np, _ := networkpolicy.New(npOptions)
	katanaRunner := &runner{
		options:        options,
		stdin:          false,
		crawlerOptions: crawlerOptions,
		crawler:        crawler,
		networkpolicy:  np,
	}
	if katanaRunner == nil {
		gologger.Fatal().Msgf("could not create runner: %s\n", err)
		return nil
	}
	defer katanaRunner.Close()
	if err := katanaRunner.ExecuteCrawling(); err != nil {
		gologger.Fatal().Msgf("could not execute crawling: %s", err)
	}

	return nil
}

type runner struct {
	crawlerOptions *types.CrawlerOptions
	stdin          bool
	crawler        engine.Engine
	options        *types.Options
	networkpolicy  *networkpolicy.NetworkPolicy
}

func (r *runner) Close() error {
	return multierr.Combine(
		r.crawler.Close(),
		r.crawlerOptions.Close(),
	)
}

func (r *runner) ExecuteCrawling() error {
	if r.crawler == nil {
		return errorutil.New("crawler is not initialized")
	}
	inputs := r.parseInputs()
	if len(inputs) == 0 {
		return errorutil.New("no input provided for crawling")
	}

	defer r.crawler.Close()

	wg := sizedwaitgroup.New(r.options.Parallelism)
	for _, input := range inputs {
		if !r.networkpolicy.Validate(input) {
			gologger.Info().Msgf("Skipping excluded host %s", input)
			continue
		}
		wg.Add()
		input = addSchemeIfNotExists(input)
		go func(input string) {
			defer wg.Done()

			if err := r.crawler.Crawl(input); err != nil {
				gologger.Warning().Msgf("Could not crawl %s: %s", input, err)
			}
		}(input)
	}
	wg.Wait()
	return nil
}

// scheme less urls are skipped and are required for headless mode and other purposes
// this method adds scheme if given input does not have any
func addSchemeIfNotExists(inputURL string) string {
	if strings.HasPrefix(inputURL, urlutil.HTTP) || strings.HasPrefix(inputURL, urlutil.HTTPS) {
		return inputURL
	}
	parsed, err := urlutil.Parse(inputURL)
	if err != nil {
		gologger.Warning().Msgf("input %v is not a valid url got %v", inputURL, err)
		return inputURL
	}
	if parsed.Port() != "" && (parsed.Port() == "80" || parsed.Port() == "8080") {
		return urlutil.HTTP + urlutil.SchemeSeparator + inputURL
	} else {
		return urlutil.HTTPS + urlutil.SchemeSeparator + inputURL
	}
}

func (r *runner) parseInputs() []string {
	values := make(map[string]struct{})
	for _, url := range r.options.URLs {
		if url == "" {
			continue
		}
		value := normalizeInput(url)
		if _, ok := values[value]; !ok {
			values[value] = struct{}{}
		}
	}
	if r.stdin {
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

func validateOptions(options *types.Options) error {
	if options.MaxDepth <= 0 && options.CrawlDuration.Seconds() <= 0 {
		return errorutil.New("either max-depth or crawl-duration must be specified")
	}
	if len(options.URLs) == 0 && !fileutil.HasStdin() {
		return errorutil.New("no inputs specified for crawler")
	}

	// Disabling automatic form fill (-aff) for headless navigation due to incorrect implementation.
	// Form filling should be handled via headless actions within the page context
	if options.Headless && options.AutomaticFormFill {
		options.AutomaticFormFill = false
		gologger.Info().Msgf("Automatic form fill (-aff) has been disabled for headless navigation.")
	}

	if (options.HeadlessOptionalArguments != nil || options.HeadlessNoSandbox || options.SystemChromePath != "") && !options.Headless {
		return errorutil.New("headless mode (-hl) is required if -ho, -nos or -scp are set")
	}
	if options.SystemChromePath != "" {
		if !fileutil.FileExists(options.SystemChromePath) {
			return errorutil.New("specified system chrome binary does not exist")
		}
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}
	for _, mr := range options.OutputMatchRegex {
		cr, err := regexp.Compile(mr)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("Invalid value for match regex option")
		}
		options.MatchRegex = append(options.MatchRegex, cr)
	}
	for _, fr := range options.OutputFilterRegex {
		cr, err := regexp.Compile(fr)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("Invalid value for filter regex option")
		}
		options.FilterRegex = append(options.FilterRegex, cr)
	}
	if options.KnownFiles != "" && options.MaxDepth < 3 {
		gologger.Info().Msgf("Depth automatically set to 3 to accommodate the `--known-files` option (originally set to %d).", options.MaxDepth)
		options.MaxDepth = 3
	}
	return nil
}

// readCustomFormConfig reads custom form fill config
func readCustomFormConfig(formConfig string) error {
	file, err := os.Open(formConfig)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not read form config")
	}
	defer file.Close()

	var data utils.FormFillData
	if err := yaml.NewDecoder(file).Decode(&data); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not decode form config")
	}
	utils.FormData = data
	return nil
}

func initExampleFormFillConfig() error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not get home directory")
	}
	defaultConfig := filepath.Join(homedir, ".config", "katana-ng", "form-config.yaml")

	if fileutil.FileExists(defaultConfig) {
		return readCustomFormConfig(defaultConfig)
	}
	if err := os.MkdirAll(filepath.Dir(defaultConfig), 0775); err != nil {
		return err
	}
	exampleConfig, err := os.Create(defaultConfig)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not get home directory")
	}
	defer exampleConfig.Close()

	err = yaml.NewEncoder(exampleConfig).Encode(utils.DefaultFormFillData)
	return err
}
