package runner

import (
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/oneaudit/katana-ng/pkg/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
)

// validateOptions validates the provided options for crawler
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
	gologger.DefaultLogger.SetFormatter(formatter.NewCLI(options.NoColors))
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
