package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/oneaudit/katana-ng/internal/runner"
	"github.com/oneaudit/katana-ng/pkg/api"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	pprofutils "github.com/projectdiscovery/utils/pprof"
	"github.com/rs/xid"
)

var (
	cfgFile string
	options = &types.Options{}
)

func main() {
	flagSet, err := readFlags()
	if err != nil {
		gologger.Fatal().Msgf("Could not read flags: %s\n", err)
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", runner.DoHealthCheck(options, flagSet))
		os.Exit(0)
	}

	katanaRunner, err := runner.New(options)
	if err != nil || katanaRunner == nil {
		if options.Version {
			return
		}
		gologger.Fatal().Msgf("could not create runner: %s\n", err)
	}
	defer katanaRunner.Close()

	// close handler
	resumeFilename := defaultResumeFilename()
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		for range c {
			gologger.DefaultLogger.Info().Msg("- Ctrl+C pressed in Terminal")
			katanaRunner.Close()

			gologger.Info().Msgf("Creating resume file: %s\n", resumeFilename)
			err := katanaRunner.SaveState(resumeFilename)
			if err != nil {
				gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}

			os.Exit(0)
		}
	}()

	var pprofServer *pprofutils.PprofServer
	if options.PprofServer {
		pprofServer = pprofutils.NewPprofServer()
		pprofServer.Start()
	}
	if pprofServer != nil {
		defer pprofServer.Stop()
	}

	if err := katanaRunner.ExecuteCrawling(); err != nil {
		gologger.Fatal().Msgf("could not execute crawling: %s", err)
	}

	// on successful execution:

	// deduplicate the lines in each file in the store-field-dir
	//use options.StoreFieldDir once https://github.com/projectdiscovery/katana/pull/877 is merged
	storeFieldDir := "katana_field"
	_ = folderutil.DedupeLinesInFiles(storeFieldDir)

	// remove the resume file in case it exists
	if fileutil.FileExists(resumeFilename) {
		os.Remove(resumeFilename)
	}

}

func readFlags() (*goflags.FlagSet, error) {
	flagSet := api.MakeFlagSet(options, cfgFile)
	// Add runner specific parameters
	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(runner.GetUpdateCallback(), "update", "up", "update katana-ng to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic katana-ng update check"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not parse flags")
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not read config file")
		}
	}

	cleanupOldResumeFiles()
	return flagSet, nil
}

func init() {
	// show detailed stacktrace in debug mode
	if os.Getenv("DEBUG") == "true" {
		errorutil.ShowStackTrace = true
	}
}

func defaultResumeFilename() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		gologger.Fatal().Msgf("could not get home directory: %s", err)
	}
	configDir := filepath.Join(homedir, ".config", "katana-ng")
	return filepath.Join(configDir, fmt.Sprintf("resume-%s.cfg", xid.New().String()))
}

// cleanupOldResumeFiles cleans up resume files older than 10 days.
func cleanupOldResumeFiles() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		gologger.Fatal().Msgf("could not get home directory: %s", err)
	}
	root := filepath.Join(homedir, ".config", "katana-ng")
	filter := fileutil.FileFilters{
		OlderThan: 24 * time.Hour * 10, // cleanup on the 10th day
		Prefix:    "resume-",
	}
	_ = fileutil.DeleteFilesOlderThan(root, filter)
}
