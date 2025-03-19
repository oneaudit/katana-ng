package runner

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

var banner = `
   __        __                
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/ NG							 
`

var version = "v1.1.0"

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\toneaudit\n\n")
}

// GetUpdateCallback returns a callback function that updates katana
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("katana-ng", version)()
	}
}
