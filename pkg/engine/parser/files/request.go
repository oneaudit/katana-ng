package files

import (
	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
)

type visitFunc func(URL string) ([]*navigation.Request, error)

type KnownFiles struct {
	parsers    []visitFunc
	httpclient *retryablehttp.Client
}

// New returns a new known files parser instance
func New(httpclient *retryablehttp.Client, files string) *KnownFiles {
	parser := &KnownFiles{
		httpclient: httpclient,
	}
	switch files {
	case "robotstxt":
		crawler := &robotsTxtCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, crawler.Visit)
	case "sitemapxml":
		crawler := &sitemapXmlCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, crawler.Visit)
	case "favicon":
		crawler := &faviconIcoCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, crawler.Visit)
	case "wpjson":
		crawler := &WPJsonCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, crawler.Visit)
	default:
		robots := &robotsTxtCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, robots.Visit)
		sitemap := &sitemapXmlCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, sitemap.Visit)
		favicon := &faviconIcoCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, favicon.Visit)
		wpjson := &WPJsonCrawler{httpclient: httpclient}
		parser.parsers = append(parser.parsers, wpjson.Visit)
	}
	return parser
}

// Request requests all known files with visitors
func (k *KnownFiles) Request(URL string) (navigationRequests []*navigation.Request) {
	for _, visitor := range k.parsers {
		navRequests, err := visitor(URL)
		if err != nil {
			gologger.Warning().Msgf("Could not parse known files for %s: %s\n", URL, err)
			continue
		}
		navigationRequests = append(navigationRequests, navRequests...)
	}
	return
}
