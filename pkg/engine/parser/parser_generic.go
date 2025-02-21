//go:build !(386 || windows)

package parser

import (
	"fmt"
	"github.com/BishopFox/jsluice"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/oneaudit/katana-ng/pkg/utils"
)

func InitWithOptions(options *types.Options) {
	if options.AutomaticFormFill {
		responseParsers = append(responseParsers, responseParser{bodyParser, bodyFormTagParser})
	}
	if options.ScrapeJSLuiceResponses {
		responseParsers = append(responseParsers, responseParser{bodyParser, scriptContentJsluiceParser})
		responseParsers = append(responseParsers, responseParser{contentParser, scriptJSFileJsluiceParser})
	}
	if options.ScrapeJSResponses {
		responseParsers = append(responseParsers, responseParser{bodyParser, scriptContentRegexParser})
		responseParsers = append(responseParsers, responseParser{contentParser, scriptJSFileRegexParser})
		responseParsers = append(responseParsers, responseParser{contentParser, bodyScrapeEndpointsParser})
	}
	if !options.DisableRedirects {
		responseParsers = append(responseParsers, responseParser{headerParser, headerLocationParser})
	}
	if options.InvestigateDirectories {
		responseParsers = append(responseParsers, responseParser{urlParser, urlPathsParser})
	}
}

// scriptContentJsluiceParser parses script content endpoints using jsluice from response
func scriptContentJsluiceParser(resp *navigation.Response) (navigationRequests []*navigation.Request) {
	resp.Reader.Find("script").Each(func(i int, item *goquery.Selection) {
		text := item.Text()
		if text == "" {
			return
		}

		endpointItems := utils.ExtractJsluiceEndpoints(text)
		for _, item := range endpointItems {
			navigationRequests = append(navigationRequests, NewNavigationRequestURLFromJavaScriptEndpoint(item, resp.Resp.Request.URL.String(), "script", fmt.Sprintf("jsluice-%s", item.Type), resp))
		}
	})
	return
}

// scriptJSFileJsluiceParser parses endpoints using jsluice from js file pages
func scriptJSFileJsluiceParser(resp *navigation.Response) (navigationRequests []*navigation.Request) {
	// Only process javascript file based on path or content type
	// CSS, JS are supported for relative endpoint extraction.
	contentType := resp.Resp.Header.Get("Content-Type")
	if !(strings.HasSuffix(resp.Resp.Request.URL.Path, ".js") || strings.HasSuffix(resp.Resp.Request.URL.Path, ".css") || strings.Contains(contentType, "/javascript")) {
		return
	}
	// Skip common js libraries
	if utils.IsPathCommonJSLibraryFile(resp.Resp.Request.URL.Path) {
		return
	}

	endpointsItems := utils.ExtractJsluiceEndpoints(string(resp.Body))
	for _, item := range endpointsItems {
		navigationRequests = append(navigationRequests, NewNavigationRequestURLFromJavaScriptEndpoint(item, resp.Resp.Request.URL.String(), "js", fmt.Sprintf("jsluice-%s", item.Type), resp))
	}
	return
}

func NewNavigationRequestURLFromJavaScriptEndpoint(item *jsluice.URL, source, tag, attribute string, resp *navigation.Response) *navigation.Request {
	requestURL := resp.AbsoluteURL(item.URL)

	var request *navigation.Request
	if item.Method == "" {
		item.Method = http.MethodGet
	}

	// Add Query Params To The URL
	if len(item.QueryParams) > 0 {
		parsedURL, err := url.Parse(requestURL)
		if err == nil {
			query := parsedURL.Query()
			for _, param := range item.QueryParams {
				query.Set(param, "katana")
			}
			parsedURL.RawQuery = query.Encode()
			requestURL = parsedURL.String()
		}
	}

	request = &navigation.Request{
		Method:       item.Method,
		URL:          requestURL,
		RootHostname: resp.RootHostname,
		Depth:        resp.Depth,
		Source:       source,
		Attribute:    attribute,
		Tag:          tag,
		Headers:      item.Headers,
	}

	return request
}
