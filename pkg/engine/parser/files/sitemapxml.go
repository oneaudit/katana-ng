package files

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type sitemapXmlCrawler struct {
	httpclient *retryablehttp.Client
}

// Visit visits the provided URL with file crawlers
func (r *sitemapXmlCrawler) Visit(URL string) (navigationRequests []*navigation.Request, err error) {
	URL = strings.TrimSuffix(URL, "/")
	requestURL := fmt.Sprintf("%s/sitemap.xml", URL)
	req, err := retryablehttp.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, errorutil.NewWithTag("sitemapcrawler", "could not create request").Wrap(err)
	}
	req.Header.Set("User-Agent", utils.WebUserAgent())

	resp, err := r.httpclient.Do(req)
	if err != nil {
		return nil, errorutil.NewWithTag("sitemapcrawler", "could not do request").Wrap(err)
	}
	defer resp.Body.Close()

	navigationRequests, err = r.parseReader(resp.Body, resp, URL)
	if err != nil {
		return nil, errorutil.NewWithTag("sitemapcrawler", "could not parse sitemap").Wrap(err)
	}
	return
}

type sitemapStruct struct {
	URLs    []parsedURL `xml:"url"`
	Sitemap []parsedURL `xml:"sitemap"`
}

type parsedURL struct {
	Loc string `xml:"loc"`
}

func (r *sitemapXmlCrawler) parseReader(reader io.Reader, resp *http.Response, baseURL string) (navigationRequests []*navigation.Request, err error) {
	// Add the source to the list
	navRequest := navigation.NewNavigationRequestURLFromResponse(resp.Request.URL.Path, baseURL, "known-files", "sitemapxml", &navigation.Response{
		Depth:      1,
		Resp:       resp,
		StatusCode: resp.StatusCode,
		Headers:    utils.FlattenHeaders(resp.Header),
	})
	navigationRequests = append(navigationRequests, navRequest)

	sitemap := sitemapStruct{}
	if err := xml.NewDecoder(reader).Decode(&sitemap); err != nil {
		return nil, errorutil.NewWithTag("sitemapcrawler", "could not decode xml").Wrap(err)
	}
	for _, url := range sitemap.URLs {
		navResp := &navigation.Response{
			Depth:      2,
			Resp:       resp,
			StatusCode: resp.StatusCode,
			Headers:    utils.FlattenHeaders(resp.Header),
		}
		navigationRequests = append(navigationRequests, navigation.NewNavigationRequestURLFromResponse(strings.Trim(url.Loc, " \t\n"), resp.Request.URL.String(), "file", "sitemapxml", navResp))
	}
	for _, url := range sitemap.Sitemap {
		navResp := &navigation.Response{
			Depth:      2,
			Resp:       resp,
			StatusCode: resp.StatusCode,
			Headers:    utils.FlattenHeaders(resp.Header),
		}
		navigationRequests = append(navigationRequests, navigation.NewNavigationRequestURLFromResponse(strings.Trim(url.Loc, " \t\n"), resp.Request.URL.String(), "file", "sitemapxml", navResp))
	}
	return
}
