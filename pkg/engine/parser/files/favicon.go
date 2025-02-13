package files

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type faviconIcoCrawler struct {
	httpclient *retryablehttp.Client
}

// Visit visits the provided URL with file crawlers
func (r *faviconIcoCrawler) Visit(URL string) ([]*navigation.Request, error) {
	URL = strings.TrimSuffix(URL, "/")
	requestURL := fmt.Sprintf("%s/favicon.ico", URL)
	req, err := retryablehttp.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, errorutil.NewWithTag("faviconcrawler", "could not create request").Wrap(err)
	}
	req.Header.Set("User-Agent", utils.WebUserAgent())

	resp, err := r.httpclient.Do(req)
	if err != nil {
		return nil, errorutil.NewWithTag("faviconcrawler", "could not do request").Wrap(err)
	}
	defer resp.Body.Close()

	return r.parseReader(resp.Body, resp, URL)
}

func (r *faviconIcoCrawler) parseReader(_ io.Reader, resp *http.Response, baseURL string) (navigationRequests []*navigation.Request, err error) {
	// Add it to the list
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
		navRequest := navigation.NewNavigationRequestURLFromResponse(resp.Request.URL.Path, baseURL, "known-files", "favicon", &navigation.Response{
			Depth:      1,
			Resp:       resp,
			StatusCode: resp.StatusCode,
			Headers:    utils.FlattenHeaders(resp.Header),
		})
		navigationRequests = append(navigationRequests, navRequest)
	}
	return
}
