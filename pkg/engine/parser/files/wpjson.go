package files

import (
	"fmt"
	"github.com/oneaudit/go-wpjson/pkg/engine"
	"io"
	"net/http"
	"strings"

	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type WPJsonCrawler struct {
	httpclient *retryablehttp.Client
}

// Visit visits the provided URL with file crawlers
func (r *WPJsonCrawler) Visit(URL string) ([]*navigation.Request, error) {
	URL = strings.TrimSuffix(URL, "/")
	requestURL := fmt.Sprintf("%s/wp-json/wp/v2/", URL)
	res, err := r.visit(requestURL)
	if err != nil {
		requestURL = fmt.Sprintf("%s?rest_route=/wp/v2/", URL)
		res, err = r.visit(requestURL)
	}
	return res, err
}

func (r *WPJsonCrawler) visit(requestURL string) ([]*navigation.Request, error) {
	req, err := retryablehttp.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, errorutil.NewWithTag("wpjsoncrawler", "could not create request").Wrap(err)
	}
	req.Header.Set("User-Agent", utils.WebUserAgent())

	resp, err := r.httpclient.Do(req)
	if err != nil {
		return nil, errorutil.NewWithTag("wpjsoncrawler", "could not do request").Wrap(err)
	}
	defer resp.Body.Close()

	return r.parseReader(resp.Body, resp)
}

func (r *WPJsonCrawler) parseReader(rr io.Reader, resp *http.Response) (navigationRequests []*navigation.Request, err error) {
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return nil, errorutil.NewWithTag("wpjsoncrawler", "Endpoint /wp-json/ not available")
	}
	content, err := io.ReadAll(rr)
	spec, err := engine.ParseSpecification(content)
	if err != nil {
		return nil, errorutil.NewWithTag("wpjsoncrawler", "could not parse spec").Wrap(err)
	}
	endpoints, err := engine.ParseEndpoints(spec)
	if err != nil {
		return nil, errorutil.NewWithTag("wpjsoncrawler", "could not parse endpoints").Wrap(err)
	}
	for _, endpoint := range endpoints {
		if !endpoint.Builtin {
			navResp := &navigation.Response{
				Depth:      2,
				Resp:       resp,
				StatusCode: resp.StatusCode,
				Headers:    endpoint.Headers,
				Body:       endpoint.Body,
			}
			navRequest := navigation.NewNavigationRequestURLFromResponse(endpoint.URL, resp.Request.URL.String(), "file", "wp-json", navResp)
			navigationRequests = append(navigationRequests, navRequest)
		}
	}

	return
}
