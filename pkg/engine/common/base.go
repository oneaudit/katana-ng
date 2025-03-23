package common

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/oneaudit/katana-ng/pkg/engine/parser"
	"github.com/oneaudit/katana-ng/pkg/engine/parser/files"
	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/output"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/oneaudit/katana-ng/pkg/utils"
	"github.com/oneaudit/katana-ng/pkg/utils/queue"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/remeh/sizedwaitgroup"
)

type Shared struct {
	Headers    map[string]string
	KnownFiles *files.KnownFiles
	Options    *types.CrawlerOptions
}

func NewShared(options *types.CrawlerOptions) (*Shared, error) {
	shared := &Shared{
		Headers: options.Options.ParseCustomHeaders(),
		Options: options,
	}
	if options.Options.KnownFiles != "" {
		httpclient, _, err := BuildHttpClient(options.Dialer, options.Options, nil)
		if err != nil {
			return nil, errorutil.New("could not create http client").Wrap(err)
		}
		shared.KnownFiles = files.New(httpclient, options.Options.KnownFiles)
	}
	return shared, nil
}

func (s *Shared) Enqueue(queue *queue.Queue, navigationRequests ...*navigation.Request) {
	for _, nr := range navigationRequests {
		if nr.URL == "" || !utils.IsURL(nr.URL) {
			continue
		}

		reqUrl := nr.RequestURL()
		if s.Options.Options.IgnoreQueryParams {
			reqUrl = utils.ReplaceAllQueryParam(reqUrl, "")
		}

		// Ignore blank URL items and only work on unique items
		if !s.Options.UniqueFilter.UniqueURL(reqUrl) && len(nr.CustomFields) == 0 {
			continue
		}
		// - URLs stuck in a loop
		if s.Options.UniqueFilter.IsCycle(nr.RequestURL()) {
			continue
		}

		// skip crawling if the endpoint is not in scope
		inScope := s.ValidateScope(nr.URL, nr.RootHostname)
		if !inScope {
			// if the user requested anyway out of scope items
			// they are sent to output without visiting
			if s.Options.Options.DisplayOutScope {
				s.Output(nr, nil, ErrOutOfScope)
			}
			continue
		}

		// Skip adding to the crawl queue when the maximum depth is exceeded
		if nr.Depth > s.Options.Options.MaxDepth {
			continue
		}
		queue.Push(nr, nr.Depth)
	}
}

func (s *Shared) ValidateScope(URL string, root string) bool {
	parsed, err := urlutil.Parse(URL)
	if err != nil {
		gologger.Warning().Msgf("failed to parse url while validating scope: %v", err)
		return false
	}
	scopeValidated, err := s.Options.ScopeManager.Validate(parsed.URL, root)
	return err == nil && scopeValidated
}

func (s *Shared) Output(navigationRequest *navigation.Request, navigationResponse *navigation.Response, err error) {
	var errData string
	if err != nil {
		errData = err.Error()
	}
	// Write the found result to output
	result := &output.Result{
		Timestamp: time.Now(),
		Request:   navigationRequest,
		Response:  navigationResponse,
		Error:     errData,
	}

	outputErr := s.Options.OutputWriter.Write(result)

	if s.Options.Options.OnResult != nil && outputErr == nil {
		s.Options.Options.OnResult(*result)
	}
}

type CrawlSession struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
	URL        *url.URL
	Hostname   string
	Queue      *queue.Queue
	HttpClient *retryablehttp.Client
	Browser    *rod.Browser
}

func (s *Shared) NewCrawlSessionWithURL(URL string) (*CrawlSession, error) {
	ctx, cancel := context.WithCancel(context.Background())
	if s.Options.Options.CrawlDuration.Seconds() > 0 {
		//nolint
		ctx, cancel = context.WithTimeout(ctx, s.Options.Options.CrawlDuration)
	}

	parsed, err := urlutil.Parse(URL)
	if err != nil {
		cancel()
		return nil, errorutil.New("could not parse root URL").Wrap(err)
	}
	hostname := parsed.Hostname()

	queue, err := queue.New(s.Options.Options.Strategy, s.Options.Options.Timeout)
	if err != nil {
		cancel()
		return nil, err
	}
	queue.Push(&navigation.Request{Method: http.MethodGet, URL: URL, Depth: 0, SkipValidation: true}, 0)

	if s.KnownFiles != nil {
		navigationRequests := s.KnownFiles.Request(URL)
		s.Enqueue(queue, navigationRequests...)
	}
	if s.Options.Options.EndpointsFile != "" {
		file, err := os.Open(s.Options.Options.EndpointsFile)
		if err != nil {
			gologger.Warning().Msgf("Could not open endpoint file for %s: %s\n", URL, err.Error())
		} else {
			//goland:noinspection GoUnhandledErrorResult
			defer file.Close()
			// Create navigationRequests
			var navigationRequests []*navigation.Request
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, URL) {
					gologger.Debug().Msgf("Skipping URL (do not match baseURL): %s\n", line)
					continue
				}
				parsedURL, err := url.Parse(line)
				if err != nil {
					gologger.Debug().Msgf("Could not parse URL %s: %s\n", line, err.Error())
					continue
				}

				navigationRequests = append(navigationRequests, &navigation.Request{
					Method:       http.MethodGet,
					URL:          parsedURL.String(),
					RootHostname: hostname,
					Depth:        2,
					Source:       line,
					Attribute:    "line",
					Tag:          "endpoints",
				})
			}
			// Add them to the queue
			s.Enqueue(queue, navigationRequests...)

			// We show warnings for major errors
			if err := scanner.Err(); err != nil {
				gologger.Warning().Msgf("Error during parsing of endpoint file: %s", err.Error())
			}
		}
	}
	httpclient, _, err := BuildHttpClient(s.Options.Dialer, s.Options.Options, func(resp *http.Response, depth int) {
		body, _ := io.ReadAll(resp.Body)
		reader, _ := goquery.NewDocumentFromReader(bytes.NewReader(body))
		var technologyKeys []string
		if s.Options.Wappalyzer != nil {
			technologies := s.Options.Wappalyzer.Fingerprint(resp.Header, body)
			technologyKeys = mapsutil.GetKeys(technologies)
		}
		navigationResponse := &navigation.Response{
			Depth:        depth + 1,
			RootHostname: hostname,
			Resp:         resp,
			Body:         string(body),
			Reader:       reader,
			Technologies: technologyKeys,
			StatusCode:   resp.StatusCode,
			Headers:      utils.FlattenHeaders(resp.Header),
		}
		navigationRequests := parser.ParseResponse(navigationResponse)
		s.Enqueue(queue, navigationRequests...)
	})
	if err != nil {
		cancel()
		return nil, errorutil.New("could not create http client").Wrap(err)
	}
	crawlSession := &CrawlSession{
		Ctx:        ctx,
		CancelFunc: cancel,
		URL:        parsed.URL,
		Hostname:   hostname,
		Queue:      queue,
		HttpClient: httpclient,
	}
	return crawlSession, nil
}

type DoRequestFunc func(crawlSession *CrawlSession, req *navigation.Request) (*navigation.Response, error)

func (s *Shared) Do(crawlSession *CrawlSession, doRequest DoRequestFunc) error {
	wg := sizedwaitgroup.New(s.Options.Options.Concurrency)
	for item := range crawlSession.Queue.Pop() {
		if ctxErr := crawlSession.Ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		req, ok := item.(*navigation.Request)
		if !ok {
			continue
		}

		if !utils.IsURL(req.URL) {
			gologger.Debug().Msgf("`%v` not a url. skipping", req.URL)
			continue
		}

		inScope, scopeErr := s.Options.ValidateScope(req.URL, crawlSession.Hostname)
		if scopeErr != nil {
			gologger.Debug().Msgf("Error validating scope for `%v`: %v. skipping", req.URL, scopeErr)
			continue
		}
		if !req.SkipValidation && !inScope {
			gologger.Debug().Msgf("`%v` not in scope. skipping", req.URL)
			continue
		}

		wg.Add()
		// gologger.Debug().Msgf("Visting: %v", req.URL) // not sure if this is needed
		go func() {
			defer wg.Done()

			s.Options.RateLimit.Take()

			// Delay if the user has asked for it
			if s.Options.Options.Delay > 0 {
				time.Sleep(time.Duration(s.Options.Options.Delay) * time.Second)
			}

			resp, err := doRequest(crawlSession, req)

			// it's dirty but if we tried something and it did not work
			// then, it should not be in the output imo
			// (this should reduce the noise when directories are always empty)
			if inScope && !(req.Tag == "dirb" && resp.StatusCode == 404) {
				s.Output(req, resp, err)
			}

			if err != nil {
				gologger.Warning().Msgf("Could not request seed URL %s: %s\n", req.URL, err)
				outputError := &output.Error{
					Timestamp: time.Now(),
					Endpoint:  req.RequestURL(),
					Source:    req.Source,
					Error:     err.Error(),
				}
				_ = s.Options.OutputWriter.WriteErr(outputError)
				return
			}
			if resp.Resp == nil || resp.Reader == nil {
				return
			}
			if s.Options.Options.DisableRedirects && resp.IsRedirect() {
				return
			}

			navigationRequests := parser.ParseResponse(resp)
			s.Enqueue(crawlSession.Queue, navigationRequests...)
		}()
	}
	wg.Wait()
	return nil
}
