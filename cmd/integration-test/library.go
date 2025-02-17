package main

import (
	"fmt"
	"math"

	"github.com/oneaudit/katana-ng/pkg/engine/standard"
	"github.com/oneaudit/katana-ng/pkg/output"
	"github.com/oneaudit/katana-ng/pkg/types"
	"github.com/oneaudit/katana-ng/pkg/utils/queue"
)

var libraryTestcases = map[string]TestCase{
	"katana-ng as library": &goIntegrationTest{},
}

type goIntegrationTest struct{}

// Execute executes a test case and returns an error if occurred
// Execute the docs at ../README.md if the code stops working for integration.
func (h *goIntegrationTest) Execute() error {
	var crawledURLs []string

	options := &types.Options{
		MaxDepth:     1,
		FieldScope:   "rdn",
		BodyReadSize: math.MaxInt,
		RateLimit:    150,
		Verbose:      debug,
		Strategy:     queue.DepthFirst.String(),
		OnResult: func(r output.Result) {
			crawledURLs = append(crawledURLs, r.Request.URL)
		},
	}
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return err
	}
	defer crawlerOptions.Close()
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return err
	}
	defer crawler.Close()
	var input = "https://public-firing-range.appspot.com"
	err = crawler.Crawl(input)
	if err != nil {
		return err
	}
	if len(crawledURLs) == 0 {
		return fmt.Errorf("no URLs crawled")
	}
	return nil
}
