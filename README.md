<h1 align="center">
  <img src="https://user-images.githubusercontent.com/8293321/196779266-421c79d4-643a-4f73-9b54-3da379bbac09.png" alt="katana" width="200px">
  <br>
</h1>

<h4 align="center">Fork of <a href="https://github.com/projectdiscovery/katana">katana</a> from Project Discovery.</h4>

## Disable Default Extension Filter

By default, Katana crawls all URLs but only displays URLs matching the extension filter. You can tune this filtering with `-em` and `-ef` flags, but there is no flag to match all extensions, as many are filtered by default.

Another issue is that when using `-em`, files with no extension are filtered.

```console
FILTER:
   ...
   -ddef, -disable-default-extension-filter  disable the default extension filter
   ...
```

✍️ With `-ddef`, you will now see `.txt`, `.zip`, and other file types in the output without using `-em`.

## Investigate Directories

By default, Katana doesn't investigate directories in a URL path. For example, if the crawler detects the URL `/assets/img/image.jpg`, it won't investigate `/assets` or `/assets/img/` unless those directories are explicitly listed. While this behavior is expected, you can modify it using the following flag:

```console
SCOPE:
   ...
   -id, -investigate-directories  enable inspection of all directories in a path
   ...
```

✍️ With this flag, folders such as `/assets/` and `/assets/img/` will be crawled. However, note that these folders will not appear in the output if the response status code was `404`.

## JSLuice Improved Support

Katana integrates with the [jsluice](https://github.com/BishopFox/jsluice) tool, which can only be compiled on Linux. It is executed on both embedded script tags and external files when using the `-jsluice` flag. Katana only used part of the output from JSLuice, ignoring HTTP methods and headers detected by the tool.

✍️ Katana-ng makes full use of the information returned by JSLuice, crawling detected endpoints using the correct HTTP methods and headers.

## Katana Output Options

Katana uses the same output format for both the output file and stdout. While this ensures consistency, it can make the output messy when using `-jsonl`. To address this, we’ve added an option for users who need to check the crawled URLs in stdout without cluttering the console with JSON lines.

```console
FILTER:
   ...
   -kss, -keep-stdout-simple   Keep stdout/logs clean and simple, even when the output file format is JSON.
   ...
```

✍️ This option ensures a cleaner stdout while still allowing you to store the output in JSON format.

## Known Files

Katana supports `robots.txt` and `sitemap.xml`. These are parsed to discover new endpoints. We added `/wp-json/` for WordPress websites, and `favicon.ico` for favicon fingerprinting.

Katana current behavior is to abort all remaining known files when there is one error, such as when there is no `sitemap.xml` file.

* [x] Robots.txt
* [x] Sitemap.xml
* [x] Favicon.ico
* [x] WP JSON

✍️ We will now see known files that were detected during crawling. If we cannot parse a known file, we will attempt other known files. New endpoints were added.

## Additional Endpoints

We added a feature that allows users to specify additional endpoints to crawl. This is particularly useful for integrating results from other tools, such as [feroxbuster](https://github.com/epi052/feroxbuster), into your crawling process. This feature supports junk lines, meaning that any non-URL lines in the file will be ignored, allowing for flexibility in your input files.

```console
INPUT:
    ...
    -endpoints string   additional endpoints to crawl (ex: one URL per line, junk lines allowed)
    ...
```

✍️ With the `-endpoints` flag, you can provide a file containing a list of URLs, one per line, which are added to the list of URLs to crawl.

## Simplified Usage As A Library

Most of Katana logic is stored inside the `internal` package, making it hard for users to smoothly use the library in their project. Aside from the cancel/resume feature, the `RunKatana` function for `nuclei-ng` do the following:

* ✅ Parse a configuration file to update Options
* ✅ Parse the form configuration file for automatic form filling
* ✅ Validate the crawler configuration
* ✅ Initialize specific parsers such as `jsluice`
* ✅ Select the crawler type based on options
* ✅ Parses and handle a list of URLs

As a side note, you can achieve a part of it by using this [snippet](https://github.com/projectdiscovery/katana?tab=readme-ov-file#katana-as-a-library).

```go
package main

import (
    "github.com/oneaudit/katana-ng/pkg/api"
    "github.com/oneaudit/katana-ng/pkg/types"
    "github.com/projectdiscovery/gologger"
)

func main() {
    options := &types.Options{
        RateLimit:     150,
        Timeout:       5,
        URLs: []string{
            "https://example.com",
        },
        OutputFile: "output.txt",
    }
    options.ConfigureOutput() // logging
    err := api.RunKatana(options, "")
    if err != nil {
        gologger.Fatal().Msgf("Could not crawl: %v", err.Error())
    }
}

```

## Minor Changes

* 😄 We can omit non-HTML responses with `-onh` or `-omit-non-html`
* ⚠️ Adding additional data (status code, body and headers) for duplicate responses