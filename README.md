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

✍️ With this flag, folders such as `/assets/` and `/assets/img/` will be crawled. However, note that these folders will still appear in the output, even if they couldn't be crawled due to errors like `403` or `404`.

## JSLuice Improved Support

Katana integrates with the [jsluice](https://github.com/BishopFox/jsluice) tool, which can only be compiled on Linux. It is executed on both embedded script tags and external files when using the `-jsluice` flag. Katana only used part of the output from JSLuice, ignoring HTTP methods and headers detected by the tool.

✍️ Katana-ng makes full use of the information returned by JSLuice, crawling detected endpoints using the correct HTTP methods and headers.

## Known Files

Katana supports `robots.txt` and `sitemap.xml`. These are parsed to discover new endpoints but are never included in the list of valid endpoints.

* [x] Robots.txt
* [x] Sitemap.xml
* [ ] ...

✍️ We will now see `/robots.txt` and `/sitemap.xml` when they were crawled.