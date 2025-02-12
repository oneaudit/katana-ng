<h1 align="center">
  <img src="https://user-images.githubusercontent.com/8293321/196779266-421c79d4-643a-4f73-9b54-3da379bbac09.png" alt="katana" width="200px">
  <br>
</h1>

<h4 align="center">Fork of <a href="https://github.com/projectdiscovery/katana">katana</a> from Project Discovery.</h4>

## Disable Default Extension Filter

By default, Katana crawls all URLs but only displays URLs matching the extension filter. We can tune this filtering with `-em` and `-ef`, but there is no flag to match all extensions as many are filtered by default.

```console
FILTER:
   ...
   -ddef, -disable-default-extension-filter  disable the default extension filter
   ...
```

✍️ We will now see `.txt`, `.zip`, etc. files in the output when using `-ddef`.

## Investigate Directories

By default, Katana doesn't investigate directories in a path. If the crawler detected the following URL: `/assets/img/image.jpg`, it won't investigate `/assets` or `/assets/img/` which may have directory listing enabled. While this behavior is fair, we added a flag if you want the crawler to behave differently.

```console
SCOPE:
   ...
   -id, -investigate-directories  enable inspection of all directories in a path
   ...
```

✍️ Folders `/assets/`, `/assets/img/`, etc. will be crawled and shown in the output. By design, they will be shown in the output even if it's 403 or 404.

## JSLuice Improved Support

The [jsluice](https://github.com/BishopFox/jsluice) tool is only available on Linux, by design, and it will still only work on Linux. Katana runs it on embed script tags and external files when using `-jsluice`. The main issue was that only a part of JSLuice output was used. Headers or HTTP methods detected by the tool were ignored by katana.

✍️ Katana-ng will properly make use of information returned by JSLuice to crawl detected endpoints using correct HTTP methods and headers.

## Known Files

Katana supports `robots.txt` and `sitemap.xml`. They are parsed and used to discover new endpoints, but they never appear themselves in the list of valid endpoints.

* [x] Robots.txt
* [x] Sitemap.xml
* [ ] ...

✍️ We will now see `/robots.txt` and `/sitemap.xml` when they were crawled.