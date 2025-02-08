<h1 align="center">
  <img src="https://user-images.githubusercontent.com/8293321/196779266-421c79d4-643a-4f73-9b54-3da379bbac09.png" alt="katana" width="200px">
  <br>
</h1>

<h4 align="center">Fork of <a href="https://github.com/projectdiscovery/katana">katana</a> from Project Discovery.</h4>

## Disable Default Extension Filter

By default, Katana crawls all URLs, but only displays URLs matching the extension filter. While we can use `-em` to add all the extension we want in the results, enable this flag will remove files with no extensions from the output.

```console
FILTER:
   ...
   -ddef, -disable-default-extension-filter  disable the default extension filter
   ...
```

✍️ We will now see `.txt`, `.zip`, etc. files in the output.

## Known Files

Katana supports `robots.txt` and `sitemap.xml`. They are parsed and used to discover new endpoints, but they never appear themselves in the list of valid endpoints.

✍️ We will now see `/robots.txt` and `/sitemap.xml` when they were crawled.