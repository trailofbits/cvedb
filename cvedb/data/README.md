# NVD Data Feeds

These are data feeds from the [National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds)
used to pre-seed CVEdb without requiring a network connection on the first run.

The installed snapshot uses the legacy NVD 1.1 format and filenames, covering
2002–2021 with partial 2021 data. Bundled feed changes are separate data updates.

For staging an upstream snapshot, run `bash path/to/download.sh` from a separate
output directory. The helper downloads matching NVD 2.0 `.meta` and `.json.gz`
pairs for 2002 through the current year and stops on download errors. Its NVD 2.0
filenames do not replace the installed legacy bundles automatically. Use
`cvedb --update` to explicitly refresh a runtime database through the supported
NVD 2.0 feed loader. The separate NVD API client remains tracked in
[issue #3](https://github.com/trailofbits/cvedb/issues/3).

## License

According to Title 17 of the United States Code, all NIST publications including these feeds are in the
public domain.
