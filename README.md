# Web Archive Crawler

This tool allows you to extract archived URLs for specific domains from sources like the Wayback Machine, Common Crawl, and VirusTotal. It's a powerful resource for researchers, security analysts, and developers looking to explore historical or archived data about websites.

## Features

- Fetch URLs from the Wayback Machine and Common Crawl archives.
- Optional integration with VirusTotal for additional URL data.
- Support for fetching archived versions of specific URLs.
- Exclude subdomains to focus on primary domains.
- Write output to a file or display it in the terminal.
- Show dates of archive snapshots in a human-readable format.

## Installation

### Prerequisites

- Go 1.21 or higher installed on your machine.
- Internet connection to fetch data from archives.

### Steps

1. Clone the repository:

   ```bash
   go install github.com/zebbern/url@latest
   ```

2. Run the tool:

   ```bash
   url [options] [domain...]
   ```

### Options

- `-t <target>`: Target domain or file containing a list of domains (one per line).
- `-o <file>`: Output file to write results (default: stdout).
- `-d`: Show the date of the fetch in the first column of the output.
- `-n`: Exclude subdomains of the target domain.
- `-v`: List different versions of URLs (from the Wayback Machine).
- `-vt <key>`: VirusTotal API key for fetching additional URLs.

### Examples

1. **Fetch URLs for a single domain**:

   ```bash
   url example.com
   ```

2. **Fetch URLs from a file of domains and write to an output file**:

   ```bash
   url -t domains.txt -o results.txt
   ```

3. **Fetch URLs without subdomains and show fetch dates**:

   ```bash
   url -d -n -t example.com
   ```

4. **List archived versions of URLs**:

   ```bash
   url -v example.com
   ```

5. **Fetch URLs including VirusTotal data**:

   ```bash
   url -vt YOUR_API_KEY -t example.com
   ```

## API Key Setup for VirusTotal

To fetch URLs from VirusTotal, you need an API key. You can obtain one by signing up at [VirusTotal](https://www.virustotal.com/gui/join-us). Use the key with the `-vt` option:

```bash
url -vt YOUR_API_KEY -t example.com
```

## Output Format

- **With Dates**: Each line includes the fetch date in RFC3339 format followed by the URL.
- **Without Dates**: Only the URLs are displayed.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [MSI](LICENSE) file for details.

## Contact

For inquiries, please contact:

- **GitHub**: [zebbern](https://github.com/zebbern)
- inspired by **WayBackURL** by @tomnomnom. 
