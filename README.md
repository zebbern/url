# Web Archive Crawler

This tool allows you to extract archived URLs for specific domains from sources like the Wayback Machine, Common Crawl, and VirusTotal. It's a powerful resource for researchers, security analysts, and developers looking to explore historical or archived data about websites.

## Table of Contents
- [Clone the repository](#Clone-the-repository)
- [Examples](#Examples)
- [Advanced Usage](#Advanced-Usage)


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


# Advanced Usage of `url` for Penetration Testing

A comprehensive guide to maximize the capabilities of the `url` tool in penetration testing workflows. These examples demonstrate advanced commands for recon and exploitation.

---

## 1. Extract URLs Containing Parameters
**Identify URLs with query parameters for further injection testing.**

**Use Case:**  
Locate endpoints potentially vulnerable to SQLi, XSS, or other injection attacks.

```bash
url example.com | grep '?'
```

---

## 2. Filter by File Extensions
**Extract URLs for specific file types such as `.php`, `.aspx`, `.jsp`, or `.txt`.**

**Use Case:**  
Focus on server-side scripts or configuration files for vulnerability analysis.

```bash
url example.com | grep -E '\.(php|aspx|jsp|txt)$'
```

---

## 3. Detect Open Redirects
**Find URLs with redirect-like parameters (`?url=`, `?redirect=`).**

**Use Case:**  
Identify open redirects that can be exploited for phishing or bypasses.

```bash
url example.com | grep -E "redirect=|url="
```

---

## 5. Hunt for Backup and Config Files
**Find URLs ending with backup or configuration file extensions.**

**Use Case:**  
Locate sensitive backup files that might expose credentials or database structures.

```bash
url example.com | grep -E '\.(bak|old|config|cfg|sql|db)$'
```

---

## 6. Enumerate Subdomains
**Identify subdomains from the extracted URLs.**

**Use Case:**  
Discover subdomains for further recon or exploitation.

```bash
url example.com | grep -oP 'https?://\K[^/]*' | sort -u
```

---

## 7. Save URLs for Burp Suite
**Export unique URLs for crawling and fuzzing in Burp Suite.**

**Use Case:**  
Import into Burp Suite for automated scanning.

```bash
url example.com | sort -u > burp_urls.txt
```

---

## 8. Test LFI Vulnerabilities
**Filter URLs for potential Local File Inclusion testing.**

**Use Case:**  
Detect vulnerable endpoints allowing file path manipulation.

```bash
url example.com | grep -E '\.php\?file='
```

---

## 9. Extract Endpoints Containing Login or Admin
**Look for URLs that might indicate sensitive areas of the website.**

**Use Case:**  
Target administrative or authentication endpoints for brute-forcing or bypass attempts.

```bash
url example.com | grep -E 'login|admin'
```

---

## 10. Chain with Other Tools
**Combine `url` output with popular security tools.**

- **Check Live URLs with `httpx`:**
  ```bash
  url example.com | httpx
  ```

- **Identify Patterns with `gf` (GoFindings):**
  ```bash
  url example.com | gf xss
  ```

- **Expand Data with `waybackurls`:**
  ```bash
  url example.com | waybackurls | sort -u
  ```

---

## 11. Automate and Expand Workflow
**Create a Bash script to automate common recon tasks.**

**Use Case:**  
Run a single script to collect multiple data types.

```bash
#!/bin/bash
domain=$1
url $domain | tee urls.txt
url $domain | grep '\.js$' | tee js_files.txt
url $domain | grep -E '\.(php|aspx|jsp)$' | tee scripts.txt
```

---


## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [MSI](LICENSE) file for details.

## Contact

For inquiries, please contact:

- **GitHub**: [zebbern](https://github.com/zebbern)
- inspired by **WayBackURL** by @tomnomnom. 
