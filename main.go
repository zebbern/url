package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// WebURL represents a web URL with an optional date
type WebURL struct {
	Date string
	URL  string
}

// fetchFunction defines the signature for fetcher functions
type fetchFunction func(string, bool, string) ([]WebURL, error)

func main() {
	// Parse command-line flags
	targetFlag := flag.String("t", "", "Target domain or file with list of domains")
	outputFileFlag := flag.String("o", "", "Output file to write results (default: stdout)")
	showDatesFlag := flag.Bool("d", false, "Show date of fetch in the first column")
	noSubdomainsFlag := flag.Bool("n", false, "Don't include subdomains of the target domain")
	getVersionsFlag := flag.Bool("v", false, "List URLs for crawled versions of input URL(s)")
	virusTotalAPIKeyFlag := flag.String("vt", "", "VirusTotal API key for additional URL fetching")
	flag.Usage = customUsage
	flag.Parse()

	// Validate input
	if *targetFlag == "" && flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Error: either -t or a domain argument is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Get list of domains to process
	domains, err := getDomains(*targetFlag, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// If -v flag is set, get versions of the URLs
	if *getVersionsFlag {
		if err := getVersionURLs(domains); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting version URLs: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Fetch URLs using the specified fetch functions
	results, errs := fetchURLs(domains, *noSubdomainsFlag, *virusTotalAPIKeyFlag)

	// Handle any errors encountered during fetching
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "Encountered %d errors while fetching URLs:\n", len(errs))
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		if len(results) == 0 {
			os.Exit(1)
		}
	}

	// Write the fetched URLs to the output
	if err := writeOutput(results, *outputFileFlag, *showDatesFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}
}

// customUsage defines the usage message for the program
func customUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [DOMAIN...]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "A web crawler inspired by WayBackURL by @tomnomnom.\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -d          Show fetch date in first column\n")
	fmt.Fprintf(os.Stderr, "  -t <target> Target domain or file with list of domains\n")
	fmt.Fprintf(os.Stderr, "  -n          Exclude subdomains\n")
	fmt.Fprintf(os.Stderr, "  -o <file>   Output file (default: stdout)\n")
	fmt.Fprintf(os.Stderr, "  -v          List crawled URL versions\n")
	fmt.Fprintf(os.Stderr, "  -vt <key>   VirusTotal API key\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  %s example.com\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -t domains.txt -o results.txt\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -d -n -t example.com\n", os.Args[0])
}

// getDomains retrieves domains from a file or command-line arguments
func getDomains(target string, args []string) ([]string, error) {
	if target != "" {
		if isDomain(target) {
			return []string{target}, nil
		}
		return readDomainsFromFile(target)
	}
	return args, nil
}

// isDomain checks if a string is a valid domain
func isDomain(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, "/")
}

// readDomainsFromFile reads domains from a file, one per line
func readDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return domains, nil
}

// fetchURLs fetches URLs from various sources concurrently
func fetchURLs(domains []string, noSubdomains bool, virusTotalAPIKey string) ([]WebURL, []error) {
	fetchFunctions := []fetchFunction{
		getWaybackURLs,
		getCommonCrawlURLs,
	}

	// Include VirusTotal fetcher if API key is provided
	if virusTotalAPIKey != "" {
		fetchFunctions = append(fetchFunctions, getVirusTotalURLs)
	}

	var results []WebURL
	var errs []error
	var wg sync.WaitGroup
	resultsChan := make(chan []WebURL)
	errorsChan := make(chan error)

	// Use a worker group to fetch URLs concurrently
	for _, domain := range domains {
		for _, fn := range fetchFunctions {
			wg.Add(1)
			go func(d string, f fetchFunction) {
				defer wg.Done()
				resp, err := f(d, noSubdomains, virusTotalAPIKey)
				if err != nil {
					errorsChan <- fmt.Errorf("error fetching URLs for %s: %v", d, err)
					return
				}
				resultsChan <- resp
			}(domain, fn)
		}
	}

	// Close channels when all fetchers are done
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()

	// Collect results and errors
	for resp := range resultsChan {
		results = append(results, resp...)
	}
	for err := range errorsChan {
		errs = append(errs, err)
	}

	return results, errs
}

// writeOutput writes the fetched URLs to the specified output
func writeOutput(results []WebURL, outputFile string, showDates bool) error {
	var writer io.Writer = os.Stdout
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output file: %v", err)
		}
		defer file.Close()
		writer = file
	}

	for _, w := range results {
		if showDates && w.Date != "" {
			d, err := time.Parse("20060102150405", w.Date)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.Date, w.URL)
				continue
			}
			if _, err := fmt.Fprintf(writer, "%s %s\n", d.Format(time.RFC3339), w.URL); err != nil {
				return fmt.Errorf("error writing to output: %v", err)
			}
		} else {
			if _, err := fmt.Fprintln(writer, w.URL); err != nil {
				return fmt.Errorf("error writing to output: %v", err)
			}
		}
	}

	return nil
}

// getVersionURLs retrieves different versions of URLs from the Wayback Machine
func getVersionURLs(domains []string) error {
	for _, u := range domains {
		versions, err := getVersions(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting versions for %s: %v\n", u, err)
			continue
		}
		for _, v := range versions {
			fmt.Println(v)
		}
	}
	return nil
}

// getVersions fetches different archived versions of a URL
func getVersions(u string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s&output=json", u,
	))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var records [][]string
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&records); err != nil {
		return nil, err
	}

	var out []string
	seen := make(map[string]bool)
	for i, record := range records {
		if i == 0 {
			continue // Skip header
		}
		if len(record) < 6 {
			continue // Ensure record has enough fields
		}
		digest := record[5]
		if seen[digest] {
			continue
		}
		seen[digest] = true
		timestamp, originalURL := record[1], record[2]
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", timestamp, originalURL))
	}

	return out, nil
}

// Fetcher functions

// getWaybackURLs fetches URLs from the Wayback Machine
func getWaybackURLs(domain string, noSubdomains bool, _ string) ([]WebURL, error) {
	prefix := "*."
	if noSubdomains {
		prefix = ""
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", prefix, domain)
	res, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching from Wayback Machine: %v", err)
	}
	defer res.Body.Close()

	var records [][]string
	if err := json.NewDecoder(res.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("error parsing Wayback Machine JSON: %v", err)
	}

	var out []WebURL
	for i, record := range records {
		if i == 0 || len(record) < 3 {
			continue // Skip header or incomplete records
		}
		out = append(out, WebURL{Date: record[1], URL: record[2]})
	}

	return out, nil
}

// getCommonCrawlURLs fetches URLs from the Common Crawl index
func getCommonCrawlURLs(domain string, noSubdomains bool, _ string) ([]WebURL, error) {
	prefix := "*."
	if noSubdomains {
		prefix = ""
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", prefix, domain)
	res, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching from Common Crawl: %v", err)
	}
	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	var out []WebURL
	for scanner.Scan() {
		var record struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		out = append(out, WebURL{Date: record.Timestamp, URL: record.URL})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Common Crawl response: %v", err)
	}

	return out, nil
}

// getVirusTotalURLs fetches URLs from VirusTotal if an API key is provided
func getVirusTotalURLs(domain string, noSubdomains bool, apiKey string) ([]WebURL, error) {
	if apiKey == "" {
		return nil, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		apiKey,
		domain,
	)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching from VirusTotal: %v", err)
	}
	defer resp.Body.Close()

	var data struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("error parsing VirusTotal JSON: %v", err)
	}

	var out []WebURL
	for _, u := range data.URLs {
		out = append(out, WebURL{URL: u.URL})
	}

	return out, nil
}
