package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	reqFile     = flag.String("r", "", "Request file.")
	payloadFile = flag.String("p", "", "Payload file.")
	proxyAddr   = flag.String("x", "", "Use http proxy (http://127.0.0.1:8080)")
	workers     = 50
	client      *http.Client
)

func main() {
	flag.Parse()

	if *reqFile == "" || *payloadFile == "" {
		fmt.Println("Usage: go run xssfury.go -r req.txt -p payloads.txt [-x http://127.0.0.1:8080]")
		return
	}

	if *proxyAddr != "" {
		proxyURL, err := url.Parse(*proxyAddr)
		if err != nil {
			fmt.Println("Bad proxy address:", err)
			return
		}
		transport := &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			DisableKeepAlives:   true,
		}
		client = &http.Client{Transport: transport}
	} else {
		client = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				DisableKeepAlives:   true,
			},
		}
	}

	template := readFile(*reqFile)
	payloads := readLines(*payloadFile)

	var wg sync.WaitGroup
	jobs := make(chan string, len(payloads))

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				sendRequest(template, payload)
			}
		}()
	}

	for _, p := range payloads {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines
}

func sendRequest(template, payload string) {
	modified := strings.ReplaceAll(template, "§", payload)

	var parts []string
	if strings.Contains(modified, "\r\n\r\n") {
		parts = strings.SplitN(modified, "\r\n\r\n", 2)
	} else if strings.Contains(modified, "\n\n") {
		parts = strings.SplitN(modified, "\n\n", 2)
	} else {
		fmt.Println("Body of request is wrong. Not found endline separators.")
		return
	}

	headersRaw := parts[0]
	body := parts[1]

	reader := bufio.NewReader(strings.NewReader(headersRaw))
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	reqParts := strings.Split(line, " ")
	if len(reqParts) < 2 {
		fmt.Println("Bad request startline.")
		return
	}

	method := reqParts[0]
	path := reqParts[1]

	req, err := http.NewRequest(method, "", strings.NewReader(body))
	if err != nil {
		fmt.Println("Error of request creation:", err)
		return
	}

	host := ""
	for {
		hline, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(hline) == "" {
			break
		}
		hparts := strings.SplitN(hline, ":", 2)
		if len(hparts) == 2 {
			key := strings.TrimSpace(hparts[0])
			val := strings.TrimSpace(hparts[1])
			keyLower := strings.ToLower(key)
			switch keyLower {
			case "host":
				host = val
				req.Host = val
			case "content-length":
			default:
				req.Header.Set(key, val)
			}
		}
	}

	if host == "" {
		fmt.Println("No Host: header in reqest file, I cannot build URL.")
		return
	}

	req.URL, err = url.Parse("http://" + host + path)
	if err != nil {
		fmt.Println("Error during URL parsing:", err)
		return
	}

	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
