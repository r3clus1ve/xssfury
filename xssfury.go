package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// ------------------ PAYLOAD MARKER -----------------

const marker = "§here§"

// ------------------ ALIAS MAP ----------------------

var aliasMap = map[string]string{
	"-r": "--request",
	"-x": "--proxy",
	"-k": "--insecure",
	"-e": "--encode",
	"-b": "--browser-check",
	"-t": "--timeout",
	"-c": "--checktime",
	"-w": "--threads",
	"-p": "--payloads",
	"-a": "--alerts-only",
}

// ------------------ ALIAS MAP NORMALIZER ----------

func normalizeArgs() {
	args := []string{os.Args[0]}
	for _, a := range os.Args[1:] {
		if v, ok := aliasMap[a]; ok {
			args = append(args, v)
		} else {
			args = append(args, a)
		}
	}
	os.Args = args
}

// ------------------ HELP STRUCTURE ---------------

func displayhelp() {
	fmt.Println()
	fmt.Println("XSSFURY 1.0. Automatic XSS fuzzer from raw HTTP requests.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("--request, -r       		path to a raw HTTP request file containing the §here§ marker")
	fmt.Println("--encode, -e        		URL encode payloads")
	fmt.Println("--browser-check, -b 		enable headless browser alert detection")
	fmt.Println("--timeout, -t       		browser check timeout (default 5s)")
	fmt.Println("--checktime, -c     		time in seconds to wait for an alert during browser checks")
	fmt.Println("--threads, -w           	number of concurrent workers (default 4)")
	fmt.Println("--insecure, -k      		skip TLS certificate verification (insecure)")
	fmt.Println("--payloads, -p				provide payload file (default payloads.log)")
	fmt.Println("--proxy, -x         		optional HTTP proxy, e.g. http://127.0.0.1:8080")
	fmt.Println("--alerts-only, -a         	displaying only payloads that triggered alerts in browser checks")
}

// ------------------ GET PAYLOADS -----------------

func getPayloads(file string) ([]string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file %s: %w", file, err)
	}
	var payloads []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "---") {
			continue
		}
		line = strings.Trim(line, "` ")
		payloads = append(payloads, line)
	}
	if len(payloads) == 0 {
		return nil, fmt.Errorf("failed to read payload file: no payloads inside or file is corrupted")
	}
	return payloads, nil
}

// ------------------ ENCODE PAYLOADS OR NOT ---------

func encodeOrNot(s string, encode bool) string {
	if encode {
		return url.QueryEscape(s)
	}
	return s
}

// ------------------ REQUEST/RESPONSE ---------------

func sendRequest(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 1<<20)
	return io.ReadAll(limited)
}

// ------------------ REFLECTION CHECK --------------

func checkReflection(body []byte, payload string) bool {
	s := string(body)
	return strings.Contains(s, payload) || strings.Contains(s, url.QueryEscape(payload))
}

func checkWithBrowser(url string, timeout time.Duration) (bool, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("disable-logging", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	triggered := false
	inner, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := chromedp.Run(inner, page.Enable()); err != nil {
		return false, err
	}
	chromedp.ListenTarget(inner, func(ev any) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			triggered = true
			_ = chromedp.Run(inner, chromedp.ActionFunc(func(ctx context.Context) error {
				return page.HandleJavaScriptDialog(true).Do(ctx)
			}))
			cancel()
		}
	})
	err := chromedp.Run(inner, chromedp.Navigate(url))
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return false, err
	}
	return triggered, nil
}

// ------------------ YESNO FORMATTER ----------------

func yesno(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// ------------------ RAW REQUEST TEMPLATE -----------

type RawRequestTemplate struct {
	Method  string
	Scheme  string
	Host    string
	Path    string
	Headers map[string][]string
	Body    string
}

// ------------------ REQUEST PARSER -----------------

func parseRawRequest(data string) (*RawRequestTemplate, error) {
	data = strings.ReplaceAll(data, "\r\n", "\n")
	lines := strings.Split(data, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}
	first := strings.TrimSpace(lines[0])
	parts := strings.SplitN(first, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %q", first)
	}
	method := strings.ToUpper(parts[0])
	path := parts[1]
	scheme := "http"
	host := ""
	headers := make(map[string][]string)
	i := 1
	for ; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			i++
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if strings.EqualFold(key, "Host") {
			host = val
		}
		if strings.EqualFold(key, "Referer") && scheme == "http" {
			if strings.HasPrefix(val, "https://") {
				scheme = "https"
			} else if strings.HasPrefix(val, "http://") {
				scheme = "http"
			}
		}
		headers[key] = append(headers[key], val)
	}
	if host == "" {
		return nil, fmt.Errorf("missing Host header in raw request")
	}
	body := ""
	if i < len(lines) {
		body = strings.Join(lines[i:], "\n")
	}
	return &RawRequestTemplate{
		Method:  method,
		Scheme:  scheme,
		Host:    host,
		Path:    path,
		Headers: headers,
		Body:    body,
	}, nil
}

// ------------------ REQUEST BUILD -----------------

func buildRawRequest(tmpl *RawRequestTemplate, payload string, encode bool) (*http.Request, string, string, error) {
	replacedPath := strings.Replace(tmpl.Path, marker, encodeOrNot(payload, encode), 1)
	replacedBody := strings.Replace(tmpl.Body, marker, encodeOrNot(payload, encode), 1)
	finalURL := fmt.Sprintf("%s://%s%s", tmpl.Scheme, tmpl.Host, replacedPath)
	var bodyReader io.Reader
	if len(replacedBody) > 0 {
		bodyReader = strings.NewReader(replacedBody)
	}
	req, err := http.NewRequest(tmpl.Method, finalURL, bodyReader)
	if err != nil {
		return nil, finalURL, replacedBody, err
	}
	for k, vs := range tmpl.Headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Host = tmpl.Host
	return req, finalURL, replacedBody, nil
}

//------------------ INSECURE FLAG HANDLER ------------

func handleInsecure(transport *http.Transport, insecureFlag bool) {
	if insecureFlag {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		fmt.Println("[🔒] TLS certificate verification disabled")
		time.Sleep(3 * time.Second)
	} else {
		fmt.Println("[🔒] TLS certificate verification enabled")
		time.Sleep(3 * time.Second)
	}
}

// ------------------ PROXY SETUP --------------------

func setupProxy(transport *http.Transport, proxyAddr string) {
	if proxyAddr != "" {
		u, err := url.Parse(proxyAddr)
		if err != nil || u.Scheme == "" || u.Host == "" {
			log.Fatalf("[🐛] Invalid proxy URL: %s", proxyAddr)
		}
		host := u.Hostname()
		if _, err := net.LookupHost(host); err != nil {
			log.Fatalf("[🐛] Proxy host does not resolve: %s", host)
		}
		if port := u.Port(); port != "" {
			if _, err := strconv.Atoi(port); err != nil {
				log.Fatalf("[🐛] Invalid proxy port in URL: %s", port)
			}
		}
		transport.Proxy = http.ProxyURL(u)
		fmt.Println("[🕷️ ] Proxy set to:", proxyAddr)
	} else {
		fmt.Println("[🕷️ ] No proxy set, sending requests directly.")
	}
	time.Sleep(2 * time.Second)
}

// ------------------ LOAD RAW REQUEST ---------------

func loadRawRequest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read request file: %v", err)
	}
	if strings.Count(string(data), marker) != 1 {
		return "", fmt.Errorf("raw request must contain exactly one %s marker", marker)
	}
	return string(data), nil
}

// ------------------ INTERRUPT HANDLER --------------

func handleInterrupt() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Println()
		log.Println("\nReceived interrupt, terminating…")
		os.Exit(0)
	}()
}

// ------------------ FUZZER CORE --------------------

func runFuzzer(client *http.Client, raw string, payloads []string, encode, browserCheck bool, timeout time.Duration, alertsOnly bool, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	tmpl, err := parseRawRequest(raw)
	if err != nil {
		log.Fatalf("[🐛] Failed to parse raw request: %v", err)
	}

	for _, pl := range payloads {
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, finalURL, _, err := buildRawRequest(tmpl, payload, encode)
			if err != nil {
				log.Printf("[🐛] Build error for payload %q: %v", payload, err)
				return
			}

			respBody, err := sendRequest(client, req)
			if err != nil {
				log.Printf("[🐛] Request error for payload %q: %v", payload, err)
				return
			}

			reflected := checkReflection(respBody, payload)
			alerted := "N/A"

			if browserCheck {
				navURL := finalURL
				if !strings.EqualFold(tmpl.Method, "GET") {
					encoded := base64.StdEncoding.EncodeToString(respBody)
					navURL = "data:text/html;base64," + encoded
				}
				ok, err := checkWithBrowser(navURL, timeout)
				if err != nil && !strings.Contains(err.Error(), "could not retrieve document root") {
					log.Fatalf("[🐛] Browser check failed: %v", err)
				}
				if ok {
					alerted = "Yes"
				} else {
					alerted = "No"
				}
			}

			if alertsOnly && alerted != "Yes" {
				return
			}

			fmt.Println("\n============================")
			fmt.Println("Payload:", payload)
			fmt.Println("Reflected:", yesno(reflected))
			fmt.Println("Alert triggered:", alerted)
			fmt.Println("Method:", tmpl.Method)
			fmt.Println("Attacked URL:", finalURL)
		}(pl)
	}

	wg.Wait()
}

// ------------------ MAIN -----------------------

func main() {
	normalizeArgs()
	flag.Usage = displayhelp

	requestFile := flag.String("request", "", "")
	proxyAddr := flag.String("proxy", "", "")
	insecureFlag := flag.Bool("insecure", false, "")
	encode := flag.Bool("encode", false, "")
	browserCheck := flag.Bool("browser-check", false, "")
	timeout := flag.Duration("timeout", 5*time.Second, "")
	checkTime := flag.Int("checktime", 0, "")
	threads := flag.Int("threads", 4, "")
	payloadFile := flag.String("payloads", "", "")
	alertsOnly := flag.Bool("alerts-only", false, "")
	flag.Parse()

	if *checkTime > 0 {
		*timeout = time.Duration(*checkTime) * time.Second
	}
	handleInterrupt()

	raw, err := loadRawRequest(*requestFile)
	if err != nil {
		log.Fatal(err)
	}

	payloads, err := getPayloads(*payloadFile)
	if err != nil {
		log.Fatalf("[🐛] Failed to get payloads: %v", err)
	}

	transport := &http.Transport{}
	setupProxy(transport, *proxyAddr)
	handleInsecure(transport, *insecureFlag)

	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	runFuzzer(client, raw, payloads, *encode, *browserCheck, *timeout, *alertsOnly, *threads)

	fmt.Println("\nDone! 🚀")
}
