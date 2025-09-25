
# XSSFURY 🚀

**Automatic reflected XSS fuzzer from raw HTTP requests.**

XSSFURY is a fast and flexible tool written in Go, designed for security researchers and bug bounty hunters. It takes a raw HTTP request with a placeholder marker, injects payloads, and detects reflected XSS both via raw response analysis and optional headless browser checks.

---

## ✨ Features

- **Raw request injection** – Accepts a raw HTTP request file with a single `§here§` marker to specify where the payload should be injected.
- **Custom payloads** – Reads payloads from a file, ignoring comments and empty lines, and can URL‑encode them if required.
- **Proxy support** – Optional HTTP or SOCKS proxy support to send requests through a proxy.
- **TLS verification control** – Optionally skip TLS certificate verification for testing environments.
- **Multi‑threaded fuzzer** – Configurable number of concurrent workers to improve throughput.
- **Headless browser checks** – Optional Chrome/Chromium headless mode to detect if the payload triggers an `alert()` dialog.
- **Timeout and wait control** – User‑configurable request and browser check timeouts, and wait time for alerts.
- **Alerts‑only mode** – Option to print only payloads that triggered an alert in the browser.
- **Flexible CLI** – Supports both long flags and short aliases for convenience (e.g. `--request` / `-r`).

---

## ⚙️ Installation

XSSFURY requires Go 1.19 or newer. To build from source:

```bash
git clone https://github.com/<your-username>/xssfury.git
cd xssfury
go build -o xssfury
```

For the optional headless browser checks you need Google Chrome or Chromium installed. XSSFURY uses the [chromedp](https://github.com/chromedp/chromedp) library to control the browser.

---

## 🚀 Usage

Create a raw HTTP request file that contains a `§here§` marker indicating where the payload should be injected. For example:

```
GET /search?q=§here§ HTTP/1.1
Host: example.com
User‑Agent: XSSFURY
Accept: */*
Connection: close
```

Provide the path to this file using the `--request` flag and pass a payload file with `--payloads`. XSSFURY will iterate over each payload, send the request, check for reflection, and optionally perform browser‑based alert detection.

```bash
./xssfury --request req.txt --payloads payloads.txt
```

### Flags

- `--request`, `-r`: Path to the raw HTTP request file containing exactly one `§here§` marker.
- `--payloads`, `-p`: Path to the payload file (default `payloads.log`).
- `--encode`, `-e`: URL‑encode payloads before injection.
- `--proxy`, `-x`: Optional proxy URL (e.g. `http://127.0.0.1:8080`).
- `--insecure`, `-k`: Skip TLS certificate verification (insecure).
- `--threads`, `-w`: Number of concurrent workers (default `4`).
- `--browser-check`, `-b`: Enable headless browser detection of `alert()`.
- `--timeout`, `-t`: Browser check timeout (default `5s`).
- `--checktime`, `-c`: Time in seconds to wait for an alert during browser checks. Overrides `--timeout`.
- `--alerts-only`, `-a`: Display only payloads that triggered alerts in browser checks.

### Example

Assuming you have a payload file `payloads.txt` containing a list of XSS payloads:

```
"\"><script>alert(1)</script>"
<img src=x onerror=alert(1)>
```

Run XSSFURY with 10 concurrent threads and browser checks enabled:

```bash
./xssfury -r req.txt -p payloads.txt -w 10 -b -a
```

The tool will output a summary for each payload, including whether it was reflected in the response and whether a browser alert was triggered.

---

## ⚠️ Disclaimer

XSSFURY is intended solely for authorized security testing and research. Do not use it against systems or networks without explicit permission. Misuse of this tool may violate laws and agreements; use it responsibly.

---

## 📜 License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE). Any derivative work or service built upon XSSFURY must also be released under the AGPLv3.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests. Please ensure your contributions align with the project's goals and the AGPL license.

---

## 🙏 Credits

XSSFURY was created by Przem. Thanks to the open source community for inspiration and support.
