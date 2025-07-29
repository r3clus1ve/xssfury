# XSSFURY

**XSSFURY** is a fast and lightweight fuzzing tool written in Go, designed to test web applications for reflected Cross-Site Scripting (XSS) vulnerabilities.  
It works by injecting payloads into customizable HTTP request templates, replacing a user-defined placeholder, and sending requests concurrently.

---

## Features

- HTTP request templating via `req.txt` with placeholder support (`§`)
- Concurrent request execution (default: 50 workers)
- Supports JSON, form-urlencoded, and arbitrary request body formats
- Automatic `Content-Length` calculation
- Proxy support (e.g. Burp Suite, OWASP ZAP)
- Custom headers including `Host`, `User-Agent`, etc.
- Simple test server (`testserver.go`) for local reflection validation

---

## Usage

```bash
go run xssfury.go -r req.txt -p payloads.txt
```

With a proxy (e.g. Burp listening on 127.0.0.1:8081):

```bash
go run xssfury.go -r req.txt -p payloads.txt -x http://127.0.0.1:8081
```

#Requirements

Go 1.18 or later
No third-party dependencies

#Notes

The Host: header in the request template is used to construct the request target.
Make sure you are testing only authorized and safe environments.
XSSFURY does not validate targets — be mindful when configuring templates.

#License

MIT License

#Author

Developed by Przem for research and security testing automation.

