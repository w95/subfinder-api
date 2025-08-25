# Subfinder REST API

A REST API server that exposes Subfinder's subdomain enumeration capabilities over HTTP.

## Quick Start

1. **Build and run the API server:**
   ```bash
   go run main.go [port]
   ```
   
   Default port is `:8005`. You can specify a custom port as an argument:
   ```bash
   go run main.go 9000  # Runs on :9000
   ```

2. **Access API documentation:**
   ```
   GET http://localhost:8005/
   ```

3. **Health check:**
   ```
   GET http://localhost:8005/health
   ```

## API Endpoints

### POST /enumerate
Enumerate subdomains for a single domain.

**Request:**
```json
{
  "domain": "hackerone.com",
  "options": {
    "threads": 10,
    "timeout": 30,
    "max_enumeration_time": 10,
    "all": true,
    "only_recursive": false
  }
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "subdomain": "api.hackerone.com",
      "sources": ["crtsh", "censys"],
      "source_count": 2
    }
  ],
  "count": 1,
  "duration": "15.2s"
}
```

### POST /enumerate/batch
Enumerate subdomains for multiple domains.

**Request:**
```json
{
  "domains": ["hackerone.com", "bugcrowd.com"],
  "options": {
    "threads": 10,
    "timeout": 30,
    "max_enumeration_time": 10,
    "all": true,
    "only_recursive": false
  }
}
```

**Response:** Same format as single domain endpoint, but with results from all domains.

## Configuration Options

- **threads**: Number of concurrent threads (default: 10)
- **timeout**: Timeout per source in seconds (default: 30)
- **max_enumeration_time**: Maximum enumeration time in minutes (default: 10)
- **all**: Use all sources for enumeration including slow ones (default: false)
- **only_recursive**: Use only sources that support recursive subdomain discovery (default: false)

## Example Usage

### cURL Examples

**Single domain:**
```bash
curl -X POST http://localhost:8005/enumerate \
  -H "Content-Type: application/json" \
  -d '{"domain": "hackerone.com"}'
```

**Multiple domains:**
```bash
curl -X POST http://localhost:8005/enumerate/batch \
  -H "Content-Type: application/json" \
  -d '{"domains": ["hackerone.com", "bugcrowd.com"]}'
```

**With custom options:**
```bash
curl -X POST http://localhost:8005/enumerate \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "hackerone.com",
    "options": {
      "threads": 20,
      "timeout": 45,
      "max_enumeration_time": 15,
      "all": true,
      "only_recursive": false
    }
  }'
```

### Python Example

```python
import requests
import json

url = "http://localhost:8005/enumerate"
data = {
    "domain": "hackerone.com",
    "options": {
        "threads": 10,
        "timeout": 30
    }
}

response = requests.post(url, json=data)
result = response.json()

if result["success"]:
    print(f"Found {result['count']} subdomains:")
    for subdomain in result["results"]:
        print(f"  {subdomain['subdomain']} (from {len(subdomain['sources'])} sources)")
else:
    print(f"Error: {result['error']}")
```

### JavaScript Example

```javascript
const response = await fetch('http://localhost:8005/enumerate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    domain: 'hackerone.com',
    options: {
      threads: 10,
      timeout: 30
    }
  })
});

const result = await response.json();

if (result.success) {
  console.log(`Found ${result.count} subdomains:`);
  result.results.forEach(subdomain => {
    console.log(`  ${subdomain.subdomain} (from ${subdomain.source_count} sources)`);
  });
} else {
  console.error(`Error: ${result.error}`);
}
```

## Features

- ✅ **CORS enabled** - Can be used from web frontends
- ✅ **JSON responses** - Easy integration with applications
- ✅ **Error handling** - Proper HTTP status codes and error messages
- ✅ **Batch processing** - Enumerate multiple domains in one request
- ✅ **Configurable options** - Customize threads, timeouts, and enumeration time
- ✅ **Source tracking** - See which sources found each subdomain
- ✅ **Performance metrics** - Request duration included in responses

## Building for Production

```bash
go build -o subfinder-api main.go
./subfinder-api 8080
```

Or build for different platforms:
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o subfinder-api-linux main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o subfinder-api-windows.exe main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o subfinder-api-macos main.go
```