package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// API Response structures
type EnumerateRequest struct {
	Domain  string      `json:"domain"`
	Domains []string    `json:"domains,omitempty"`
	Options *APIOptions `json:"options,omitempty"`
}

type APIOptions struct {
	Threads            int  `json:"threads,omitempty"`
	Timeout            int  `json:"timeout,omitempty"`
	MaxEnumerationTime int  `json:"max_enumeration_time,omitempty"`
	All                bool `json:"all,omitempty"`            // Use all sources for enumeration (slow)
	OnlyRecursive      bool `json:"only_recursive,omitempty"` // Use only recursive sources
}

type EnumerateResponse struct {
	Success  bool                           `json:"success"`
	Message  string                         `json:"message,omitempty"`
	Results  []SubdomainResult              `json:"results,omitempty"`
	Count    int                            `json:"count"`
	Sources  map[string]map[string]struct{} `json:"sources,omitempty"`
	Duration string                         `json:"duration"`
}

type SubdomainResult struct {
	Subdomain   string   `json:"subdomain"`
	Sources     []string `json:"sources"`
	SourceCount int      `json:"source_count"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// SubfinderJSONOutput represents the JSON output format from subfinder
type SubfinderJSONOutput struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	Input  string `json:"input"`
}

// API Server
type APIServer struct {
	port string
}

func NewAPIServer(port string) *APIServer {
	return &APIServer{port: port}
}

// CORS Middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Health check endpoint
func (s *APIServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"success":   true,
		"message":   "Subfinder API is running",
		"version":   "2.0",
		"timestamp": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Single domain enumeration endpoint
func (s *APIServer) enumerateDomainHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EnumerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		s.sendError(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// Validate domain format (basic validation)
	if !isValidDomain(req.Domain) {
		s.sendError(w, "Invalid domain format", http.StatusBadRequest)
		return
	}

	// Set default options
	opts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		JSON:               true, // Enable JSON output for structured parsing
	}

	// Override with user options if provided
	if req.Options != nil {
		if req.Options.Threads > 0 {
			opts.Threads = req.Options.Threads
		}
		if req.Options.Timeout > 0 {
			opts.Timeout = req.Options.Timeout
		}
		if req.Options.MaxEnumerationTime > 0 {
			opts.MaxEnumerationTime = req.Options.MaxEnumerationTime
		}
		// Set source enumeration options based on user preferences
		opts.All = req.Options.All
		opts.OnlyRecursive = req.Options.OnlyRecursive
	}

	// Create subfinder runner
	subfinder, err := runner.NewRunner(opts)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Failed to create subfinder runner: %v", err), http.StatusInternalServerError)
		return
	}

	// Enumerate subdomains
	output := &bytes.Buffer{}
	err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), req.Domain, []io.Writer{output})
	if err != nil {
		s.sendError(w, fmt.Sprintf("Failed to enumerate subdomains: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse JSON results from output
	results := make([]SubdomainResult, 0)
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "{}" {
			var subfinderResult SubfinderJSONOutput
			if err := json.Unmarshal([]byte(line), &subfinderResult); err != nil {
				// If JSON parsing fails, treat as plain text (fallback)
				results = append(results, SubdomainResult{
					Subdomain:   line,
					Sources:     []string{"subfinder"},
					SourceCount: 1,
				})
				continue
			}

			results = append(results, SubdomainResult{
				Subdomain:   subfinderResult.Host,
				Sources:     []string{subfinderResult.Source},
				SourceCount: 1,
			})
		}
	}

	response := EnumerateResponse{
		Success:  true,
		Results:  results,
		Count:    len(results),
		Duration: time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Batch domain enumeration endpoint
func (s *APIServer) enumerateBatchHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EnumerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if len(req.Domains) == 0 {
		s.sendError(w, "Domains array is required and cannot be empty", http.StatusBadRequest)
		return
	}

	// Validate all domains
	for _, domain := range req.Domains {
		if !isValidDomain(domain) {
			s.sendError(w, fmt.Sprintf("Invalid domain format: %s", domain), http.StatusBadRequest)
			return
		}
	}

	// Set default options
	opts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		JSON:               true, // Enable JSON output for structured parsing
	}

	// Override with user options if provided
	if req.Options != nil {
		if req.Options.Threads > 0 {
			opts.Threads = req.Options.Threads
		}
		if req.Options.Timeout > 0 {
			opts.Timeout = req.Options.Timeout
		}
		if req.Options.MaxEnumerationTime > 0 {
			opts.MaxEnumerationTime = req.Options.MaxEnumerationTime
		}
		// Set source enumeration options based on user preferences
		opts.All = req.Options.All
		opts.OnlyRecursive = req.Options.OnlyRecursive
	}

	// Create subfinder runner
	subfinder, err := runner.NewRunner(opts)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Failed to create subfinder runner: %v", err), http.StatusInternalServerError)
		return
	}

	// Enumerate subdomains for all domains
	allResults := make([]SubdomainResult, 0)
	totalCount := 0

	for _, domain := range req.Domains {
		output := &bytes.Buffer{}
		err := subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output})
		if err != nil {
			log.Printf("Failed to enumerate domain %s: %v", domain, err)
			continue
		}

		// Parse JSON results for this domain
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && line != "{}" {
				var subfinderResult SubfinderJSONOutput
				if err := json.Unmarshal([]byte(line), &subfinderResult); err != nil {
					// If JSON parsing fails, treat as plain text (fallback)
					allResults = append(allResults, SubdomainResult{
						Subdomain:   line,
						Sources:     []string{"subfinder"},
						SourceCount: 1,
					})
					totalCount++
					continue
				}

				allResults = append(allResults, SubdomainResult{
					Subdomain:   subfinderResult.Host,
					Sources:     []string{subfinderResult.Source},
					SourceCount: 1,
				})
				totalCount++
			}
		}
	}

	response := EnumerateResponse{
		Success:  true,
		Results:  allResults,
		Count:    totalCount,
		Duration: time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper function to send error responses
func (s *APIServer) sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Success: false,
		Error:   message,
	}

	json.NewEncoder(w).Encode(response)
}

// Basic domain validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}

	return true
}

// Start the API server
func (s *APIServer) Start() {
	r := mux.NewRouter()

	// Add CORS middleware
	r.Use(corsMiddleware)

	// API routes
	r.HandleFunc("/health", s.healthHandler).Methods("GET")
	r.HandleFunc("/enumerate", s.enumerateDomainHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/enumerate/batch", s.enumerateBatchHandler).Methods("POST", "OPTIONS")

	// API documentation endpoint
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		docs := map[string]interface{}{
			"name":        "Subfinder API",
			"version":     "2.0",
			"description": "REST API for subdomain enumeration using Subfinder",
			"endpoints": map[string]interface{}{
				"GET /health":           "Health check endpoint",
				"POST /enumerate":       "Enumerate subdomains for a single domain",
				"POST /enumerate/batch": "Enumerate subdomains for multiple domains",
			},
			"example_single_domain": map[string]interface{}{
				"domain": "hackerone.com",
				"options": map[string]interface{}{
					"threads":              10,
					"timeout":              30,
					"max_enumeration_time": 10,
					"all":                  true,
					"only_recursive":       false,
				},
			},
			"example_batch": map[string]interface{}{
				"domains": []string{"hackerone.com", "bugcrowd.com"},
				"options": map[string]interface{}{
					"threads":              10,
					"timeout":              30,
					"max_enumeration_time": 10,
					"all":                  true,
					"only_recursive":       false,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(docs)
	}).Methods("GET")

	log.Printf("Subfinder API server starting on port %s", s.port)
	log.Printf("Visit http://localhost%s for API documentation", s.port)
	log.Fatal(http.ListenAndServe(s.port, r))
}

func main() {
	// Get port from environment or use default
	port := ":8005"
	if len(os.Args) > 1 {
		if p, err := strconv.Atoi(os.Args[1]); err == nil && p > 0 && p < 65536 {
			port = ":" + strconv.Itoa(p)
		}
	}

	// Disable timestamps in logs
	log.SetFlags(0)

	server := NewAPIServer(port)
	server.Start()
}
