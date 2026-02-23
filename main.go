package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"bytes"
	"crypto/tls"
	"io"
	"net/http"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const userAgent = "cert-manager-webhook-autodns/1.0"

var GroupName = os.Getenv("GROUP_NAME")

// apiThrottleDelay is the minimum time between AutoDNS API calls.
// Configurable via API_THROTTLE_SECONDS env var (default: 10).
var apiThrottleDelay = func() time.Duration {
	s := os.Getenv("API_THROTTLE_SECONDS")
	if s == "" {
		return 10 * time.Second
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 10 * time.Second
	}
	return time.Duration(v) * time.Second
}()

// authLockoutDuration is how long to block API calls after an auth failure.
// Configurable via AUTH_LOCKOUT_MINUTES env var (default: 65).
var authLockoutDuration = func() time.Duration {
	s := os.Getenv("AUTH_LOCKOUT_MINUTES")
	if s == "" {
		return 65 * time.Minute
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 65 * time.Minute
	}
	return time.Duration(v) * time.Minute
}()

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	klog.Infof("Starting AutoDNS webhook solver (throttle: %s, auth_lockout: %s)", apiThrottleDelay, authLockoutDuration)
	cmd.RunWebhookServer(GroupName, &autoDNSSolver{})
}

// autoDNSSolver implements the webhook.Solver interface.
type autoDNSSolver struct {
	client        kubernetes.Interface
	mu            sync.Mutex
	lastCall      time.Time
	sessionID     string
	sessionExpiry time.Time
	authLockedAt  time.Time
	authLastError string
}

// solverConfig is the configuration decoded from the solver config JSON.
type solverConfig struct {
	SecretRef  string `json:"secretRef"`
	Namespace  string `json:"secretNamespace"`
	URL        string `json:"url"`
	Zone       string `json:"zone"`
	NameServer string `json:"nameServer"`
}

// autodnsZoneRecord is a single resource record for the AutoDNS API.
type autodnsZoneRecord struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
}

// autodnsZoneUpdate is the request body for PATCH /zone/{zone}/{ns}.
type autodnsZoneUpdate struct {
	Origin             string              `json:"origin"`
	ResourceRecordsAdd []autodnsZoneRecord `json:"resourceRecordsAdd,omitempty"`
	ResourceRecordsRem []autodnsZoneRecord `json:"resourceRecordsRem,omitempty"`
}

// autodnsLoginRequest is the JSON body for POST /login.
type autodnsLoginRequest struct {
	Context  string `json:"context"`
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *autoDNSSolver) Name() string {
	return "autodns"
}

func (s *autoDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	username, password, ctx, err := s.getCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %v", err)
	}

	zone := cfg.Zone
	if zone == "" {
		zone = extractZone(ch.ResolvedZone)
	}

	record := autodnsZoneRecord{
		Name:  extractRecordName(ch.ResolvedFQDN, zone),
		Value: ch.Key,
		Type:  "TXT",
		TTL:   60,
	}

	body := autodnsZoneUpdate{Origin: zone, ResourceRecordsAdd: []autodnsZoneRecord{record}}

	return s.callAPI(cfg, username, password, ctx, zone, body)
}

func (s *autoDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	username, password, ctx, err := s.getCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %v", err)
	}

	zone := cfg.Zone
	if zone == "" {
		zone = extractZone(ch.ResolvedZone)
	}

	record := autodnsZoneRecord{
		Name:  extractRecordName(ch.ResolvedFQDN, zone),
		Value: ch.Key,
		Type:  "TXT",
		TTL:   60,
	}

	body := autodnsZoneUpdate{Origin: zone, ResourceRecordsRem: []autodnsZoneRecord{record}}

	return s.callAPI(cfg, username, password, ctx, zone, body)
}

func (s *autoDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	s.client = cl
	return nil
}

func (s *autoDNSSolver) getCredentials(cfg solverConfig, namespace string) (string, string, string, error) {
	ns := cfg.Namespace
	if ns == "" {
		ns = namespace
	}
	secretName := cfg.SecretRef
	if secretName == "" {
		secretName = "autodns-credentials"
	}

	secret, err := s.client.CoreV1().Secrets(ns).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get secret %s/%s: %v", ns, secretName, err)
	}

	username := string(secret.Data["username"])
	password := string(secret.Data["password"])
	apiCtx := string(secret.Data["context"])

	if username == "" || password == "" {
		return "", "", "", fmt.Errorf("secret %s/%s missing username or password", ns, secretName)
	}
	if apiCtx == "" {
		apiCtx = "4" // default to live system
	}

	return username, password, apiCtx, nil
}

// isAuthError returns true for HTTP status codes that indicate authentication failure.
func isAuthError(statusCode int) bool {
	return statusCode == 401 || statusCode == 403
}

func (s *autoDNSSolver) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// login creates a session via POST /login and stores the session ID.
func (s *autoDNSSolver) login(baseURL, username, password, apiCtx string) error {
	loginBody := autodnsLoginRequest{
		Context:  apiCtx,
		User:     username,
		Password: password,
	}

	jsonBody, err := json.Marshal(loginBody)
	if err != nil {
		return fmt.Errorf("failed to marshal login request: %v", err)
	}

	endpoint := fmt.Sprintf("%s/login?timeout=55", baseURL)
	klog.Infof("AutoDNS login: POST %s", endpoint)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create login request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Domainrobot-Context", apiCtx)
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("AutoDNS login failed: status=%d body=%s", resp.StatusCode, string(respBody))
		if isAuthError(resp.StatusCode) {
			s.authLockedAt = time.Now()
			s.authLastError = errMsg
			klog.Errorf("AutoDNS auth FAILED (status %d) — circuit breaker activated for %s. Check credentials in secret, then restart pod.", resp.StatusCode, authLockoutDuration)
		}
		return fmt.Errorf("%s", errMsg)
	}

	sessionID := resp.Header.Get("X-Domainrobot-SessionId")
	if sessionID == "" {
		return fmt.Errorf("login succeeded but no X-Domainrobot-SessionId in response")
	}

	s.sessionID = sessionID
	s.sessionExpiry = time.Now().Add(50 * time.Minute) // 55min timeout with 5min buffer
	klog.Infof("AutoDNS login success, session valid until %s", s.sessionExpiry.Format(time.RFC3339))
	return nil
}

// ensureSession logs in if there is no valid session.
func (s *autoDNSSolver) ensureSession(baseURL, username, password, apiCtx string) error {
	if s.sessionID != "" && time.Now().Before(s.sessionExpiry) {
		return nil
	}
	klog.Infof("AutoDNS session expired or missing, logging in...")
	return s.login(baseURL, username, password, apiCtx)
}

func (s *autoDNSSolver) callAPI(cfg solverConfig, username, password, apiCtx, zone string, body autodnsZoneUpdate) error {
	s.mu.Lock()

	// Circuit breaker: refuse to call API if auth is locked out
	if !s.authLockedAt.IsZero() {
		remaining := authLockoutDuration - time.Since(s.authLockedAt)
		if remaining > 0 {
			s.mu.Unlock()
			klog.Errorf("AutoDNS auth circuit breaker OPEN — blocking API call for %s (last error: %s)", remaining.Round(time.Second), s.authLastError)
			return fmt.Errorf("AutoDNS auth locked out for %s after auth failure — check credentials in secret, then restart pod. Last error: %s", remaining.Round(time.Second), s.authLastError)
		}
		// Lockout expired, reset
		klog.Infof("AutoDNS auth lockout expired, allowing API calls again")
		s.authLockedAt = time.Time{}
		s.authLastError = ""
	}

	// Throttle API calls
	if elapsed := time.Since(s.lastCall); elapsed < apiThrottleDelay {
		wait := apiThrottleDelay - elapsed
		klog.Infof("AutoDNS throttle: waiting %s before next API call", wait)
		s.mu.Unlock()
		time.Sleep(wait)
		s.mu.Lock()
	}
	s.lastCall = time.Now()

	baseURL := cfg.URL
	if baseURL == "" {
		baseURL = "https://api.autodns.com/v1"
	}

	// Ensure we have a valid session
	if err := s.ensureSession(baseURL, username, password, apiCtx); err != nil {
		s.mu.Unlock()
		return err
	}

	sessionID := s.sessionID
	s.mu.Unlock()

	nameServer := cfg.NameServer
	if nameServer == "" {
		nameServer = "a.ns14.net" // InterNetX default
	}

	endpoint := fmt.Sprintf("%s/zone/%s/%s", baseURL, zone, nameServer)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	klog.Infof("AutoDNS API call: PATCH %s", endpoint)

	req, err := http.NewRequest("PATCH", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Domainrobot-Context", apiCtx)
	req.Header.Set("X-Domainrobot-SessionId", sessionID)
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("AutoDNS API error: status=%d body=%s", resp.StatusCode, string(respBody))

		// On auth errors, invalidate session and activate circuit breaker
		if isAuthError(resp.StatusCode) {
			s.mu.Lock()
			s.sessionID = ""
			s.authLockedAt = time.Now()
			s.authLastError = errMsg
			s.mu.Unlock()
			klog.Errorf("AutoDNS auth FAILED (status %d) — circuit breaker activated for %s. Check credentials in secret, then restart pod.", resp.StatusCode, authLockoutDuration)
		}

		return fmt.Errorf("%s", errMsg)
	}

	klog.Infof("AutoDNS API success: %s %d", endpoint, resp.StatusCode)
	return nil
}

func loadConfig(cfgJSON *apiextensionsv1.JSON) (solverConfig, error) {
	cfg := solverConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

// extractZone removes the trailing dot from a DNS zone.
func extractZone(resolvedZone string) string {
	return strings.TrimSuffix(resolvedZone, ".")
}

// extractRecordName returns the record name relative to the zone.
func extractRecordName(fqdn, zone string) string {
	name := strings.TrimSuffix(fqdn, ".")
	name = strings.TrimSuffix(name, "."+zone)
	return name
}
