package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName, &autoDNSSolver{})
}

// autoDNSSolver implements the webhook.Solver interface.
type autoDNSSolver struct {
	client kubernetes.Interface
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

// autodnsZoneUpdate is the request body for zone updates.
type autodnsZoneUpdate struct {
	Adds    []autodnsZoneRecord `json:"adds,omitempty"`
	Removes []autodnsZoneRecord `json:"removes,omitempty"`
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

	body := autodnsZoneUpdate{Adds: []autodnsZoneRecord{record}}

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

	body := autodnsZoneUpdate{Removes: []autodnsZoneRecord{record}}

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

func (s *autoDNSSolver) callAPI(cfg solverConfig, username, password, apiCtx, zone string, body autodnsZoneUpdate) error {
	url := cfg.URL
	if url == "" {
		url = "https://api.autodns.com/v1"
	}

	nameServer := cfg.NameServer
	if nameServer == "" {
		nameServer = "a.ns14.net" // InterNetX default
	}

	endpoint := fmt.Sprintf("%s/zone/%s/%s", url, zone, nameServer)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	klog.Infof("AutoDNS API call: PATCH %s", endpoint)

	req, err := http.NewRequest("PATCH", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Domainrobot-Context", apiCtx)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("AutoDNS API error: status=%d body=%s", resp.StatusCode, string(respBody))
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
