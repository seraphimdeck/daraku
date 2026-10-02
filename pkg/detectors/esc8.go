package detectors

import (
	"fmt"
	"net/http"
	"strings"
	"crypto/tls"

	httpClient "github.com/seraphimdeck/daraku/pkg/http"
	"github.com/seraphimdeck/daraku/pkg/models"
)

func (e *Engine) DetectESC8() []models.Finding {
	var findings []models.Finding

	probe := httpClient.NewProbeClient()

	for _, ca := range e.CAs {
		if strings.TrimSpace(ca.DNSHostName) == "" {
			continue
		}

		httpFinding := checkESC8Endpoint(probe, &ca, false)
		if httpFinding != nil {
			findings = append(findings, *httpFinding)
		}

		httpsFinding := checkESC8Endpoint(probe, &ca, true)
		if httpsFinding != nil {
			findings = append(findings, *httpsFinding)
		}
	}

	return findings
}

func checkESC8Endpoint(probe *httpClient.ProbeClient, ca *models.EnterpriseCA, useTLS bool) *models.Finding {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s/certsrv/", scheme, ca.DNSHostName)

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "daraku/1.2.0")

	client := probe.HTTPClient
	if useTLS {
		client = &http.Client{
			Timeout: probe.HTTPClient.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	authHeaders := resp.Header.Values("WWW-Authenticate")
	ntlmSupported := false
	for _, h := range authHeaders {
		upperH := strings.ToUpper(h)
		if strings.Contains(upperH, "NTLM") || strings.Contains(upperH, "NEGOTIATE") {
			ntlmSupported = true
			break
		}
	}

	if !ntlmSupported {
		return nil
	}

	epaEnabled := false
	for _, h := range authHeaders {
		if strings.Contains(strings.ToLower(h), "tokenbinding") ||
			strings.Contains(strings.ToLower(h), "channelbindings") {
			epaEnabled = true
			break
		}
	}

	evidence := []string{
		fmt.Sprintf("HTTP status=%d", resp.StatusCode),
		fmt.Sprintf("WWW-Authenticate=%v", authHeaders),
		fmt.Sprintf("EPA Enabled=%v", epaEnabled),
		fmt.Sprintf("Scheme=%s", scheme),
	}

	severity := models.SeverityCritical
	if epaEnabled {
		severity = models.SeverityHigh
	}

	return &models.Finding{
		ID:             "ESC8",
		Title:          fmt.Sprintf("AD CS Web Enrollment over %s with NTLM Advertised (ESC8)", strings.ToUpper(scheme)),
		Severity:       severity,
		Confidence:     models.ConfidenceCandidate,
		Category:       "AD CS",
		AffectedEntity: ca.DNSHostName,
		Description:    fmt.Sprintf("Enterprise CA '%s' merespons %s Web Enrollment pada %s dan mengiklankan NTLM/Negotiate. EPA=%v.", ca.Name, strings.ToUpper(scheme), targetURL, epaEnabled),
		Evidence:       evidence,
		Remediation:    "Nonaktifkan layanan Web Enrollment jika tidak digunakan. Gunakan HTTPS, aktifkan EPA, dan evaluasi kebutuhan NTLM.",
		References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
	}
}