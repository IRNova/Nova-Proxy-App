package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GASDeployer handles automatic deployment of Google Apps Script
type GASDeployer struct {
	accessToken string
	client      *http.Client
}

type GASProject struct {
	ProjectID string `json:"projectId,omitempty"`
	Title     string `json:"title"`
	ParentID  string `json:"parentId,omitempty"`
}

type GASContent struct {
	Files []GASFile `json:"files"`
}

type GASFile struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Source string `json:"source"`
}

type GASDeployment struct {
	DeploymentID string `json:"deploymentId,omitempty"`
	Version      struct {
		VersionNumber string `json:"versionNumber,omitempty"`
	} `json:"version,omitempty"`
	UpdateTime string `json:"updateTime,omitempty"`
}

func NewGASDeployer(accessToken string) *GASDeployer {
	return &GASDeployer{
		accessToken: accessToken,
		client:      &http.Client{Timeout: 30 * time.Second},
	}
}

// CreateProject creates a new Apps Script project
func (d *GASDeployer) CreateProject(title string) (*GASProject, error) {
	url := "https://script.googleapis.com/v1/projects"
	body := GASProject{Title: title}

	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+d.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create project failed: %w", err)
	}
	defer resp.Body.Close()

	var project GASProject
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("decode project failed: %w", err)
	}
	return &project, nil
}

// UpdateContent updates the script content with Code.gs and worker.js
func (d *GASDeployer) UpdateContent(projectID string, codeGS, workerJS string) error {
	url := fmt.Sprintf("https://script.googleapis.com/v1/projects/%s/content", projectID)
	content := GASContent{
		Files: []GASFile{
			{
				Name:   "Code",
				Type:   "SERVER_JS",
				Source: codeGS,
			},
			{
				Name:   "worker",
				Type:   "SERVER_JS",
				Source: workerJS,
			},
		},
	}

	data, _ := json.Marshal(content)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+d.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("update content failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update content failed: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// CreateDeployment creates a new deployment (version + deployment)
func (d *GASDeployer) CreateDeployment(projectID, description string) (*GASDeployment, error) {
	// First create a version
	versionURL := fmt.Sprintf("https://script.googleapis.com/v1/projects/%s/versions", projectID)
	versionBody := map[string]string{"description": description}
	data, _ := json.Marshal(versionBody)
	req, _ := http.NewRequest("POST", versionURL, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+d.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create version failed: %w", err)
	}
	defer resp.Body.Close()

	var version struct {
		VersionNumber string `json:"versionNumber"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return nil, fmt.Errorf("decode version failed: %w", err)
	}

	// Then create deployment
	deployURL := fmt.Sprintf("https://script.googleapis.com/v1/projects/%s/deployments", projectID)
	deployBody := map[string]interface{}{
		"versionNumber": version.VersionNumber,
		"manifestFileName": "Code",
		"description": description,
	}
	data, _ = json.Marshal(deployBody)
	req, _ = http.NewRequest("POST", deployURL, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+d.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create deployment failed: %w", err)
	}
	defer resp.Body.Close()

	var deployment GASDeployment
	if err := json.NewDecoder(resp.Body).Decode(&deployment); err != nil {
		return nil, fmt.Errorf("decode deployment failed: %w", err)
	}
	return &deployment, nil
}

// DeployCloudflareWorker deploys worker.js to Cloudflare
type CFDeployer struct {
	apiToken  string
	accountID string
	client    *http.Client
}

func NewCFDeployer(apiToken, accountID string) *CFDeployer {
	return &CFDeployer{
		apiToken:  apiToken,
		accountID: accountID,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *CFDeployer) DeployWorker(name, script string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s", d.accountID, name)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader([]byte(script)))
	req.Header.Set("Authorization", "Bearer "+d.apiToken)
	req.Header.Set("Content-Type", "application/javascript")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("deploy worker failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("deploy worker failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	workerURL := fmt.Sprintf("https://%s.%s.workers.dev", name, d.accountID)
	return workerURL, nil
}

// DeployAll does full auto-setup: GAS project + CF worker
func DeployAll(gasToken, cfToken, cfAccountID string) (map[string]string, error) {
	result := make(map[string]string)

	// Deploy GAS
	gas := NewGASDeployer(gasToken)
	project, err := gas.CreateProject("NovaProxy Relay")
	if err != nil {
		return result, fmt.Errorf("GAS project: %w", err)
	}
	result["gas_project_id"] = project.ProjectID

	if err := gas.UpdateContent(project.ProjectID, DefaultCodeGS, DefaultWorkerJS); err != nil {
		return result, fmt.Errorf("GAS content: %w", err)
	}

	deployment, err := gas.CreateDeployment(project.ProjectID, "NovaProxy auto-deploy")
	if err != nil {
		return result, fmt.Errorf("GAS deploy: %w", err)
	}
	result["gas_deployment_id"] = deployment.DeploymentID

	// Deploy CF Worker
	if cfToken != "" && cfAccountID != "" {
		cf := NewCFDeployer(cfToken, cfAccountID)
		workerURL, err := cf.DeployWorker("novaproxy-relay", DefaultWorkerJS)
		if err != nil {
			return result, fmt.Errorf("CF worker: %w", err)
		}
		result["cf_worker_url"] = workerURL
	}

	return result, nil
}

// DefaultCodeGS is the default Google Apps Script code
const DefaultCodeGS = `var AUTH_KEY = "Novaproxy";
var WORKER_URL = "https://novaproxy-relay.YOUR_ACCOUNT.workers.dev";

function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);
    if (data.auth !== AUTH_KEY) {
      return ContentService.createTextOutput(JSON.stringify({error: "unauthorized"})).setMimeType(ContentService.MimeType.JSON);
    }
    var options = {
      method: data.method || "GET",
      headers: data.headers || {},
      payload: data.body || null,
      muteHttpExceptions: true,
      followRedirects: false
    };
    if (data.binary === false) {
      var resp = UrlFetchApp.fetch(data.url, options);
      return ContentService.createTextOutput(JSON.stringify({
        status: resp.getResponseCode(),
        headers: resp.getHeaders(),
        body: resp.getContentText()
      })).setMimeType(ContentService.MimeType.JSON);
    }
    var resp = UrlFetchApp.fetch(data.url, options);
    var blob = resp.getBlob();
    return ContentService.createTextOutput(JSON.stringify({
      status: resp.getResponseCode(),
      headers: resp.getHeaders(),
      body: Utilities.base64Encode(blob.getBytes()),
      binary: true
    })).setMimeType(ContentService.MimeType.JSON);
  } catch(e) {
    return ContentService.createTextOutput(JSON.stringify({error: e.toString()})).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NovaProxy Relay</title>';
  html += '<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">';
  html += '<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#e5e5e5}.card{text-align:center;padding:40px;border-radius:24px;background:#141414;border:1px solid rgba(255,255,255,.08)}.status{color:#22c55e;font-size:14px}.title{font-size:24px;font-weight:700;margin:12px 0}.sub{color:#a3a3a3;font-size:14px}</style></head>';
  html += '<body><div class="card"><div class="status">● ONLINE</div><div class="title">NovaProxy Relay</div><div class="sub">Secure connection relay · v1.0</div></div></body></html>';
  return HtmlService.createHtmlOutput(html).setTitle("NovaProxy Relay");
}

function doBatch(e) {
  var requests = JSON.parse(e.postData.contents);
  if (!Array.isArray(requests)) {
    return ContentService.createTextOutput(JSON.stringify({error: "expected array"})).setMimeType(ContentService.MimeType.JSON);
  }
  var options = requests.map(function(r) {
    return {
      url: r.url,
      method: r.method || "GET",
      headers: r.headers || {},
      payload: r.body || null,
      muteHttpExceptions: true
    };
  });
  var responses = UrlFetchApp.fetchAll(options);
  var result = responses.map(function(r) {
    return {
      status: r.getResponseCode(),
      headers: r.getHeaders(),
      body: r.getContentText()
    };
  });
  return ContentService.createTextOutput(JSON.stringify(result)).setMimeType(ContentService.MimeType.JSON);
}
`

// DefaultWorkerJS is the default Cloudflare Worker code
const DefaultWorkerJS = `export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/") {
      return new Response("NovaProxy Relay Worker", { status: 200 });
    }
    const target = url.searchParams.get("url");
    if (!target) {
      return new Response("Missing url parameter", { status: 400 });
    }
    try {
      const method = request.method;
      const headers = new Headers(request.headers);
      headers.set("X-Forwarded-For", request.headers.get("CF-Connecting-IP") || "");
      const body = method !== "GET" && method !== "HEAD" ? request.body : undefined;
      const resp = await fetch(target, { method, headers, body });
      return new Response(resp.body, {
        status: resp.status,
        headers: resp.headers
      });
    } catch(e) {
      return new Response(e.toString(), { status: 500 });
    }
  }
};
`
