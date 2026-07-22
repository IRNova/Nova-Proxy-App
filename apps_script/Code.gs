var CACHE = CacheService.getScriptCache();
var LOCK = LockService.getScriptLock();

function doPost(e) {
  return handleRequest(e);
}

function doGet(e) {
  return handleRequest(e);
}

function handleRequest(e) {
  var start = new Date().getTime();
  var payload = JSON.parse(e.postData ? e.postData.contents : "{}");
  var method = payload.m || "GET";
  var url    = payload.u || "";
  var headers = payload.h || {};
  var body    = payload.b || "";
  var authKey = payload.k || "";
  var batch   = payload.batch || false;
  var gz      = payload.gz || 0;

  if (batch && url === "") {
    return handleBatch(payload.items, authKey, start);
  }

  var result = fetchUrl(method, url, headers, body, gz, start);
  result.k = "ok";

  var output = ContentService.createTextOutput(JSON.stringify(result));
  output.setMimeType(ContentService.MimeType.JSON);
  return output;
}

function fetchUrl(method, url, headers, body, gz, start) {
  var result = {s: 200, b: "", h: {}, trace: [{t: "gas", ms: 0}]};
  try {
    var params = {
      method: method,
      headers: headers,
      muteHttpExceptions: true,
      followRedirects: true,
      validateHttpsCertificates: false
    };
    if (body && method !== "GET" && method !== "HEAD") {
      var contentType = headers["content-type"] || headers["Content-Type"] || "application/octet-stream";
      params.contentType = contentType;
      params.payload = Utilities.base64Decode(body);
    }
    var resp = UrlFetchApp.fetch(url, params);
    result.s = resp.getResponseCode();
    result.h = resp.getHeaders();

    // Loop detection
    var bodyText = resp.getContentText();
    if (bodyText.indexOf("googleapps.com") !== -1 || bodyText.indexOf("script.google.com") !== -1) {
      result.s = 508;
      result.e = "loop detected";
      result.trace[0].ms = new Date().getTime() - start;
      return result;
    }

    var raw = resp.getContent();
    if (gz == 1 && raw.length > 0) {
      raw = Utilities.gzip(raw);
    }
    result.b = Utilities.base64Encode(raw);
    result.trace[0].ms = new Date().getTime() - start;

    var wafHeaders = ["x-amz", "x-azure", "cf-ray", "server-timing", "x-served-by"];
    for (var i = 0; i < wafHeaders.length; i++) {
      if (result.h[wafHeaders[i]]) {
        result.trace[0].waf = wafHeaders[i];
        break;
      }
    }

  } catch (e) {
    result.s = 502;
    result.e = e.message || "relay error";
    result.trace[0].ms = new Date().getTime() - start;
  }
  return result;
}

function handleBatch(items, authKey, start) {
  var results = [];
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    var r = fetchUrl(item.m, item.u, item.h || {}, item.b || "", 0, start);
    results.push(r);
  }
  var output = ContentService.createTextOutput(JSON.stringify({s: 200, b: JSON.stringify(results), k: "ok"}));
  output.setMimeType(ContentService.MimeType.JSON);
  return output;
}
