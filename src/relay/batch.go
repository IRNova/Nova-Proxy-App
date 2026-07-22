package relay

import (
	"encoding/json"
	"fmt"
	"time"
)

type batchCommand struct {
	Method  string            `json:"m"`
	URL     string            `json:"u"`
	Headers map[string]string `json:"h,omitempty"`
	Body    string            `json:"b,omitempty"`
}

func (e *Engine) submitBatch(cmd batchCommand) []byte {
	payload := e.buildPayload(cmd.Method, cmd.URL, cmd.Headers, []byte(cmd.Body))

	respCh := make(chan []byte, 1)
	item := batchItem{payload: payload, respCh: respCh}

	e.batchMu.Lock()
	e.batchPending = append(e.batchPending, item)
	if e.batchTimer == nil {
		e.batchTimer = time.AfterFunc(50*time.Millisecond, e.flushBatch)
	}
	e.batchMu.Unlock()

	return <-respCh
}

func (e *Engine) flushBatch() {
	e.batchMu.Lock()
	items := e.batchPending
	e.batchPending = nil
	e.batchTimer = nil
	e.batchMu.Unlock()

	if len(items) == 0 {
		return
	}

	batch := make([]batchCommand, len(items))
	for i, item := range items {
		batch[i] = batchCommand{
			Method: fmt.Sprintf("%v", item.payload["m"]),
			URL:    fmt.Sprintf("%v", item.payload["u"]),
		}
		if h, ok := item.payload["h"].(map[string]any); ok {
			mh := make(map[string]string)
			for k, v := range h {
				mh[k] = fmt.Sprintf("%v", v)
			}
			batch[i].Headers = mh
		}
		if b, ok := item.payload["b"].(string); ok {
			batch[i].Body = b
		}
	}

	payload := map[string]any{
		"m":     "POST",
		"u":     "",
		"k":     e.authKey,
		"batch": true,
		"items": batch,
	}

	path := "/macros/s/" + e.pickScriptID("") + "/exec"
	body, _ := json.Marshal(payload)

	respData, err := e.h1Relay(path, body)
	if err != nil || len(respData) == 0 {
		errResp := errorResponse(502, "batch relay failed")
		for _, item := range items {
			item.respCh <- errResp
		}
		return
	}

	rr := safeParseRelayResponse(respData)
	if rr.Error != "" || rr.Status != 200 {
		errResp := errorResponse(502, "batch error: "+rr.Error)
		for _, item := range items {
			item.respCh <- errResp
		}
		return
	}

	rawItems := []map[string]any{}
	if err := json.Unmarshal([]byte(rr.Body), &rawItems); err != nil {
		errResp := errorResponse(502, "batch bad body")
		for _, item := range items {
			item.respCh <- errResp
		}
		return
	}

	if len(rawItems) != len(items) {
		errResp := errorResponse(502, fmt.Sprintf("batch count mismatch: got %d, expected %d", len(rawItems), len(items)))
		for _, item := range items {
			item.respCh <- errResp
		}
		return
	}

	for i, raw := range rawItems {
		if _, ok := raw["r"].(string); ok {
			rawJSON, _ := json.Marshal(raw)
			items[i].respCh <- rawJSON
		} else {
			items[i].respCh <- e.parseJSON(map[string]any{
				"s": raw["s"],
				"h": raw["h"],
				"b": raw["b"],
			})
		}
	}
}

func (e *Engine) deduplicateURL(targetURL string, body []byte) []byte {
	return nil
}
