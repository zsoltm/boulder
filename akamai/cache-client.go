package akamai

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	blog "github.com/letsencrypt/boulder/log"
)

type purgeRequest struct {
	Objects []string `json:"objects"`
}

type purgeResponse struct {
	HTTPStatus       int    `json:"httpStatus"`
	Detail           string `json:"detail"`
	EstimatedSeconds int    `json:"estimatedSeconds"`
	PurgeID          string `json:"purgeId"`
	ProgressURI      string `json:"progressUri"`
	PingAfterSeconds int    `json:"pingAfterSeconds"`
	SupportID        string `json:"supportId"`
}

// CachePurgeClient talks to the Akamai CCU REST API. It is safe to make concurrent
// purge requests.
type CachePurgeClient struct {
	client       *http.Client
	apiEndpoint  string
	username     string
	password     string
	retries      int
	retryBackoff time.Duration
	log          *blog.AuditLogger
}

var (
	errRetryable = errors.New("")
	errFatal     = errors.New("")
	// ErrAllRetriesFailed lets the caller of Purge to know if all the purge submission
	// attempts failed
	ErrAllRetriesFailed = errors.New("All attempts to submit purge request failed")
)

// NewCachePurgeClient constructs a new CachePurgeClient
func NewCachePurgeClient() *CachePurgeClient {
	return &CachePurgeClient{}
}

func (cpc *CachePurgeClient) purge(urls []string) error {
	purgeReq := purgeRequest{urls}
	reqJSON, err := json.Marshal(purgeReq)
	if err != nil {
		return err
	}

	resp, err := cpc.client.Post(cpc.apiEndpoint, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return errRetryable
	}
	if resp.Body == nil {
		return errRetryable
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errRetryable
	}

	var purgeInfo purgeResponse
	err = json.Unmarshal(body, &purgeInfo)
	if err != nil {
		return errRetryable
	}

	// Actually check the purge info...

	return nil
}

// Purge sends a purge request to the configured API endpoint
func (cpc *CachePurgeClient) Purge(urls []string) error {
	successful := false
	for i := 0; i <= cpc.retries; i++ {
		if i > 0 {
			time.Sleep(cpc.retryBackoff)
		}
		err := cpc.purge(urls)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			cpc.log.AuditErr(err)
			if err == errFatal {
				return err
			}
			continue
		}
		successful = true
		break
	}

	if !successful {
		return ErrAllRetriesFailed
	}
	return nil
}
