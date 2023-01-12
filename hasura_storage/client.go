package hasura_storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/beepshow/nhost-go/common"
	"github.com/oriser/regroup"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type HasuraStorageClient struct {
	Url         string
	AdminSecret string

	AccessToken string
	httpClient  http.Client
	subdomain   string
}

type UploadParams struct {
	FilePath string
	FormData *bytes.Buffer
	Id       string
	Name     string
	BucketId string
}

type FileMetadata struct {
	Id        string
	Name      string
	Size      uint
	MimeType  string
	Etag      string
	CreatedAt string
	BucketId  string
}

type UploadResponse struct {
	*FileMetadata `json:"fileMetadata"` // maybe nil
	Error         *common.ErrorPayload  `json:"error"` // maybe nil
}

type PresignedUrl struct {
	Url        string
	Expiration uint
}
type GetPresignedUrlResponse struct {
	*PresignedUrl `json:"presignedUrl"` // maybe nil
	Error         *common.ErrorPayload  `json:"error"` // maybe nil
}

type DeleteResponse struct {
	Error *common.ErrorPayload `json:"error"` // maybe nil
}

func New(url string, adminSecret string) (*HasuraStorageClient, error) {

	client := HasuraStorageClient{
		Url:         url,
		AdminSecret: adminSecret,
		httpClient:  http.Client{},
	}

	return &client, nil
}

func NewWithSubdomain(url string, adminSecret string, subdomain string) (*HasuraStorageClient, error) {

	client := HasuraStorageClient{
		Url:         url,
		AdminSecret: adminSecret,
		httpClient:  http.Client{},
		subdomain:   subdomain,
	}

	return &client, nil
}

// TODO test
func (client *HasuraStorageClient) Upload(params *UploadParams) (*UploadResponse, error) {
	var formDataContentType string

	if params.FilePath != "" {
		file, _ := os.Open(params.FilePath)
		defer file.Close()
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", filepath.Base(file.Name()))
		io.Copy(part, file)
		writer.Close()
		params.FormData = body
		formDataContentType = writer.FormDataContentType()
	} else {
		x := multipart.NewWriter(&bytes.Buffer{})
		formDataContentType = x.FormDataContentType()
	}

	requestUrl := fmt.Sprintf("%s%s", client.Url, "/files")
	req, _ := http.NewRequest("POST", requestUrl, params.FormData)
	req.Header = common.MergeMaps(client.generateUploadHeaders(params), client.generateAuthHeaders())
	req.Header.Add("Content-Type", formDataContentType)
	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Printf("client: error making http request: %s\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)       // response body is []byte
	fmt.Printf("Result: %s\n", string(respBody)) // convert to string before print

	uploadResp := UploadResponse{
		FileMetadata: nil,
		Error:        nil,
	}

	var mapRes map[string]interface{}
	json.Unmarshal(respBody, &mapRes)
	if mapRes["error"] != nil {
		var jsonErr common.ErrorPayload
		justTheError, _ := json.Marshal(mapRes["error"])
		json.Unmarshal(justTheError, &jsonErr)
		return &uploadResp, nil
	}

	// Unmarshall as a normal result
	var result UploadResponse
	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal(respBody, &result)

	return &result, nil
}

func (client *HasuraStorageClient) generateUploadHeaders(params *UploadParams) map[string][]string {
	var headers = make(map[string][]string)
	if params.BucketId != "" {
		headers["x-nhost-bucket-id"] = []string{params.BucketId}
	}
	if params.Id != "" {
		headers["x-nhost-file-id"] = []string{params.Id}
	}
	if params.Name != "" {
		headers["x-nhost-file-name"] = []string{params.Name}
	}

	return headers
}

func (client *HasuraStorageClient) generateAuthHeaders() map[string][]string {
	var headers = make(map[string][]string)
	if client.AdminSecret == "" && client.AccessToken == "" {
		return headers
	}

	if client.AdminSecret != "" {
		headers["x-hasura-admin-secret"] = []string{client.AdminSecret}
	} else {
		headers["Authorization"] = []string{`Bearer ` + client.AccessToken}
	}
	return headers
}

func (client *HasuraStorageClient) GetPresignedUrl(fileId string) (*GetPresignedUrlResponse, error) {
	requestUrl := client.Url + "/files/" + fileId + "/presignedurl"
	req, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header = client.generateAuthHeaders()
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Printf("client: error making http request: %s\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	fmt.Printf("Result: %s\n", string(respBody))

	presignedResp := GetPresignedUrlResponse{
		PresignedUrl: nil,
		Error:        nil,
	}

	var mapRes map[string]interface{}
	json.Unmarshal(respBody, &mapRes)
	if mapRes["error"] != nil {
		var jsonErr common.ErrorPayload
		justTheError, _ := json.Marshal(mapRes["error"])
		json.Unmarshal(justTheError, &jsonErr)
		presignedResp.Error = &jsonErr
		return &presignedResp, nil
	}

	var result PresignedUrl
	json.Unmarshal(respBody, &result)

	// In case we work with local nhost make sure the presigned url is accesible via the actual client.subdomain
	// in case it is an IP address and not "localhost"
	var localhostRegex = regroup.MustCompile(common.LOCALHOST_REGEX_PREFIX)
	res := &common.UrlMatchResult{}
	err = localhostRegex.MatchToTarget(result.Url, res)
	// If match
	if err == nil && client.subdomain != "localhost" {
		result.Url = strings.Replace(result.Url, "localhost", client.subdomain, 1)
	}

	return &GetPresignedUrlResponse{Error: nil, PresignedUrl: &result}, nil
}

// TODO test
func (client *HasuraStorageClient) Delete(fileId string) (*DeleteResponse, error) {
	requestUrl := client.Url + "/files/" + fileId
	req, _ := http.NewRequest("DELETE", requestUrl, nil)
	req.Header = client.generateAuthHeaders()
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Printf("client: error making http request: %s\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	fmt.Printf("Result: %s\n", string(respBody))

	deleteResp := DeleteResponse{
		Error: nil,
	}

	var mapRes map[string]interface{}
	json.Unmarshal(respBody, &mapRes)
	if mapRes["error"] != nil {
		var jsonErr common.ErrorPayload
		justTheError, _ := json.Marshal(mapRes["error"])
		json.Unmarshal(justTheError, &jsonErr)
		return &deleteResp, nil
	}

	var result DeleteResponse
	json.Unmarshal(respBody, &result)

	return &result, nil
}

// TODO test
func (client *HasuraStorageClient) GetPublicUrl(fileId string) string {
	return client.Url + "/files/" + fileId
}
