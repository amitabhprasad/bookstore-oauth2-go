package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amitabhprasad/bookstore-util-go/rest_errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8082",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}
func AuthenticateRequest(request *http.Request, auth_url string) rest_errors.RestErr {
	fmt.Println("Inside AuthenticateRequest ******** ")
	if request == nil {
		return rest_errors.NewBadRequestError("Empty request")
	}
	cleanRequest(request)
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	if auth_url != "" {
		oauthRestClient.BaseURL = auth_url
	}
	fmt.Println("Inside AuthenticateRequest using ****** ", oauthRestClient.BaseURL)
	accessToken, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", accessToken.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", accessToken.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(at string) (*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", at))
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError(
			fmt.Sprintf("Invalid response when trying to get access-token using client %s ", oauthRestClient.BaseURL), nil)
	}
	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, rest_errors.NewInternalServerError("Invalid error interface when trying to get access-token", err)
		}
		return nil, restErr
	}
	var token accessToken
	err := json.Unmarshal(response.Bytes(), &token)
	if err != nil {
		return nil, rest_errors.NewInternalServerError("unable to marshal get accesstoken response", err)
	}
	return &token, nil
}
