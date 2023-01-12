package nhost

import (
	"encoding/json"
	"fmt"
	"github.com/beepshow/nhost-go/hasura_auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jarcoal/httpmock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
	"time"
)

//	{
//	 "https://hasura.io/jwt/claims": {
//	   "x-hasura-fan-id": "28de3732-2ef5-4a6e-988e-fc5db33bcdea",
//	   "x-hasura-allowed-roles": [
//	     "user",
//	     "me"
//	   ],
//	   "x-hasura-default-role": "user",
//	   "x-hasura-user-id": "be9eb329-df97-48a9-9346-f76755f3fe42",
//	   "x-hasura-user-is-anonymous": "false"
//	 },
//	 "sub": "be9eb329-df97-48a9-9346-f76755f3fe42",
//	 "iat": 1672254949,
//	 "exp": 1672255449,
//	 "iss": "hasura-auth"
//	}

// Creates a token with the given claim. If sub, iat, exp, iss is set in claim, it is left asis, otherwise a
// value is provided for it. If exp is not set expiresInSeconds is used to calculate its value.
func CreateToken(claims jwt.MapClaims, expiresInSeconds int) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	if claims["sub"] == nil {
		claims["sub"] = "be9eb329-df97-48a9-9346-f76755f3fe42"
	}
	if claims["iat"] == nil {
		claims["iat"] = time.Now()
	}
	if claims["exp"] == nil {
		claims["exp"] = time.Now().Add(time.Duration(expiresInSeconds) * time.Second)
	}
	if claims["iss"] == nil {
		claims["iss"] = "hasura-auth"
	}
	token.Claims = claims

	var secretKey = []byte("secretkey")
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func CreateSigninResponse() string {
	session := CreateSessionResponse()
	response := make(map[string]interface{})
	response["session"] = session

	result, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}

	return string(result)
}

func CreateRefreshTokenResponse() string {
	session := CreateSessionResponse()
	result, err := json.Marshal(session)
	if err != nil {
		panic(err)
	}

	return string(result)
}

func CreateSessionResponse() map[string]interface{} {
	claims := jwt.MapClaims{}

	userId := "be9eb329-df97-48a9-9346-f76755f3fe42"
	fanId := "28de3732-2ef5-4a6e-988e-fc5db33bcdea"
	expiresIn := 2
	refreshToken := "5cca0478-5e5c-44c1-84fc-619b5f456957"

	//	 "https://hasura.io/jwt/claims": {
	//	   "x-hasura-fan-id": "28de3732-2ef5-4a6e-988e-fc5db33bcdea",
	//	   "x-hasura-allowed-roles": [
	//	     "user",
	//	     "me"
	//	   ],
	//	   "x-hasura-default-role": "user",
	//	   "x-hasura-user-id": "be9eb329-df97-48a9-9346-f76755f3fe42",
	//	   "x-hasura-user-is-anonymous": "false"
	//	 },
	hasuraClaims := jwt.MapClaims{}

	var allowedRoles [2]string
	allowedRoles[0] = "user"
	allowedRoles[1] = "me"

	hasuraClaims["x-hasura-fan-id"] = fanId
	hasuraClaims["x-hasura-allowed-roles"] = allowedRoles
	hasuraClaims["x-hasura-default-role"] = "user"
	hasuraClaims["x-hasura-user-id"] = userId
	hasuraClaims["x-hasura-user-is-anonymous"] = "false"

	claims["https://hasura.io/jwt/claims"] = hasuraClaims
	claims["sub"] = userId

	token, _ := CreateToken(claims, expiresIn)
	fmt.Printf("Token: %s\n", token)

	// {
	//  "session": {
	//    "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJodHRwczovL2hhc3VyYS5pby9qd3QvY2xhaW1zIjp7IngtaGFzdXJhLWZhbi1pZCI6IjI4ZGUzNzMyLTJlZjUtNGE2ZS05ODhlLWZjNWRiMzNiY2RlYSIsIngtaGFzdXJhLWFsbG93ZWQtcm9sZXMiOlsidXNlciIsIm1lIl0sIngtaGFzdXJhLWRlZmF1bHQtcm9sZSI6InVzZXIiLCJ4LWhhc3VyYS11c2VyLWlkIjoiYmU5ZWIzMjktZGY5Ny00OGE5LTkzNDYtZjc2NzU1ZjNmZTQyIiwieC1oYXN1cmEtdXNlci1pcy1hbm9ueW1vdXMiOiJmYWxzZSJ9LCJzdWIiOiJiZTllYjMyOS1kZjk3LTQ4YTktOTM0Ni1mNzY3NTVmM2ZlNDIiLCJpYXQiOjE2NzE4MjIzNTksImV4cCI6MTY3MTgyMjg1OSwiaXNzIjoiaGFzdXJhLWF1dGgifQ.I2uY0Lp_ZQLT6aDIkej26tieE8REjdjTcDpgDY0RUYU",
	//    "accessTokenExpiresIn": 500,
	//    "refreshToken": "5cca0478-5e5c-44c1-84fc-619b5f456957",
	//    "user": {
	//      "id": "be9eb329-df97-48a9-9346-f76755f3fe42",
	//      "createdAt": "2022-12-03T10:14:53.254353+00:00",
	//      "displayName": "asd@asd.as",
	//      "avatarUrl": "https://s.gravatar.com/avatar/26f716bfba89b71dc1f67cb893a21867?r=g&default=blank",
	//      "locale": "en",
	//      "email": "asd@asd.as",
	//      "isAnonymous": false,
	//      "defaultRole": "user",
	//      "metadata": {},
	//      "emailVerified": false,
	//      "phoneNumber": null,
	//      "phoneNumberVerified": false,
	//      "activeMfaType": null,
	//      "roles": [
	//        "user",
	//        "me"
	//      ]
	//    }
	//  },
	//  "mfa": null
	//}
	session := make(map[string]interface{})
	session["accessToken"] = token
	session["accessTokenExpiresIn"] = expiresIn
	session["refreshToken"] = refreshToken
	session["mfa"] = nil

	user := make(map[string]interface{})
	session["user"] = user
	user["id"] = userId
	user["id"] = userId
	user["createdAt"] = "2022-12-03T10:14:53.254353+00:00"
	user["displayName"] = "asd@asd.as"
	user["avatarUrl"] = "https://s.gravatar.com/avatar/26f716bfba89b71dc1f67cb893a21867?r=g&default=blank"
	user["locale"] = "en"
	user["email"] = "asd@asd.as"
	user["isAnonymous"] = false
	user["defaultRole"] = "user"
	user["metadata"] = make(map[string]interface{})
	user["emailVerified"] = false
	user["phoneNumber"] = nil
	user["phoneNumberVerified"] = false
	user["activeMfaType"] = nil

	var roles [2]string
	roles[0] = "user"
	roles[1] = "me"
	user["roles"] = roles

	return session
}

func Test_createToken(t *testing.T) {
	claims := jwt.MapClaims{}

	//	 "https://hasura.io/jwt/claims": {
	//	   "x-hasura-fan-id": "28de3732-2ef5-4a6e-988e-fc5db33bcdea",
	//	   "x-hasura-allowed-roles": [
	//	     "user",
	//	     "me"
	//	   ],
	//	   "x-hasura-default-role": "user",
	//	   "x-hasura-user-id": "be9eb329-df97-48a9-9346-f76755f3fe42",
	//	   "x-hasura-user-is-anonymous": "false"
	//	 },
	hasuraClaims := jwt.MapClaims{}

	var allowedRoles [2]string
	allowedRoles[0] = "user"
	allowedRoles[1] = "me"

	hasuraClaims["x-hasura-fan-id"] = "28de3732-2ef5-4a6e-988e-fc5db33bcdea"
	hasuraClaims["x-hasura-allowed-roles"] = allowedRoles
	hasuraClaims["x-hasura-default-role"] = "user"
	hasuraClaims["x-hasura-user-id"] = "be9eb329-df97-48a9-9346-f76755f3fe42"
	hasuraClaims["x-hasura-user-is-anonymous"] = "false"

	claims["https://hasura.io/jwt/claims"] = hasuraClaims
	claims["sub"] = "be9eb329-df97-48a9-9346-f76755f3fe42"

	token, err := CreateToken(claims, 10)
	assert.Nil(t, err)
	fmt.Printf("Token: %s", token)
}

func Test_urlFromSubdomain_localhost(t *testing.T) {
	for service := Auth; service <= Graphql; service++ {
		expected1 := fmt.Sprintf("http://localhost:1337/v1/%s", serviceNames[service])
		url, _ := urlFromSubdomain("localhost", "", service)
		assert.Equal(t, expected1, url, "urls should match")
		url, _ = urlFromSubdomain("http://localhost", "", service)
		assert.Equal(t, expected1, url, "urls should match")

		expected2 := fmt.Sprintf("https://localhost:1337/v1/%s", serviceNames[service])
		url, _ = urlFromSubdomain("https://localhost", "", service)
		assert.Equal(t, expected2, url, "urls should match")
		url, _ = urlFromSubdomain("https://localhost:1337", "", service)
		assert.Equal(t, expected2, url, "urls should match")

		expected3 := fmt.Sprintf("http://localhost:5678/v1/%s", serviceNames[service])
		url, _ = urlFromSubdomain("http://localhost:5678", "", service)
		assert.Equal(t, expected3, url, "urls should match")

		// IP addresses should be handled the same as "localhost"

		expected4 := fmt.Sprintf("http://192.168.100.55:1337/v1/%s", serviceNames[service])
		url, _ = urlFromSubdomain("192.168.100.55", "", service)
		assert.Equal(t, expected4, url, "urls should match")
		url, _ = urlFromSubdomain("http://192.168.100.55", "", service)
		assert.Equal(t, expected4, url, "urls should match")

		expected5 := fmt.Sprintf("https://192.168.100.55:1337/v1/%s", serviceNames[service])
		url, _ = urlFromSubdomain("https://192.168.100.55", "", service)
		assert.Equal(t, expected5, url, "urls should match")
		url, _ = urlFromSubdomain("https://192.168.100.55:1337", "", service)
		assert.Equal(t, expected5, url, "urls should match")

		expected6 := fmt.Sprintf("http://192.168.100.55:5678/v1/%s", serviceNames[service])
		url, _ = urlFromSubdomain("http://192.168.100.55:5678", "", service)
		assert.Equal(t, expected6, url, "urls should match")

	}
}

func Test_urlFromSubdomain_nhost(t *testing.T) {
	subdomain := "somesubdomain"
	region := "someregion"
	for service := Auth; service <= Graphql; service++ {
		expected := fmt.Sprintf("https://%s.%s.%s.nhost.run/v1", subdomain, serviceNames[service], region)
		url, _ := urlFromSubdomain(subdomain, region, service)
		assert.Equal(t, expected, url, "urls should match")
	}
}

func Test_urlFromSubdomain_nhost_noRegion(t *testing.T) {
	// when panic() called, recover, ie. continue test
	defer func() { _ = recover() }()

	subdomain := "somesubdomain"
	region := ""
	for service := Auth; service <= Graphql; service++ {
		urlFromSubdomain(subdomain, region, service)
		t.Errorf("did not panic")
	}
}

func Test_signIn_tokenRefresh_signOut(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	responderSignInResponse := CreateSigninResponse()

	// We expect back this
	var expectedSignInResponse hasura_auth.SignInResponse
	json.Unmarshal([]byte(responderSignInResponse), &expectedSignInResponse)

	// Respond with static responderSignInResponse
	//	`{"session":{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJodHRwczovL2hhc3VyYS5pby9qd3QvY2xhaW1zIjp7IngtaGFzdXJhLWZhbi1pZCI6IjI4ZGUzNzMyLTJlZjUtNGE2ZS05ODhlLWZjNWRiMzNiY2RlYSIsIngtaGFzdXJhLWFsbG93ZWQtcm9sZXMiOlsidXNlciIsIm1lIl0sIngtaGFzdXJhLWRlZmF1bHQtcm9sZSI6InVzZXIiLCJ4LWhhc3VyYS11c2VyLWlkIjoiYmU5ZWIzMjktZGY5Ny00OGE5LTkzNDYtZjc2NzU1ZjNmZTQyIiwieC1oYXN1cmEtdXNlci1pcy1hbm9ueW1vdXMiOiJmYWxzZSJ9LCJzdWIiOiJiZTllYjMyOS1kZjk3LTQ4YTktOTM0Ni1mNzY3NTVmM2ZlNDIiLCJpYXQiOjE2NzE4MjIzNTksImV4cCI6MTY3MTgyMjg1OSwiaXNzIjoiaGFzdXJhLWF1dGgifQ.I2uY0Lp_ZQLT6aDIkej26tieE8REjdjTcDpgDY0RUYU","accessTokenExpiresIn":500,"refreshToken":"5cca0478-5e5c-44c1-84fc-619b5f456957","user":{"id":"be9eb329-df97-48a9-9346-f76755f3fe42","createdAt":"2022-12-03T10:14:53.254353+00:00","displayName":"asd@asd.as","avatarUrl":"https://s.gravatar.com/avatar/26f716bfba89b71dc1f67cb893a21867?r=g&default=blank","locale":"en","email":"asd@asd.as","isAnonymous":false,"defaultRole":"user","metadata":{},"emailVerified":false,"phoneNumber":null,"phoneNumberVerified":false,"activeMfaType":null,"roles":["user","me"]}},"mfa":null}`)
	httpmock.RegisterResponder("POST", "http://localhost:1337/v1/auth/signin/email-password",
		httpmock.NewStringResponder(200, responderSignInResponse))

	// Generate a new response when called, so that dates are up-to-date in the response
	httpmock.RegisterResponder("POST", "http://localhost:1337/v1/auth/token",
		func(req *http.Request) (*http.Response, error) {
			log.Debugf("http://localhost:1337/v1/auth/token called at %s", time.Now())
			return httpmock.NewStringResponse(200, CreateRefreshTokenResponse()), nil
		})

	httpmock.RegisterResponder("POST", "http://localhost:1337/v1/auth/signout",
		httpmock.NewStringResponder(200, ""))

	client, err := New("localhost", "")
	assert.Nil(t, err)

	var tokenChangeReported bool = false
	var signInReported bool = false
	var signOutReported bool = false
	client.Auth.OnTokenChanged(func(session *hasura_auth.Session) {
		tokenChangeReported = true
	})
	client.Auth.OnAuthStateChanged(func(event hasura_auth.AuthChangeEvent, session *hasura_auth.Session) {
		if event == hasura_auth.SIGNED_IN {
			signInReported = true
		}
		if event == hasura_auth.SIGNED_OUT {
			signOutReported = true
		}
	})

	signInResp := client.Auth.SignInEmailPassword(hasura_auth.SignInEmailPasswordParams{
		Email:    "asd@asd.as",
		Password: "asd",
	})
	assert.Nil(t, signInResp.Error)
	fmt.Printf("signInResp.Session: %#v", signInResp.Session)

	// If all json processing is correct, we get back the same expectedSignInResponse we sent in httpmock
	assert.Equal(t, expectedSignInResponse, signInResp)

	// Wait 5 seconds, ie. 3 /token calls
	time.Sleep(time.Duration(4) * time.Second)

	client.Auth.SignOut(hasura_auth.SignOutParams{All: true})

	info := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, info["POST http://localhost:1337/v1/auth/signin/email-password"])
	assert.Equal(t, 3, info["POST http://localhost:1337/v1/auth/token"])
	assert.Equal(t, 1, info["POST http://localhost:1337/v1/auth/signout"])
	assert.True(t, signInReported)
	assert.True(t, tokenChangeReported)
	assert.True(t, signOutReported)

}

func Test_signIn_invalidIncorrectEmailOrPassword(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "http://localhost:1337/v1/auth/signin/email-password",
		httpmock.NewStringResponder(400, `{"status":401,"message":"Incorrect email or password","error":"invalid-email-password"}`))

	client, err := New("localhost", "")
	assert.Nil(t, err)
	signInResp := client.Auth.SignInEmailPassword(hasura_auth.SignInEmailPasswordParams{
		Email:    "asd@wrong.email",
		Password: "asd",
	})
	fmt.Println(signInResp)
	assert.NotNil(t, signInResp.Error)
	assert.Equal(t, uint(401), signInResp.Error.Status)
	assert.Equal(t, "invalid-email-password", signInResp.Error.Error)
	assert.Equal(t, "Incorrect email or password", signInResp.Error.Message)
}

func Test_signIn_invalidRequestEmail(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "http://localhost:1337/v1/auth/signin/email-password",
		httpmock.NewStringResponder(400, `{"status":400,"message":"\"email\" must be a valid email","error":"invalid-request"}`))

	client, err := New("localhost", "")
	assert.Nil(t, err)
	signInResp := client.Auth.SignInEmailPassword(hasura_auth.SignInEmailPasswordParams{
		Email:    "asd@asd.asd",
		Password: "asd",
	})
	fmt.Println(signInResp)
	assert.NotNil(t, signInResp.Error)
	assert.Equal(t, uint(400), signInResp.Error.Status)
	assert.Equal(t, "invalid-request", signInResp.Error.Error)
	assert.Equal(t, `"email" must be a valid email`, signInResp.Error.Message)
}

func Test_getPresignedUrl(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	client, err := New("localhost", "")
	assert.Nil(t, err)
	assert.Equal(t, "", client.Storage.AccessToken)

	//
	// Try without authentication
	//
	httpmock.RegisterResponder("GET", "http://localhost:1337/v1/storage/files/137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e/presignedurl",
		httpmock.NewStringResponder(404, `{"error":{"message":"file not found"}}`))
	res, err := client.Storage.GetPresignedUrl("137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e")
	assert.Nil(t, err)
	fmt.Println(res)
	assert.Equal(t, "file not found", res.Error.Message)

	//
	// Sign in
	//
	responderSignInResponse := CreateSigninResponse()
	var expectedSignInResponse hasura_auth.SignInResponse
	json.Unmarshal([]byte(responderSignInResponse), &expectedSignInResponse)
	httpmock.RegisterResponder("POST", "http://localhost:1337/v1/auth/signin/email-password",
		httpmock.NewStringResponder(200, responderSignInResponse))
	signInResp := client.Auth.SignInEmailPassword(hasura_auth.SignInEmailPasswordParams{
		Email:    "asd@asd.as",
		Password: "asd",
	})
	fmt.Println(signInResp)
	assert.Equal(t, expectedSignInResponse, signInResp)
	fmt.Println(client.Storage.AccessToken)
	assert.NotEqual(t, "", client.Storage.AccessToken)

	//
	// Try with authentication
	//
	// {"url":"http://localhost:1337/v1/storage/files/137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e/presignedurl/content?X-Amz-Algorithm=AWS4-HMAC-SHA256\u0026X-Amz-Credential=minioaccesskey123123%2F20230102%2Fno-region%2Fs3%2Faws4_request\u0026X-Amz-Date=20230102T095711Z\u0026X-Amz-Expires=30\u0026X-Amz-SignedHeaders=host\u0026X-Amz-Signature=46a959f3c5d615c15ba8e3cead08a9bc8fb2b35d5bdd404f6f1a5ac1eee65470","expiration":30}
	httpmock.RegisterResponder("GET", "http://localhost:1337/v1/storage/files/137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e/presignedurl",
		httpmock.NewStringResponder(200, `{"url":"http://localhost:1337/v1/storage/files/137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e/presignedurl/content?X-Amz-Algorithm=AWS4-HMAC-SHA256\u0026X-Amz-Credential=minioaccesskey123123%2F20230102%2Fno-region%2Fs3%2Faws4_request\u0026X-Amz-Date=20230102T095711Z\u0026X-Amz-Expires=30\u0026X-Amz-SignedHeaders=host\u0026X-Amz-Signature=46a959f3c5d615c15ba8e3cead08a9bc8fb2b35d5bdd404f6f1a5ac1eee65470","expiration":30}`))
	res, err = client.Storage.GetPresignedUrl("137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e")
	assert.Nil(t, err)
	fmt.Println(res)
	assert.True(t, strings.HasPrefix(res.PresignedUrl.Url, "http://localhost:1337/v1/storage/files/137c616a-bcfe-4bc2-b9b8-9ae0c9cdaa1e/presignedurl/content?"))
}
