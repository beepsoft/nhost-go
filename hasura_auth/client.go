package hasura_auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/beepshow/nhost-go/common"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"reflect"
	"time"
)

type OnTokenChangedCallback func(session *Session)
type OnAuthChangedCallback func(event AuthChangeEvent, session *Session)

type AuthClient struct {
	Url                 string
	AutoRefreshToken    bool
	AutoSignIn          bool
	AutoLogin           bool
	RefreshIntervalTime uint

	onTokenChangedFunctions map[uintptr]OnTokenChangedCallback
	onAuthChangedFunctions  map[uintptr]OnAuthChangedCallback
	clientStorage           ClientStorage
	started                 bool
	authStatus              AuthStatus
	session                 *Session // The current session
	clientUrl               string   // New's URL we can redirect to
	httpClient              http.Client
	nextRefresh             time.Time
	refreshTimer            *time.Timer
}

type AuthStatus struct {
	Authentication     AuthState
	Loading            bool
	ConnectionAttempts uint
}

type AuthState uint8

const (
	SIGNED_OUT_STATE AuthState = iota
	SIGNED_IN_STATE
)

type UserType struct {
	ID                  string                 `json:"id"`                  // User's unique identifier (uuid)
	CreatedAt           string                 `json:"createdAt"`           // The date-time when the user has been created
	DisplayName         string                 `json:"displayName"`         // User's display name
	AvatarUrl           string                 `json:"avatarUrl"`           // @example `'en'`
	Locale              string                 `json:"locale"`              // The locale of the user, as a two-characters string @example `'en'`
	Email               string                 `json:"email"`               // User's email address
	IsAnonymous         bool                   `json:"isAnonymous"`         // Wether or not the user is anonymous
	DefaultRole         string                 `json:"defaultRole"`         // The default role of the user @example `'user'`
	Roles               []string               `json:"roles"`               // The roles assigned to the user @example `['user', 'me']`
	Metadata            map[string]interface{} `json:"metadata"`            // Additional attributes used for user information
	EmailVerified       bool                   `json:"emailVerified"`       // Is `true` if the user email has not been verified
	PhoneNumber         string                 `json:"phoneNumber"`         //
	PhoneNumberVerified bool                   `json:"phoneNumberVerified"` //
	ActiveMfaType       string                 `json:"activeMfaType"`       // 'totp' | null
}

type Session struct {
	AccessToken          string   `json:"accessToken"`
	AccessTokenExpiresIn uint     `json:"accessTokenExpiresIn"`
	RefreshToken         string   `json:"refreshToken"`
	User                 UserType `json:"user"`
}

type AuthChangeEvent uint8

const (
	SIGNED_IN AuthChangeEvent = iota + 1
	SIGNED_OUT
)

func (client *AuthClient) Start() {
	client.started = true
	set := hashset.New()
	_ = set.Values()
}

func (client *AuthClient) OnTokenChanged(fn func(session *Session)) {
	ptr := reflect.ValueOf(fn).Pointer()
	if client.onTokenChangedFunctions[ptr] == nil {
		client.onTokenChangedFunctions[ptr] = fn
	}
}

func (client *AuthClient) reportTokenChanged(session *Session) {
	for _, element := range client.onTokenChangedFunctions {
		element(session)
	}
}

func (client *AuthClient) OnAuthStateChanged(fn func(event AuthChangeEvent, session *Session)) {
	ptr := reflect.ValueOf(fn).Pointer()
	if client.onAuthChangedFunctions[ptr] == nil {
		client.onAuthChangedFunctions[ptr] = fn
	}
}

func (client *AuthClient) reportAuthStateChanged(event AuthChangeEvent, session *Session) {
	for _, element := range client.onAuthChangedFunctions {
		element(event, session)
	}
}

func (client *AuthClient) IsAuthenticated() bool {
	return client.authStatus.Authentication == SIGNED_IN_STATE
}

func (client *AuthClient) AuthenticationStatus() AuthStatus {
	return client.authStatus
}

func (client *AuthClient) AccessToken() string {
	if client.Session() == nil {
		return ""
	}
	return client.Session().AccessToken
}

func (client *AuthClient) Session() *Session {
	return client.session
}

func (client *AuthClient) User() UserType {
	return client.session.User
}

// TODO: do we need redirecttion?
func (client *AuthClient) rewriteRedirectTo() {
	// TODO
}

func (client *AuthClient) encodeQueryParameters(baseUrl string) {
	// TODO
}

type SignInEmailPasswordParams struct {
	Email    string
	Password string
}

type SignOutParams struct {
	All bool
}

type SignInEmailPasswordOtpParams struct {
	Otp    string
	Ticket string
}

type RegistrationOptions struct {
	//   /**
	//   * Locale of the user, in two digits
	//   * @example `'en'`
	//   */
	//  locale?: string
	//  /**
	//   * Allowed roles of the user. Must be a subset of the default allowed roles defined in Hasura Auth.
	//   * @example `['user','me']`
	//   */
	//  allowedRoles?: string[]
	//  /**
	//   * Default role of the user. Must be part of the default allowed roles defined in Hasura Auth.
	//   * @example `'user'`
	//   */
	//  defaultRole?: string
	//  /**
	//   * Display name of the user. If not provided, it will use the display name given by the social provider (Oauth) used on registration, or the email address otherwise.
	//   */
	//  displayName?: string
	//  /**
	//   * Custom additional user information stored in the `metadata` column. Can be any JSON object.
	//   * @example `{ firstName: 'Bob', profession: 'builder' }`
	//   */
	//  metadata?: Record<string, unknown>
}

type RedirectOption struct {
	/**
	 * Redirection path in the client application that will be used in the link in the verification email.
	 * For instance, if you want to redirect to `https://myapp.com/success`, the `redirectTo` value is `'/success'`.
	 */
	RedirectTo string
}

type PasswordlessOptions struct {
	RegistrationOptions
	RedirectOption
}
type SignInPasswordlessEmailParams struct {
	Email string
	PasswordlessOptions
}

type SignInPasswordlessSecurityKeyParams struct {
	Email       string
	SecurityKey bool // should be true
}

type SignInPasswordlessSmsOtpParams struct {
	PhoneNumber string
	Otp         string
}

type SignInPasswordlessSmsParams struct {
	PhoneNumber string
	PasswordlessOptions
}

type Provider uint8

const (
	UNSET_PROVIDER Provider = iota
	APPLE
	AZUREAD
	BITBUCKET
	DISCORD
	FACEBOOK
	GITHUB
	GITLAB
	GOOGLE
	LINKEDIN
	SPOTIFY
	STRAVA
	TWITCH
	TWITTER
	WINDOWSLIVE
	WORKOS
)

type CommonProviderOptions struct {
	RegistrationOptions
	RedirectOption
}

type SignInWithProviderParams struct {
	Provider
	CommonProviderOptions
}

type SignInParams struct {
	SignInEmailPasswordParams
	SignInEmailPasswordOtpParams
	SignInPasswordlessEmailParams
	SignInPasswordlessSecurityKeyParams
	SignInPasswordlessSmsOtpParams
	SignInPasswordlessSmsParams
	SignInWithProviderParams
}

type Mfa struct {
	Ticket string `json:"ticket"`
}

type SignInResponse struct {
	*Session `json:"session"`     // maybe nil
	*Mfa     `json:"mfa"`         // maybe nil
	Error    *common.ErrorPayload `json:"error"` // maybe nil
}

func (client *AuthClient) SignInEmailPassword(params SignInEmailPasswordParams) SignInResponse {
	resp := SignInResponse{
		Session: nil,
		Mfa:     nil,
		Error:   nil,
	}

	if params.Email == "" {
		resp.Error.Error = "Email not provided"
		return resp
	}

	if params.Password == "" {
		resp.Error.Error = "Password not provided"
		return resp
	}

	if !isValidEmail(params.Email) {
		resp.Error = INVALID_EMAIL_ERROR
		return resp
	}

	if !isValidPassword(params.Password) {
		resp.Error = INVALID_PASSWORD_ERROR
		return resp
	}

	data := make(map[string]interface{})
	data["email"] = params.Email
	data["password"] = params.Password

	jsonRes, err := client.postRequest("/signin/email-password", &data)
	if err != nil {
		resp.Error = &common.ErrorPayload{
			Error:   err.Error(),
			Status:  NETWORK_ERROR_CODE,
			Message: err.Error(),
		}
		return resp
	}

	// Does it contain an error?
	var mapRes map[string]interface{}
	json.Unmarshal([]byte(jsonRes), &mapRes)
	if mapRes["error"] != nil {
		var jsonErr common.ErrorPayload
		json.Unmarshal([]byte(jsonRes), &jsonErr)
		resp.Error = &jsonErr
		return resp
	}

	// Unmarshall as a normal result
	var result SignInResponse
	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal([]byte(jsonRes), &result)

	client.reportAuthStateChanged(SIGNED_IN, result.Session)

	client.saveSession(result.Session)

	return result
}

func (client *AuthClient) SignOut(params SignOutParams) *common.ErrorPayload {
	data := make(map[string]interface{})
	data["refreshToken"] = client.session.RefreshToken
	data["all"] = params.All
	jsonRes, err := client.postRequest("/signout", &data)

	if err != nil {
		// TODO: retry?
		//resp.Error = &ErrorPayload{
		//	Error:   err.Error(),
		//	Status:  NETWORK_ERROR_CODE,
		//	Message: err.Error(),
		//}
		//return resp
	}

	// Does it contain an error?
	var mapRes map[string]interface{}
	json.Unmarshal([]byte(jsonRes), &mapRes)
	if mapRes["error"] != nil {
		var jsonErr common.ErrorPayload
		json.Unmarshal([]byte(jsonRes), &jsonErr)
		client.saveSession(nil)
		return &jsonErr
	}

	client.saveSession(nil)

	return nil
}

func (client *AuthClient) postRequest(url string, data *map[string]interface{}) (string, error) {
	return client.postRequestWithHeaders(url, data, nil)
}

func (client *AuthClient) postRequestWithHeaders(url string, data *map[string]interface{}, headers map[string][]string) (string, error) {
	requestUrl := fmt.Sprintf("%s%s", client.Url, url)
	dataBytes, _ := json.Marshal(data)
	bodyReader := bytes.NewReader(dataBytes)
	req, err := http.NewRequest(http.MethodPost, requestUrl, bodyReader)
	if err != nil {
		return "", err
	}

	// Set all headers from param
	if headers != nil {
		req.Header = headers
	}
	req.Header.Set("Content-TYpe", "application/json")

	// Run the request
	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Printf("client: error making http request: %s\n", err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)                              // response body is []byte
	log.Debugf("postRequestWithHeaders Result: %s\n", string(body)) // convert to string before print

	return string(body), err
}

func (client *AuthClient) SignIn(params *SignInParams) SignInResponse {
	if params == nil {
		// TODO: Anonymous sign-in
		return SignInResponse{}
	}

	// Sign in with a social provider (OAuth)
	if params.Provider != UNSET_PROVIDER {
		// TODO
		return SignInResponse{}
	}

	// Email + password
	if params.SignInEmailPasswordParams.Email != "" && params.SignInEmailPasswordParams.Password != "" {
		return client.SignInEmailPassword(params.SignInEmailPasswordParams)
	}

	if params.SignInPasswordlessSecurityKeyParams.Email != "" && params.SignInPasswordlessSecurityKeyParams.SecurityKey {
		// TODO
		return SignInResponse{}
	}

	// * Passwordless Email (magic link)
	if params.SignInPasswordlessEmailParams.Email != "" {
		// TODO
		return SignInResponse{}
	}

	// * Passwordless SMS: [step 2/2] sign in using SMS OTP
	if params.SignInPasswordlessSmsOtpParams.PhoneNumber != "" && params.SignInPasswordlessSmsOtpParams.Otp != "" {
		// TODO
		return SignInResponse{}
	}

	// * Passwordless SMS: [step 1/2] sign in using SMS
	if params.SignInPasswordlessSmsParams.PhoneNumber != "" {
		// TODO
		return SignInResponse{}
	}

	// * Email + password MFA TOTP
	if params.SignInEmailPasswordOtpParams.Otp != "" {
		// TODO
		return SignInResponse{}
	}

	return SignInResponse{
		Error:   INVALID_SIGN_IN_METHOD,
		Mfa:     nil,
		Session: nil,
	}

	return SignInResponse{}
}

type AuthClaims struct {
	jwt.RegisteredClaims
	HasuraClaims map[string]interface{} `json:"https://hasura.io/jwt/claims"`
}

func (client *AuthClient) DecodedAccessToken() (*jwt.Token, *AuthClaims, error) {
	claims := AuthClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(client.AccessToken(), &claims)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	//fmt.Println(token.Claims)
	//fmt.Println(claims)
	return token, &claims, nil
}

func (client *AuthClient) HasuraClaims() (map[string]interface{}, error) {
	_, claims, err := client.DecodedAccessToken()
	if err != nil {
		return nil, err
	}
	//fmt.Println(claims)
	return claims.HasuraClaims, nil
}

func (client *AuthClient) saveSession(session *Session) {
	client.session = session
	if client.refreshTimer != nil {
		client.refreshTimer.Stop()
	}
	client.reportTokenChanged(session)
	if session == nil {
		client.clientStorage.SetItem(NHOST_JWT_EXPIRES_AT_KEY, "")
		client.clientStorage.SetItem(NHOST_REFRESH_TOKEN_KEY, "")
		client.reportAuthStateChanged(SIGNED_OUT, nil)
	} else {
		refreshInSeconds := session.AccessTokenExpiresIn
		if client.RefreshIntervalTime != 0 {
			refreshInSeconds = client.RefreshIntervalTime
		}

		client.nextRefresh = time.Now().Local().Add(time.Second * time.Duration(refreshInSeconds))
		client.clientStorage.SetItem(NHOST_JWT_EXPIRES_AT_KEY, client.nextRefresh.Format(time.RFC3339))
		client.clientStorage.SetItem(NHOST_REFRESH_TOKEN_KEY, session.RefreshToken)

		client.refreshTimer = time.NewTimer(time.Second * time.Duration(refreshInSeconds-uint(refreshInSeconds*2/3)))
		go func() {
			<-client.refreshTimer.C
			client.refreshTimer = nil
			client.RefreshToken()
		}()
	}
}

func (client *AuthClient) RefreshToken() error {
	data := make(map[string]interface{})
	data["refreshToken"] = client.session.RefreshToken

	jsonRes, err := client.postRequest("/token", &data)

	if err != nil {
		// TODO: retry?
		//resp.Error = &ErrorPayload{
		//	Error:   err.Error(),
		//	Status:  NETWORK_ERROR_CODE,
		//	Message: err.Error(),
		//}
		//return resp
	}

	// Does it contain an error?
	var mapRes map[string]interface{}
	json.Unmarshal([]byte(jsonRes), &mapRes)
	if mapRes["error"] != nil {
		var jsonErr common.ErrorPayload
		json.Unmarshal([]byte(jsonRes), &jsonErr)
		// TODO: what to do with the error?
		return nil
		//resp.Error = &jsonErr
		//return resp
	}

	// The result is a Session
	var newSession Session
	err = json.Unmarshal([]byte(jsonRes), &newSession)
	if err != nil {
		return err
	}
	client.saveSession(&newSession)
	return nil
}

func New(
	backendUrl string,
	clientUrl string,
	autoRefreshToken bool,
	autoSignIn bool,
	autoLogin bool,
	clientStorage ClientStorage,
	refreshIntervalTime uint,
	start bool) (*AuthClient, error) {

	client := AuthClient{
		Url:                     backendUrl,
		AutoRefreshToken:        autoRefreshToken,
		AutoSignIn:              autoSignIn,
		AutoLogin:               autoLogin,
		RefreshIntervalTime:     refreshIntervalTime,
		clientStorage:           clientStorage,
		onTokenChangedFunctions: make(map[uintptr]OnTokenChangedCallback),
		onAuthChangedFunctions:  make(map[uintptr]OnAuthChangedCallback),
		clientUrl:               clientUrl,
		httpClient:              http.Client{},
	}

	if start {
		client.Start()
	}

	return &client, nil
}
