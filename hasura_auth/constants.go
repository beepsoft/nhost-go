package hasura_auth

const (
	NHOST_REFRESH_TOKEN_KEY  = "nhostRefreshToken"
	NHOST_JWT_EXPIRES_AT_KEY = "nhostRefreshTokenExpiresAt"

	MIN_PASSWORD_LENGTH = 3

	/**
	 * Minimum time in seconds between now and the JWT expiration time before the JWT is refreshed
	 * For instance, if set to 60, the client will refresh the JWT one minute before it expires
	 */
	TOKEN_REFRESH_MARGIN = 300 // five minutes

	REFRESH_TOKEN_RETRY_INTERVAL = 5 // Number of seconds before retrying a token refresh after an error
)
