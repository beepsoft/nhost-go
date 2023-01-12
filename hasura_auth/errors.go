package hasura_auth

import (
	"github.com/beepshow/nhost-go/common"
)

const (
	NETWORK_ERROR_CODE    = 0
	OTHER_ERROR_CODE      = 1
	VALIDATION_ERROR_CODE = 10
	STATE_ERROR_CODE      = 20
)

var (
	TOKEN_REFRESHER_RUNNING_ERROR = &common.ErrorPayload{
		Status:  STATE_ERROR_CODE,
		Error:   "refresher-already-running",
		Message: "The token refresher is already running. You must wait until is has finished before submitting a new token.",
	}

	USER_ALREADY_SIGNED_IN = &common.ErrorPayload{
		Status:  STATE_ERROR_CODE,
		Error:   "already-signed-in",
		Message: "User is already signed in",
	}

	USER_UNAUTHENTICATED = &common.ErrorPayload{
		Status:  STATE_ERROR_CODE,
		Error:   "unauthenticated-user",
		Message: "User is not authenticated",
	}
	USER_NOT_ANONYMOUS = &common.ErrorPayload{
		Status:  STATE_ERROR_CODE,
		Error:   "user-not-anonymous",
		Message: "User is not anonymous",
	}
	EMAIL_NEEDS_VERIFICATION = &common.ErrorPayload{
		Status:  STATE_ERROR_CODE,
		Error:   "unverified-user",
		Message: "Email needs verification",
	}

	INVALID_REFRESH_TOKEN = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-refresh-token",
		Message: "Invalid or expired refresh token",
	}

	INVALID_SIGN_IN_METHOD = &common.ErrorPayload{
		Status:  OTHER_ERROR_CODE,
		Error:   "invalid-sign-in-method",
		Message: "invalid-sign-in-method",
	}

	INVALID_EMAIL_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-email",
		Message: "Email is incorrectly formatted",
	}

	INVALID_MFA_TYPE_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-mfa-type",
		Message: "MFA type is invalid",
	}

	INVALID_MFA_CODE_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-mfa-code",
		Message: "MFA code is invalid",
	}

	INVALID_PASSWORD_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-password",
		Message: "Password is incorrectly formatted",
	}

	INVALID_PHONE_NUMBER_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-phone-number",
		Message: "Phone number is incorrectly formatted",
	}

	INVALID_MFA_TICKET_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "invalid-mfa-ticket",
		Message: "MFA ticket is invalid",
	}

	NO_MFA_TICKET_ERROR = &common.ErrorPayload{
		Status:  VALIDATION_ERROR_CODE,
		Error:   "no-mfa-ticket'",
		Message: "No MFA ticket has been provided",
	}
)
