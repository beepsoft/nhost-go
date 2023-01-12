package hasura_auth

import (
	"regexp"
	"strings"
)

const (
	EMAIL_REGEXP = `^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$`
)

func isValidEmail(email string) bool {

	// export const isValidEmail = (email?: string | null) =>
	//  !!email &&
	//  typeof email === 'string' &&
	//  !!String(email)
	//    .toLowerCase()
	//    .match(
	//      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
	//    )
	re := regexp.MustCompile(EMAIL_REGEXP)
	return re.MatchString(strings.ToLower(email))
}

func isValidPassword(password string) bool {
	// export const isValidPassword = (password?: string | null) =>
	//  !!password && typeof password === 'string' && password.length >= MIN_PASSWORD_LENGTH
	return len(password) >= MIN_PASSWORD_LENGTH
}

func isValidPhoneNumber(phoneNumber string) bool {
	// // TODO improve validation
	//export const isValidPhoneNumber = (phoneNumber?: string | null) =>
	//  !!phoneNumber && typeof phoneNumber === 'string'
	panic("Not implemented yet")
}

func isValidTicket(ticket string) bool {
	//   ticket &&
	//  typeof ticket === 'string' &&
	//  ticket.match(/^mfaTotp:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
	panic("Not implemented yet")
}
