package common

type ErrorPayload struct {
	Error   string `json:"error"`
	Status  uint   `json:"status"`
	Message string `json:"message"`
}
