package auth

type Error struct {
	StatusCode    int
	Message       string
	PublicMessage string
}

func (e Error) Error() string {
	return e.Message
}
