package auth


type User struct {
	credentials map[string]UserCredentials
}

type UserCredentials interface {

}
