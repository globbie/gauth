package json

import (
	"encoding/json"
	"github.com/globbie/gauth/pkg/auth/view"
	"net/http"
)

const ViewType = "json"

type Config struct {
	Indent string
}

func (c Config) New(contentType string) (view.View, error) {
	v := View{
		Config: c,
	}
	return &v, nil
}

type View struct {
	Config
}

func (v *View) Login(w http.ResponseWriter, info []view.ProviderInfo) error {
	resp, err := json.MarshalIndent(info, "", v.Indent)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
	return nil
}
