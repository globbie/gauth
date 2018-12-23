package staticView

import (
	"github.com/globbie/gauth/pkg/auth/view"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

const (
	ViewType = "static"

	indexTemplate    = "index.html"
	loginTemplate    = "login.html"
	registerTemplate = "register.html"
)

type Config struct {
	Address      string `json:"address"`
	StaticDir    string `json:"static-dir"`
	TemplatesDir string `json:"templates-dir"`
}

func (c Config) New(contentType string) (view.View, error) {
	static := http.StripPrefix("/static/", http.FileServer(http.Dir(c.StaticDir)))
	v := View{
		Config: c,
		static: static,
	}
	v.loadTemplates()
	return &v, nil
}

type View struct {
	Config

	static http.Handler

	index    *template.Template
	login    *template.Template
	register *template.Template
	notFound *template.Template
}

func (v *View) loadTemplates() {
	files, err := ioutil.ReadDir(v.TemplatesDir)
	if err != nil {
		log.Fatalf("could not read templates c.templatesPathectory '%v', err: %v", v.TemplatesDir, err)
	}

	var fileNames []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileNames = append(fileNames, filepath.Join(v.TemplatesDir, file.Name()))
	}
	if len(fileNames) == 0 {
		log.Fatalf("no templates were found in '%v'", v.TemplatesDir)
	}
	templates, err := template.ParseFiles(fileNames...)
	if err != nil {
		log.Fatalln("could not parse files, err:", err)
	}

	v.index = templates.Lookup(indexTemplate)
	if v.index == nil {
		log.Fatalln("could not find index template")
	}
	v.login = templates.Lookup(loginTemplate)
	if v.login == nil {
		log.Fatalln("could not find login template")
	}
	v.register = templates.Lookup(registerTemplate)
	if v.register == nil {
		log.Fatalln("could not find register template")
	}
}

func (v *View) Login(w http.ResponseWriter, info []view.ProviderInfo) error {
	data := struct {
		Providers []view.ProviderInfo
	}{
		info,
	}
	v.login.Execute(w, data)
	return nil
}
