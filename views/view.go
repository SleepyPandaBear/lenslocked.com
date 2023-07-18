package views

import (
    "html/template"
    "path/filepath"
    "net/http"
    "net/url"
    "bytes"
    "io"
    "errors"
    "github.com/gorilla/csrf"

    "lenslocked.com/context"
)

var (
    LayoutDir string = "./views/layouts/"
    TemplateExt string = ".tmpl"
    TemplateDir string = "./views/"
)

type View struct {
    Template *template.Template
    Layout string
}

func (v *View) Render(w http.ResponseWriter, r *http.Request, data interface{}) {
    w.Header().Set("Content-Type", "text/html")

    var vd Data

    switch d := data.(type) {
    case Data:
        vd = d
    default:
        vd = Data{
            Yield: data,
        }
    }

    if alert := getAlert(r); alert != nil {
        vd.Alert = alert
        clearAlert(w)
    }

    vd.User = context.User(r.Context())
    var buf bytes.Buffer

    csrfField := csrf.TemplateField(r)
    tpl := v.Template.Funcs(template.FuncMap{
        "csrfField": func() template.HTML {
            return csrfField
        },
    })

    err := tpl.ExecuteTemplate(&buf, v.Layout, vd)
    if err != nil {
        http.Error(w, "someting went wrong", http.StatusInternalServerError)
        return
    }

    io.Copy(w, &buf)
}

func (v *View) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    v.Render(w, r, nil)
}

func layoutFiles() []string {
    files, err := filepath.Glob(LayoutDir + "*" + TemplateExt)

    if err != nil {
        panic(err)
    }

    return files
}

func addTemplatePath(files []string) {
    for i, f := range files {
        files[i] = TemplateDir + f
    }
}

func addTemplateExt(files []string) {
    for i, f := range files {
        files[i] = f + TemplateExt
    }
}

func NewView(layout string, files ...string) *View {
    addTemplatePath(files)
    addTemplateExt(files)

    files = append(files, layoutFiles()...)

    t, err := template.New("").Funcs(template.FuncMap{
        "csrfField": func() (template.HTML, error) {
            return "", errors.New("ccsrfField is not implemented")
        },
        "pathEscape": func(s string) string {
            return url.PathEscape(s)
        },
    }).ParseFiles(files...)

    if err != nil {
        panic(err)
    }

    return &View {
        Template: t,
        Layout: layout,
    }

}
