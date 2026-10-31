package main
func h(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get(r.URL.Query().Get("url"))                                   // EXPECT ssrf-user-url
	http.Redirect(w, r, r.URL.Query().Get("next"), 302)                             // EXPECT open-redirect
	db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", r.FormValue("id")))      // EXPECT sqli-interpolated
	exec.Command("sh", "-c", "convert "+r.FormValue("f"))                          // EXPECT cmd-injection
	t := template.HTML(r.FormValue("bio"))                                          // EXPECT xss-template-string
}
