package web

import (
	"html/template"
	"ipvoid/voidlog"
	"net/http"
	"sort"
	"ipvoid/jail"
	"ipvoid/resolver"
	"ipvoid/watch"
)

type StatPageData struct {
	Watchlist []stat
	Jaillist  []stat
	History   []string
	Log       []string
}

type stat struct {
	IP    string
	Score float32
	Host  string
}


func init() {

}

var tmpl *template.Template

func Webserver() {
	tmpl = template.Must(template.ParseFiles("template/index.html"))
	http.HandleFunc("/stats", statsPage)
	http.ListenAndServe(":9900", nil)
}


func statsPage(w http.ResponseWriter, r *http.Request) {
	data := StatPageData{}

	var statWatch []stat
	var statJail []stat
	var stathistory []string
	var log []string

	//sorting watch list
	for k, v := range watch.Watchlist {
		host := resolver.Lookup(k)
		statWatch = append(statWatch, stat{k, v, host})
	}

	sort.Slice(statWatch, func(i, j int) bool {
		return statWatch[i].Score > statWatch[j].Score
	})

	//sorting jail list
	for k, v := range jail.Ip_list {
		host := resolver.Lookup(k)
		statJail = append(statJail, stat{k, v, host})
	}

	sort.Slice(statJail, func(i, j int) bool {
		return statJail[i].Score > statJail[j].Score
	})

	//copy jail history data
	jail.JailHistory.Do(func(p interface{}) {
		if p != nil {
			stathistory = append(stathistory, p.(string))
		}
	})
	//reverse history
	for i, j := 0, len(stathistory)-1; i < j; i, j = i+1, j-1 {
		stathistory[i], stathistory[j] = stathistory[j], stathistory[i]
	}

	//copy log data
	voidlog.LogHistory.Do(func(p interface{}) {
		if p != nil {
			log = append(log, p.(string))
		}
	})
	//reverse log
	for i, j := 0, len(log)-1; i < j; i, j = i+1, j-1 {
		log[i], log[j] = log[j], log[i]
	}

	data.Watchlist = statWatch
	data.Jaillist = statJail
	data.History = stathistory
	data.Log = log
	tmpl.Execute(w, data)
	}