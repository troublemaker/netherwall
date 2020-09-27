package main

import (
	"github.com/coreos/go-iptables/iptables"
	"ipvoid/config"
	"ipvoid/jail"
	"ipvoid/watch"
	"ipvoid/web"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	err := config.Setup()
	if err != nil {
		log.Println("Config error: %s \n", err.Error())
		os.Exit(1)
	}

	//Init IP Tables interface
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("IPtables init issue: %s \n", err.Error())
		os.Exit(1)
	}

	err = jail.Setup(ipt)
	if err != nil {
		log.Printf("IPtables setup issue: %s \n", err.Error())
		os.Exit(1)
	}

	//Launch main watcher loop
	go watch.Run()

	//Launch webserver
	go web.Webserver()

	//graceful shutdown
	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	<-terminate
	log.Println("Shutting down")

	jail.ClearJail()
	watch.StoreState()

	os.Exit(0)
}
