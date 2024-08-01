package main

import (
	"encoding/json"
	"github.com/go-acme/lego/v4/certificate"
	"log"
	"os"
	"tgbot/certs"
	"tgbot/lego"
)

type Config struct {
	CaAccountEmail string `json:"ca_account_email"`
	WestUsername   string `json:"west_username"`
	WestPassword   string `json:"west_password"`
}

func main() {

	/**
	  tuiguang9bu433@163.com
	  tuiguang9bu
	  cdstk.com
	*/
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalln(err.Error())
	}
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalln(err.Error())
	}
	client, err := lego.NewLegoClient(config.CaAccountEmail, config.WestUsername, config.WestPassword)
	if err != nil {
		log.Fatal(err.Error())
	}
	certsStore := certs.NewCertificatesStorage()

	//Create a user. New accounts need an email and private key to start.

	request := certificate.ObtainRequest{
		Domains: []string{"cdstk.com", "*.cdstk.com"},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}
	certsStore.SaveResource(certificates)

}
