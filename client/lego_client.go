package client

import (
	"letsgo/accounts"
	"letsgo/config"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
)

func NewLegoClient(ca config.CAInfo, p challenge.Provider) (*lego.Client, error) {
	accountStore := accounts.NewAccountsStorage(ca.AccountEmail, ca.Name)
	account := accountStore.LoadAccount(ca)
	config := lego.NewConfig(account)
	config.CADirURL = ca.Url
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	err = client.Challenge.SetDNS01Provider(p)
	if err != nil {
		return nil, err
	}
	return client, nil
}
