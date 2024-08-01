package client

import (
	"letsgo/accounts"
	"letsgo/providers"

	"github.com/go-acme/lego/v4/lego"
)

func NewLegoClient(accountEmail, westUsername, westPassword string) (*lego.Client, error) {
	accountStore := accounts.NewAccountsStorage(accountEmail)
	account := accountStore.LoadAccount()
	config := lego.NewConfig(account)
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	err = client.Challenge.SetDNS01Provider(providers.NewWestDNSProvider(westUsername, westPassword))
	if err != nil {
		return nil, err
	}
	return client, nil
}
