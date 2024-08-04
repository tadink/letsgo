package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	CA              CAInfo `json:"ca"`
	WestUsername    string `json:"west_username"`
	WestPassword    string `json:"west_password"`
	ParallelCount   int    `json:"parallel_count"`
	BtDbPath        string `json:"bt_db_path"`
	BtVhostDir      string `json:"bt_vhost_dir"`
	NginxRestartCmd string `json:"nginx_restart_cmd"`
	NginxConfTpl    string
}

type CAInfo struct {
	AccountEmail string `json:"account_email"`
	Name         string `json:"name"`
	Url          string `json:"url"`
	EABKid       string `json:"eab_kid"`
	EABHmacKey   string `json:"eab_hmac_key"`
}

func ParseConfig() (*Config, error) {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	nd, err := os.ReadFile("nginx_conf.tpl")
	if err != nil {
		return nil, err
	}
	config.NginxConfTpl = string(nd)
	return &config, nil
}
