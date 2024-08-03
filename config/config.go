package config

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
