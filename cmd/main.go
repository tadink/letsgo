package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"letsgo/certs"
	"letsgo/client"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

type Config struct {
	CaAccountEmail string `json:"ca_account_email"`
	WestUsername   string `json:"west_username"`
	WestPassword   string `json:"west_password"`
}

var certsStore = certs.NewCertificatesStorage()
var parallelChann = make(chan struct{}, 10)
var c *lego.Client

func init() {
	config, err := parseConfig()
	if err != nil {
		log.Fatalln(err.Error())
	}
	c, err = client.NewLegoClient(config.CaAccountEmail, config.WestUsername, config.WestPassword)
	if err != nil {
		log.Fatal(err.Error())
	}

}
func main() {
	/**
	  tuiguang9bu433@163.com
	  tuiguang9bu
	  cdstk.com
	*/

	domains, err := getDomains()
	if err != nil {
		log.Fatalln(err.Error())
	}

	for _, domain := range domains {
		parallelChann <- struct{}{}
		go applyRequest(domain)

	}

}

func applyRequest(domain string) {
	defer func() {
		<-parallelChann
	}()
	request := certificate.ObtainRequest{
		Domains: []string{domain, fmt.Sprintf("*.%s", domain)},
		Bundle:  true,
	}
	certificates, err := c.Certificate.Obtain(request)
	if err != nil {
		fmt.Println("obtain error", err.Error())
		return
	}
	err = certsStore.SaveResource(certificates)
	if err != nil {
		fmt.Println("saveResource error", err.Error())
		return
	}
	crtFile, err := filepath.Abs(certsStore.GetFileName(domain, ".crt"))
	if err != nil {
		fmt.Println("get crt file name error", err.Error())
		return
	}
	keyFile, err := filepath.Abs(certsStore.GetFileName(domain, ".key"))
	if err != nil {
		fmt.Println("get key file name error", err.Error())
		return

	}
	err = generateNginxConf(domain, crtFile, keyFile)
	if err != nil {
		fmt.Println("generateNginxConf:", err.Error())
	}

}
func getDomains() ([]string, error) {
	d, err := os.ReadFile("domains.txt")
	if err != nil {
		return nil, err
	}
	d = bytes.ReplaceAll(d, []byte("\r"), []byte(""))
	domains := strings.Split(string(d), "\n")
	return domains, nil

}
func parseConfig() (*Config, error) {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
func generateNginxConf(domain string, crtFile string, keyFile string) error {
	tpl := `server{
    listen 80;
	listen 443 ssl http2;
    server_name %s *.%s;
   
	ssl_certificate    %s;
    ssl_certificate_key   %s;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass http://127.0.0.1:8899;
        proxy_set_header Accept-Encoding "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
        proxy_cache off;
        proxy_set_header scheme $scheme;
 }
}`

	nginxConf := fmt.Sprintf(tpl, domain, domain, crtFile, keyFile)
	nginxConfName := fmt.Sprintf("%s.conf", domain)
	err := os.WriteFile("/www/wwwroot/server/panel/vhost/nginx/"+nginxConfName, []byte(nginxConf), os.ModePerm)
	if err != nil {
		return err
	}
	return nil

}
