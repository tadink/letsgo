package task

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"letsgo/bt"
	"letsgo/certs"
	"letsgo/client"
	"letsgo/common"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

var certsStore = certs.NewCertificatesStorage()
var parallelChan chan struct{}
var finishChan chan struct{}
var c *lego.Client
var wg *sync.WaitGroup = new(sync.WaitGroup)
var domainQueue chan string
var Conf *Config

type Config struct {
	CaAccountEmail string `json:"ca_account_email"`
	WestUsername   string `json:"west_username"`
	WestPassword   string `json:"west_password"`
	ParallelCount  int    `json:"parallel_count"`
	BtDbPath       string `json:"bt_db_path"`
	BtVhostDir     string `json:"bt_vhost_dir"`
	NginxConfTpl   string
}

func Init() error {
	var err error
	Conf, err = parseConfig()
	if err != nil {
		return err
	}
	err = bt.InitDb(Conf.BtDbPath)
	if err != nil {
		return err
	}
	c, err = client.NewLegoClient(Conf.CaAccountEmail, Conf.WestUsername, Conf.WestPassword)
	if err != nil {
		return err
	}
	parallelChan = make(chan struct{}, Conf.ParallelCount)
	finishChan = make(chan struct{})
	domainQueue = make(chan string, 50)
	return nil
}
func Run() {
	fmt.Println("start run")
	err := Init()
	if err != nil {
		slog.Error("task init error:" + err.Error())
		return
	}
	domains, err := getDomains()
	if err != nil {
		slog.Error("get domains error:" + err.Error())
		return
	}
	go handleBtDb()

	for _, domain := range domains {

		err = parseCertificate(domain)
		if err == nil {
			continue
		}
		wg.Add(1)
		parallelChan <- struct{}{}
		go applyRequest(domain)

	}
	wg.Wait()
	close(parallelChan)
	close(domainQueue)
	<-finishChan
	c := exec.Command("/etc/init.d/nginx", "reload")
	err = c.Run()
	if err != nil {
		slog.Error("重启nginx失败:" + err.Error())
	}
}

func handleBtDb() {
	for domain := range domainQueue {
		_, err := bt.QuerySite(domain)
		if err == nil {
			continue
		}
		s := &bt.Site{Name: domain, Path: "/www/wwwroot/", Status: "1", Ps: domain, AddTime: time.Now().Format("2006-01-02 15:04:05")}
		err = bt.SaveSite(s)
		if err != nil {
			slog.Error("save site error:" + err.Error())
			continue
		}
	}
	close(finishChan)
}

func getDomains() ([]string, error) {
	d, err := os.ReadFile("domains")
	if err != nil {
		return nil, err
	}
	domainStr := strings.ReplaceAll(string(d), "\r", "")
	domains := strings.Split(domainStr, "\n")
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
	nd, err := os.ReadFile("nginx_conf.tpl")
	if err != nil {
		return nil, err
	}
	config.NginxConfTpl = string(nd)
	return &config, nil
}

func applyRequest(domain string) {
	defer func() {
		wg.Done()
		<-parallelChan
	}()
	var priKey crypto.PrivateKey = nil
	dp, _ := certsStore.ReadFile(domain, ".key")
	if dp != nil {
		keyPemBlock, _ := pem.Decode(dp)
		if keyPemBlock != nil && keyPemBlock.Type == "RSA PRIVATE KEY" {
			priKey, _ = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
		}
	}
	request := certificate.ObtainRequest{
		Domains:    []string{domain, fmt.Sprintf("*.%s", domain)},
		Bundle:     true,
		PrivateKey: priKey,
	}
	certificates, err := c.Certificate.Obtain(request)
	if err != nil {
		slog.Error("obtain error:" + err.Error())
		return
	}
	err = certsStore.SaveResource(certificates)
	if err != nil {
		slog.Error("saveResource error:" + err.Error())
		return
	}
	crtFile, err := filepath.Abs(certsStore.GetFileName(domain, ".crt"))
	if err != nil {
		slog.Error("get crt file name error:" + err.Error())
		return
	}
	keyFile, err := filepath.Abs(certsStore.GetFileName(domain, ".key"))
	if err != nil {
		slog.Error("get key file name error:" + err.Error())
		return

	}
	err = generateNginxConf(domain, crtFile, keyFile)
	if err != nil {
		slog.Error("generateNginxConf:" + err.Error())
		return
	}
	domainQueue <- domain

}

func generateNginxConf(domain string, crtFile string, keyFile string) error {
	rp := strings.NewReplacer("{domain}", domain, "{crt}", crtFile, "{key}", keyFile)
	nginxConf := rp.Replace(Conf.NginxConfTpl)
	nginxConfName := fmt.Sprintf("%s.conf", domain)
	if err := common.CreateNonExistingFolder(Conf.BtVhostDir); err != nil {
		return err
	}
	err := os.WriteFile(filepath.Join(Conf.BtVhostDir, nginxConfName), []byte(nginxConf), os.ModePerm)
	if err != nil {
		return err
	}

	return nil

}
func parseCertificate(domain string) error {
	certificates, err := certsStore.ReadCertificate(domain, ".crt")
	if err != nil {
		return err
	}
	if len(certificates) < 1 {
		return fmt.Errorf("未读取到证书 %s", domain)
	}
	d := time.Until(certificates[0].NotAfter)

	if d < time.Hour*72 {
		return fmt.Errorf("证书过期时间小于72小时 %s,%s", domain, certificates[0].NotAfter.Format("2006-01-02 15:04:05"))
	}

	return nil
}
