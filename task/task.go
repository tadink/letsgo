package task

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"letsgo/bt"
	"letsgo/certs"
	"letsgo/client"
	"letsgo/common"
	"letsgo/config"
	"letsgo/providers"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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
var Conf *config.Config
var counter *Counter

type Counter struct {
	failObtain atomic.Int32
	failSave   atomic.Int32
}

func Init() error {
	err := common.Auth()
	if err != nil {
		return err
	}
	Conf, err = config.ParseConfig()
	if err != nil {
		return err
	}
	err = checkConfig(Conf)
	if err != nil {
		return err
	}
	err = bt.InitDb(Conf.BtDbPath)
	if err != nil {
		return err
	}
	p := providers.NewWestDNSProvider(Conf.WestUsername, Conf.WestPassword)
	c, err = client.NewLegoClient(Conf.CA, p)
	if err != nil {
		return err
	}
	parallelChan = make(chan struct{}, Conf.ParallelCount)
	finishChan = make(chan struct{})
	domainQueue = make(chan string, 50)
	counter = new(Counter)
	return nil
}
func Run() {
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
	var dealCount = 0
	for _, domain := range domains {

		err = parseCertificate(domain)
		if err == nil {
			continue
		}
		dealCount++
		if dealCount > 300 {
			break
		}
		time.Sleep(5 * time.Second)
		wg.Add(1)
		parallelChan <- struct{}{}
		go applyRequest(domain)
	}
	wg.Wait()
	close(parallelChan)
	close(domainQueue)
	<-finishChan
	slog.Info(fmt.Sprintf("运行完成:申请证书失败总共 %d 个，证书保存失败总共：%d个", counter.failObtain.Load(), counter.failSave.Load()))
	n := strings.SplitN(Conf.NginxRestartCmd, " ", 2)
	if len(n) < 2 {
		return
	}
	c := exec.Command(n[0], n[1])
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
		s := &bt.Site{
			Name:    domain,
			Path:    "/www/wwwroot/",
			Status:  "1",
			Ps:      domain,
			AddTime: time.Now().Format("2006-01-02 15:04:05"),
		}
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
		counter.failObtain.Add(1)
		slog.Error("obtain error:" + err.Error())
		return
	}
	err = certsStore.SaveResource(certificates)
	if err != nil {
		counter.failSave.Add(1)
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
	err = common.GenerateNginxConf(Conf.NginxConfTpl, Conf.BtVhostDir, domain, crtFile, keyFile)
	if err != nil {
		slog.Error("generateNginxConf:" + err.Error())
		return
	}
	domainQueue <- domain

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

func checkConfig(config *config.Config) error {
	if config.CA.AccountEmail == "" {
		return errors.New("ca邮箱不能为空")
	}
	pattern := `\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*`
	reg := regexp.MustCompile(pattern)
	if !reg.MatchString(config.CA.AccountEmail) {
		return errors.New("ca邮箱格式不正确")

	}
	if config.CA.Name == "" {
		return errors.New("ca名称不能为空")
	}
	if config.CA.Name != "letsencrypt" && config.CA.Name != "zerossl" {
		return errors.New("ca名称只能是letsencrypt或者zerossl")
	}
	if config.CA.Name == "letsencrypt" && !strings.Contains(config.CA.Url, "letsencrypt") {
		return errors.New("ca名称和ca url不匹配")
	}
	if config.CA.Name == "zerossl" && !strings.Contains(config.CA.Url, "zerossl") {
		return errors.New("ca名称和ca url不匹配")
	}
	if config.CA.Name == "zerossl" && (config.CA.EABKid == "" || config.CA.EABHmacKey == "") {
		return errors.New("eab_kid和eab_hmac_key不能为空")
	}
	return nil
}
