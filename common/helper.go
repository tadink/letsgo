package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wenzhenxi/gorsa"
)

func CreateNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o700)
	} else if err != nil {
		return err
	}
	return nil
}
func GenerateNginxConf(nginxConfTpl, btVhostDir, domain, crtFile, keyFile string) error {
	rp := strings.NewReplacer("{domain}", domain, "{crt}", crtFile, "{key}", keyFile)
	nginxConf := rp.Replace(nginxConfTpl)
	nginxConfName := fmt.Sprintf("%s.conf", domain)
	if err := CreateNonExistingFolder(btVhostDir); err != nil {
		return err
	}
	err := os.WriteFile(filepath.Join(btVhostDir, nginxConfName), []byte(nginxConf), os.ModePerm)
	if err != nil {
		return err
	}

	return nil

}

type AuthInfo struct {
	IPList []string `json:"ip_list"`
	Date   string   `json:"date"`
}

func Auth() error {
	pubKye := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvq1VxUSGS56LI2evSRvw
ERKI/in+H8dyKo+wrUo3G2LnYP3fIv1JZHxNLnypGnBg10JiMnqflirSnlwQbJmo
9oQq4fHmWRNdbLnmFeOCfDhDrwsfYOwrg0DatJ3/04m8sY+7YXOKAUQh1rxf+EFD
rR1T6G7zewd6ECGZOXuHz3wjTHUwLlWZWM9L+416RNeUv3qMKpFcuIOrtCDwpOsH
k2DZ/jquytj5w+FXhrVHv2c3Igc9iMVoRa2idRL4cbhSsXLaIPhcrImTVlA2ToBG
QdmiS0y4cp5gClh3hQ1HiDYD93ejohIBrek9jY2SE+dGoGTBuBlQ047YqrRa5DBI
0QIDAQAB
-----END PUBLIC KEY-----`

	data, err := os.ReadFile("auth")
	if err != nil {
		return errors.Join(errors.New("鉴权文件读取错误"), err)
	}
	result, err := gorsa.PublicDecrypt(string(data), pubKye)
	if err != nil {
		return errors.Join(errors.New("解密错误"), err)
	}
	var authInfo AuthInfo
	err = json.Unmarshal([]byte(result), &authInfo)
	if err != nil {
		return errors.Join(errors.New("json 解析错误"), err)
	}
	t, err := time.Parse("2006-01-02", authInfo.Date)
	if err != nil {
		return errors.Join(errors.New("日期格式错误"), err)
	}
	if time.Since(t) > 0 {
		return errors.New("有效期超时")
	}
	loalIP, _ := getLocalAddresses()
	if len(loalIP) < 1 {
		return errors.New("未获取到有效IP")
	}
	if !intersection(loalIP, authInfo.IPList) {
		return errors.New("IP地址验证不通过")
	}

	return nil

}
func getLocalAddresses() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			ips = append(ips, v4.String())
		}
	}

	return ips, nil
}
func intersection(a, b []string) bool {
	m := make(map[string]bool)
	for _, x := range a {
		m[x] = true
	}
	for _, y := range b {
		if m[y] {
			return true
		}
	}
	return false
}

type DomainInfo struct {
	Domains  []string
	NginxTpl string
}

func GetDomains() ([]DomainInfo, error) {
	var result []DomainInfo
	dirs, err := os.ReadDir("domain_dir")
	if err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("domain_dir", dir.Name(), "domains"))
		if err != nil {
			return nil, err
		}
		item := DomainInfo{Domains: strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")}

		b, err = os.ReadFile(filepath.Join("domain_dir", dir.Name(), "nginx_conf.tpl"))
		if err != nil {
			return nil, err
		}
		item.NginxTpl = string(b)
		result = append(result, item)

	}

	return result, nil

}
