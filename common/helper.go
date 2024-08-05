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
	fmt.Println(loalIP)
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

func Encrypt() {
	priKey := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+rVXFRIZLnosj
Z69JG/AREoj+Kf4fx3Iqj7CtSjcbYudg/d8i/UlkfE0ufKkacGDXQmIyep+WKtKe
XBBsmaj2hCrh8eZZE11sueYV44J8OEOvCx9g7CuDQNq0nf/Tibyxj7thc4oBRCHW
vF/4QUOtHVPobvN7B3oQIZk5e4fPfCNMdTAuVZlYz0v7jXpE15S/eowqkVy4g6u0
IPCk6weTYNn+Oq7K2PnD4VeGtUe/ZzciBz2IxWhFraJ1EvhxuFKxctog+FysiZNW
UDZOgEZB2aJLTLhynmAKWHeFDUeINgP3d6OiEgGt6T2NjZIT50agZMG4GVDTjtiq
tFrkMEjRAgMBAAECggEBAJe18nhyfSfNjYcuCBlzUR9EUBtp7ff7CKs0iK5YTmBL
4S0a0V9Vh/+bpw1FwoZ2w5aCCv9+8VrZ15qIRckiuXzqy/PaNBzLe5n2j0r7KecM
HU44206SmkxkXZ8310TIYookgkKXW0aGnyXr26/6vY4Pt6NIJBHPcR9EnFVQJE7A
ZN9qrrnTmxBkVgeh5MuFCHzwLTc+tyZIz3GlSqExMQ0/VyfRStQjGDojBakQVf6f
eO8VybzhVMtcc9jHAay4kzvJrmojOXcxEckSacK3sQdSv7CpNnSvA18vDHGr8AeU
9BdXwDqQGKQWthMr30W0h50zP5gcL9TecZ6E/ae938ECgYEA9qS1PO7SfxGk2tnr
QMnWq69z6tw5IH0isAsjfhsxH/3f1CpYookKPEQ2fco/WnA2Q9iyzO9rDu1diBHg
Il3YAYYawlxnOyM075fPSfmwj4avIoW1kwrqDD2yxIejRQ4DlisoB/aK3hJHODTM
Zac2JC827+oMYMY++SyZTy/D3SMCgYEAxekbZLuw39Der8HC/4Wjagjp6KxP/ses
IP/YT4z3op+OgxUeNJshjTP3hJr32ytEKI00bQ0Vc3C8giDtHAyFRp85F+f8Vh1t
avrjphS0wI4PDNV+Ibk21zmqRtIXSVBN8XgLn6ow36PiTgl8geGO5i84hLCdRtiw
2j6aebF143sCgYEA862FNj9KDqry8hotOGRxyEvfPaH4euXHGKDYnyXkYhQkSOzR
hzvXtfU61Qq1jvegVWXKOXktj6DqMJ5gj/Ohjtfcpjw+7Yl6KmEVNqQPUa4iZ/ws
iatV02Q9s7fCkl4nIv1eXoexaXgrjxdy/de3QQa4w028jvwuiWYLzdWGMHsCgYAT
SaOMzqnvNhjtwhFx+6EwbUv2jAyDxQvmb2iyYAemRqyJ4938vH2pmD3wI3YyWuYa
maBZXGQRyxPkDrds+19lwZC73rT944JNYcQb5Hq1JWMcGhZfzQAmO413t3PjhjsC
ZHOljN2UfhFJD62drtDRaBq2+8toIyghLOa7I2tczwKBgFfjVo5oP8La2nG0WLAa
zUBlIi1g/Lo1eKJ81qS6pPOxT0/DHrYgZXJ7w3SCr1z6OD5q5CD96WIj916T1wEI
N36ruuotrTuuJNRxP2VW+XH8A9JdOPf0jmcrZlFcak528lwiIRWnfUjPLc7bjnry
12/MtOmpSYJdbXTwyiElVwqE
-----END PRIVATE KEY-----`

	authInfo := AuthInfo{IPList: []string{"123.42.23.14"}, Date: "2025-07-22"}
	data, _ := json.Marshal(&authInfo)
	result, err := gorsa.PriKeyEncrypt(string(data), priKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = os.WriteFile("auth", []byte(result), os.ModePerm)
	if err != nil {
		fmt.Println(err.Error())
	}

}

func GetDomains() ([]string, error) {
	d, err := os.ReadFile("domains")
	if err != nil {
		return nil, err
	}
	domainStr := strings.ReplaceAll(string(d), "\r", "")
	domains := strings.Split(domainStr, "\n")
	return domains, nil

}
