package providers

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"golang.org/x/text/encoding/simplifiedchinese"
)

const AddURL = "https://api.west.cn/api/v2/domain/?act=adddnsrecord"
const DeleteURL = "https://api.west.cn/api/v2/domain/?act=deldnsrecord"

type WestDNSProvider struct {
	Username    string
	ApiPassword string
	recordIds   sync.Map
}
type WestResponse struct {
	Result   int     `json:"result"`
	Clientid string  `json:"clientid"`
	Data     DNSData `json:"data"`
	Msg      string  `json:"msg"`
	ErrCode  int     `json:"errcode"`
}
type DNSData struct {
	Id int `json:"id"`
}

func NewWestDNSProvider(Username string, ApiPassword string) *WestDNSProvider {
	return &WestDNSProvider{
		Username: Username, ApiPassword: ApiPassword,
	}

}
func (d *WestDNSProvider) Timeout() (timeout, interval time.Duration) {
	return 10 * time.Minute, 10 * time.Second
}

func (d *WestDNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fmt.Printf("%+v", info)
	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("west: could not find zone for domain %q: %w", domain, err)
	}
	authZone = dns01.UnFqdn(authZone)
	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone)
	if err != nil {
		return err
	}
	fmt.Println(authZone, subDomain)
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	westToken := fmt.Sprintf("%x", md5.Sum([]byte(d.Username+d.ApiPassword+timestamp)))
	fmt.Println(domain)
	form := url.Values{}
	form.Add("domain", domain)
	form.Add("host", subDomain)
	form.Add("type", "TXT")
	form.Add("value", info.Value)
	form.Add("ttl", "60")
	form.Add("level", "10")
	form.Add("token", westToken)
	form.Add("username", d.Username)
	form.Add("time", timestamp)
	request, err := http.NewRequest("POST", AddURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	// make API request to set a TXT record on fqdn with value and TTL
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	data, err = simplifiedchinese.GBK.NewDecoder().Bytes(data)
	if err != nil {
		return err
	}
	var w WestResponse
	err = json.Unmarshal(data, &w)
	if err != nil {
		return err
	}
	if w.Result != 200 {
		return errors.New("errcode:" + strconv.Itoa(w.ErrCode) + " msg:" + w.Msg)
	}
	key := fmt.Sprintf("%x", md5.Sum([]byte(domain+token+keyAuth)))
	d.recordIds.Store(key, w.Data.Id)
	return nil
}
func (d *WestDNSProvider) CleanUp(domain, token, keyAuth string) error {
	//username := "tuiguang9bu433@163.com"
	//apiPassword := "tuiguang9bu"
	key := fmt.Sprintf("%x", md5.Sum([]byte(domain+token+keyAuth)))
	recordId, ok := d.recordIds.LoadAndDelete(key)
	if !ok {
		return fmt.Errorf("recordId 不存在 %s", domain)
	}
	id := fmt.Sprintf("%d", recordId.(int))
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	westToken := fmt.Sprintf("%x", md5.Sum([]byte(d.Username+d.ApiPassword+timestamp)))
	form := url.Values{}
	form.Add("domain", domain)
	form.Add("id", id)
	form.Add("token", westToken)
	form.Add("username", d.Username)
	form.Add("time", timestamp)

	request, err := http.NewRequest("POST", DeleteURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	// make API request to set a TXT record on fqdn with value and TTL
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	data, err = simplifiedchinese.GBK.NewDecoder().Bytes(data)
	if err != nil {
		return err
	}
	var w WestResponse
	err = json.Unmarshal(data, &w)
	if err != nil {
		return err
	}
	if w.Result != 200 {
		return errors.New("errcode:" + strconv.Itoa(w.ErrCode) + " msg:" + w.Msg)

	}
	return nil
}
