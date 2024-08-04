package providers

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"golang.org/x/text/encoding/simplifiedchinese"
)

const AddURL = "https://api.west.cn/api/v2/domain/?act=adddnsrecord"
const DeleteURL = "https://api.west.cn/api/v2/domain/?act=deldnsrecord"
const GetURL = "https://api.west.cn/api/v2/domain/?act=getdnsrecord"

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

type GetDNSResponse struct {
	Result   int       `json:"result"`
	Clientid string    `json:"clientid"`
	Data     []DNSData `json:"data"`
	Msg      string    `json:"msg"`
	ErrCode  int       `json:"errcode"`
}
type DNSData struct {
	Id      int    `json:"id"`
	Item    string `json:"item"`
	Value   string `json:"value"`
	DNSType string `json:"type"`
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
	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("west: could not find zone for domain %q: %w", domain, err)
	}
	authZone = dns01.UnFqdn(authZone)
	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone)
	if err != nil {
		return fmt.Errorf("west: could extract sub domain zone for domain %q: %w", domain, err)
	}
	slog.Info("auth_zone subdomain", authZone, subDomain)
	form := &url.Values{}
	form.Add("domain", domain)
	form.Add("host", subDomain)
	form.Add("type", "TXT")
	form.Add("value", info.Value)
	form.Add("ttl", "60")
	form.Add("level", "10")
	w, err := d.addRecord(form)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%x", md5.Sum([]byte(domain+token+keyAuth)))
	if w.Result != 200 && w.ErrCode == 20118 {
		id, err := d.getRecords(domain, subDomain, info.Value)
		if err != nil {
			return err
		}
		if id == 0 {
			return fmt.Errorf("未获取到%s对应dns id", domain)
		}
		d.recordIds.Store(key, id)
		return nil
	}

	d.recordIds.Store(key, w.Data.Id)
	return nil
}
func (d *WestDNSProvider) CleanUp(domain, token, keyAuth string) error {
	key := fmt.Sprintf("%x", md5.Sum([]byte(domain+token+keyAuth)))
	recordId, ok := d.recordIds.LoadAndDelete(key)
	if !ok {
		return fmt.Errorf("recordId 不存在 %s", domain)
	}
	id := fmt.Sprintf("%d", recordId.(int))
	form := &url.Values{}
	form.Add("domain", domain)
	form.Add("id", id)
	_, err := d.deleteRecord(form)

	if err != nil {
		return err
	}
	return nil
}

func (d *WestDNSProvider) addRecord(form *url.Values) (*WestResponse, error) {
	data, err := d.getResponse(AddURL, form)
	if err != nil {
		return nil, err
	}
	var w WestResponse
	err = json.Unmarshal(data, &w)
	if err != nil {
		return nil, err
	}
	return &w, nil

}
func (d *WestDNSProvider) deleteRecord(form *url.Values) (*WestResponse, error) {
	data, err := d.getResponse(DeleteURL, form)
	if err != nil {
		return nil, err
	}
	var w WestResponse
	err = json.Unmarshal(data, &w)
	if err != nil {
		return nil, err
	}
	return &w, nil

}
func (d *WestDNSProvider) getRecords(domain, subDomain, value string) (int, error) {
	form := new(url.Values)
	form.Add("domain", domain)
	form.Add("limit", "100")
	data, err := d.getResponse(GetURL, form)
	if err != nil {
		return 0, err
	}
	var r GetDNSResponse
	err = json.Unmarshal(data, &r)
	if err != nil {
		return 0, err
	}
	if r.Result != 200 {
		return 0, fmt.Errorf("getRecords error:%d %s", r.ErrCode, r.Msg)
	}
	if len(r.Data) < 1 {
		return 0, fmt.Errorf("getRecords error:解析记录为空")
	}
	for _, record := range r.Data {
		if record.DNSType == "TXT" && record.Value == value && record.Item == subDomain {
			return record.Id, nil
		}
	}
	return 0, nil

}

func (d *WestDNSProvider) getResponse(u string, form *url.Values) ([]byte, error) {
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	westToken := fmt.Sprintf("%x", md5.Sum([]byte(d.Username+d.ApiPassword+timestamp)))
	form.Add("token", westToken)
	form.Add("username", d.Username)
	form.Add("time", timestamp)

	request, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	data, err = simplifiedchinese.GBK.NewDecoder().Bytes(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
