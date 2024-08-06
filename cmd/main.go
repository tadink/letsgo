package main

import (
	"context"
	"fmt"
	"letsgo/bt"
	"letsgo/certs"
	"letsgo/common"
	"letsgo/config"
	"letsgo/log"
	"letsgo/providers"
	"letsgo/task"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/go-co-op/gocron/v2"
)

func main() {
	// common.Encrypt()
	// return
	// if err := common.Auth(); err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }
	if len(os.Args) < 2 {
		serverStart()
		return
	}
	switch os.Args[1] {
	case "start":
		handleStartCmd()
	case "stop":
		handleStopCmd()
	case "restart":
		handleStopCmd()
		handleStartCmd()
	case "fix_nginx":
		fixNginxConf()
	case "fix_bt":
		fixBtSite()
	case "clean_dns":
		cleanDnsRecord()
	default:
		fmt.Println("unknown command")
	}
	/**
	  tuiguang9bu433@163.com
	  tuiguang9bu
	  cdstk.com
	  https://acme.zerossl.com/v2/DV90
	  https://acme-v02.api.letsencrypt.org/directory


	ahkuai8.com
	deyuantea.com
	njfzr.com
	errcode:20118 msg:记录已经存在重复添加
	*/

}
func handleStartCmd() {
	cmd := exec.Command(os.Args[0])
	err := cmd.Start()
	if err != nil {
		fmt.Println("start error:", err.Error())
		return
	}
	pid := fmt.Sprintf("%d", cmd.Process.Pid)
	err = os.WriteFile("pid", []byte(pid), os.ModePerm)
	if err != nil {
		fmt.Println("写入pid文件错误", err.Error())
		err = cmd.Process.Kill()
		if err != nil {
			fmt.Println("Process Kill错误", err.Error())
		}
		return
	}
	fmt.Println("启动成功", pid)
}
func handleStopCmd() {
	data, err := os.ReadFile("pid")
	if err != nil {
		fmt.Println("read pid error", err.Error())
		return
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Println("read pid error", err.Error())
		return
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("find process error", err.Error())
		return
	}
	if runtime.GOOS == "windows" {
		err = process.Signal(syscall.SIGKILL)
	} else {
		err = process.Signal(syscall.SIGTERM)
	}
	if err != nil {
		fmt.Println("process.Signal error", err.Error())
		return
	}
	fmt.Println("程序已经停止")
}
func serverStart() {
	log.Init()
	s, err := gocron.NewScheduler(gocron.WithLogger(slog.Default()))
	if err != nil {
		slog.Error(err.Error())
		return
	}
	_, err = s.NewJob(
		gocron.DurationJob(time.Hour*5),
		gocron.NewTask(task.Run),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithStartAt(gocron.WithStartImmediately()),
		gocron.WithEventListeners(gocron.AfterJobRunsWithPanic(task.AfterJobRunsWithPanic)),
	)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	s.Start()
	ctx, cancelFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelFunc()
	<-ctx.Done()
	slog.Info("Shutdown letsgo ...")
	err = s.Shutdown()
	if err != nil {
		slog.Error(err.Error())
	}
}
func fixNginxConf() {
	fs, err := os.ReadDir("certificates")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	conf, err := config.ParseConfig()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = bt.InitDb(conf.BtDbPath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	certsStore := certs.NewCertificatesStorage()
	for _, f := range fs {
		domain := f.Name()
		fName := path.Join(conf.BtVhostDir, domain+".conf")
		_, err = os.Stat(fName)
		if !os.IsNotExist(err) {
			continue
		}
		crtFile, err := filepath.Abs(certsStore.GetFileName(domain, ".crt"))
		if err != nil {
			fmt.Println("get crt file name error:", domain, err.Error())
			return
		}
		keyFile, err := filepath.Abs(certsStore.GetFileName(domain, ".key"))
		if err != nil {
			fmt.Println("get key file name error:", domain, err.Error())
			return

		}
		err = common.GenerateNginxConf(conf.NginxConfTpl, conf.BtVhostDir, domain, crtFile, keyFile)
		if err != nil {
			fmt.Println("generateNginxConf:" + err.Error())
			return
		}
		_, err = bt.QuerySite(domain)
		if err == nil {
			continue
		}
		s := &bt.Site{Name: domain, Path: "/www/wwwroot/", Status: "1", Ps: domain, AddTime: time.Now().Format("2006-01-02 15:04:05")}
		err = bt.SaveSite(s)
		if err != nil {
			fmt.Println("save site error:", err.Error())
			return
		}

	}
}
func fixBtSite() {
	conf, err := config.ParseConfig()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = bt.InitDb(conf.BtDbPath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	domains, err := common.GetDomains()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for _, domain := range domains {
		_, err = bt.QuerySite(domain)

		if err == nil {
			continue
		}
		fmt.Println(err.Error())
		s := &bt.Site{Name: domain, Path: "/www/wwwroot/", Status: "1", Ps: domain, AddTime: time.Now().Format("2006-01-02 15:04:05")}
		err = bt.SaveSite(s)
		if err != nil {
			fmt.Println("save site error:", err.Error())
			return
		}
	}

}

func cleanDnsRecord() {
	conf, err := config.ParseConfig()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	domains, err := common.GetDomains()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	p := providers.NewWestDNSProvider(conf.WestUsername, conf.WestPassword)
	for _, domain := range domains {
		records, err := p.GetRecords(domain)
		if err != nil {
			fmt.Println(domain, err.Error())
			continue
		}
		for _, record := range records {
			if record.DNSType == "TXT" && record.Item == "_acme-challenge" {
				id := fmt.Sprintf("%d", record.Id)
				form := &url.Values{}
				form.Add("domain", domain)
				form.Add("id", id)
				_, err = p.DeleteRecord(form)
				if err != nil {
					fmt.Println(domain, err.Error())
				}
			}

		}
	}
}
