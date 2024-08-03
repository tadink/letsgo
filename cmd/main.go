package main

import (
	"context"
	"fmt"
	"letsgo/log"
	"letsgo/task"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/go-co-op/gocron/v2"
)

func main() {
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
	default:
		fmt.Println("unknown command")
	}
	/**
	  tuiguang9bu433@163.com
	  tuiguang9bu
	  cdstk.com
	  https://acme.zerossl.com/v2/DV90
	  https://acme-v02.api.letsencrypt.org/directory
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
