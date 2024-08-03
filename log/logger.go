package log

import (
	"log"
	"log/slog"

	legoLog "github.com/go-acme/lego/v4/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Init() {
	w := &lumberjack.Logger{
		Filename:   "./logs/app.log",
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	}
	logger := slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	legoLog.Logger = log.New(&lumberjack.Logger{
		Filename:   "./logs/lego.log",
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28, //days
	}, "", log.LstdFlags)

}
