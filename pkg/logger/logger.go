// Copyright 2025
// Licensed under the  Apache License

package logger

import "go.uber.org/zap"

var (
	log *zap.SugaredLogger
)

func init() {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()
	log = zapLogger.Sugar()
}

func Infof(templateStr string, args ...interface{}) {
	log.Infof(templateStr, args...)
}

func Errorf(templateStr string, args ...interface{}) {
	log.Errorf(templateStr, args...)
}

func Fatalf(templateStr string, args ...interface{}) {
	log.Fatalf(templateStr, args...)
}

func Panicf(templateStr string, args ...interface{}) {
	log.Fatalf(templateStr, args...)
}
