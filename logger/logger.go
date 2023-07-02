package logger

import (
	"github.com/ethereum/go-ethereum/log"
	"os"
)

// LogWriter designed for gin to use - gin.LoggerWithWriter(logger.LogWriter)
var LogWriter = os.Stdout

// Logger is for other purposes - logger.Logger.Info(msg, "key1", value1, "key2", value2, ...)
var Logger = log.Root()
