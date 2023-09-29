package cmd

import (
	"cpk-authentication/logger"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/spf13/cobra"
	"os"
	"runtime/debug"
	"strings"
)

var loggerPath, logLevel string
var logClose func() error = nil

func refreshLogger() error {
	if logClose != nil {
		err := logClose()
		if err != nil {
			return err
		}
		logClose = nil
	}
	levelValue, err := log.LvlFromString(strings.ToLower(logLevel))
	if err != nil {
		return err
	}
	if loggerPath != "" {
		writer, err := os.OpenFile(loggerPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return err
		} else {
			logger.LogWriter = writer
		}
		logClose = func() error {
			return writer.Close()
		}
		logger.Logger.SetHandler(log.LvlFilterHandler(levelValue, log.StreamHandler(writer, log.LogfmtFormat())))
	} else {
		logger.Logger.SetHandler(log.LvlFilterHandler(levelValue, log.StreamHandler(os.Stdout, log.TerminalFormat(true))))
	}
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "smq",
	Short: "A very simple message queue",
	Long:  `A very simple custom message queue.`,
}

func init() {
	logger.Logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(true)))
	rootCmd.PersistentFlags().StringVarP(&loggerPath, "log-path", "l", "", "The path to write executing logs")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "L", "info", "The level of logger [crit|error|warn|info|debug|trace]")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return refreshLogger()
	}
}

func Execute() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("Error:", err)
			fmt.Println(string(debug.Stack()))
			os.Exit(2)
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
