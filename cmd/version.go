package cmd

import (
	"cpk/logger"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get version of this executable file",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		logger.Logger.Info("Version found", "version", "1.0")
		return
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
