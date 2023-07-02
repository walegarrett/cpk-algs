package cmd

import (
	"cpk/base/edwards25519"
	"cpk/logger"
	"cpk/mq"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
)

var nodePort, clientPort uint16
var passwordHashFile, privateKeyFile string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		passwordHash, err := os.ReadFile(passwordHashFile)
		if err != nil {
			return
		}
		privateKeyBuf, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return
		}
		cfg := &mq.Config{
			NodePort:     nodePort,
			ClientPort:   clientPort,
			PasswordHash: string(passwordHash),
		}
		cfg.SKey.Scalar, err = (&edwards25519.Scalar{}).SetCanonicalBytes(privateKeyBuf)
		if err != nil {
			return
		}
		logger.Logger.Info("Starting", "config", cfg)
		mq := mq.NewMessageQueue(cfg)
		err = mq.Run()
		if err != nil {
			return err
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		recv := <-sigs
		logger.Logger.Info("Receive signal, stopping", "signal", recv.String())
		mq.Shutdown()
		return
	},
}

func init() {
	serveCmd.Flags().StringVarP(&passwordHashFile, "password-hash-file", "p", "", "The path of file contains password hash")
	serveCmd.Flags().StringVarP(&privateKeyFile, "private-key-file", "s", "", "The path of file contains private key")
	serveCmd.Flags().Uint16VarP(&nodePort, "node-port", "n", 0, "The port to listen from node")
	serveCmd.Flags().Uint16VarP(&clientPort, "client-port", "c", 0, "The port to listen from client")
	_ = serveCmd.MarkFlagRequired("password-hash-file")
	_ = serveCmd.MarkFlagRequired("private-key-file")
	_ = serveCmd.MarkFlagRequired("node-port")
	_ = serveCmd.MarkFlagRequired("client-port")
	rootCmd.AddCommand(serveCmd)
}
