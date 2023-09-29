package cmd

import (
	"cpk-algs/base"
	"encoding/hex"
	"github.com/Songmu/prompter"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate secret files",
}

func init() {
	var passwordFile string
	var pwdCmd = &cobra.Command{
		Use:   "pwd",
		Short: "Generate password files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			password := prompter.Password("Enter password")
			buf, err := base.PasswordEncrypt(password)
			if err != nil {
				return
			}
			err = ioutil.WriteFile(passwordFile, []byte(buf), 0755)
			return
		},
	}
	pwdCmd.Flags().StringVarP(&passwordFile, "password-file", "p", "", "A file contains password record for the input password")
	_ = pwdCmd.MarkFlagRequired("password-file")
	genCmd.AddCommand(pwdCmd)

	var privateFile, publicFile string
	var skeyCmd = &cobra.Command{
		Use:   "skey",
		Short: "Generate private key files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			priv := base.RandomPrivateKey()
			pub := priv.Public()
			err = os.WriteFile(privateFile, priv.Bytes(), 0600)
			if err != nil {
				return
			}
			err = os.WriteFile(publicFile, []byte(hex.EncodeToString(pub.Bytes())), 0666)
			if err != nil {
				return
			}
			return
		},
	}
	skeyCmd.Flags().StringVarP(&privateFile, "private-key-file", "s", "", "A file contains private key record")
	skeyCmd.Flags().StringVarP(&publicFile, "public-key-file", "k", "", "A file contains private key record")
	_ = skeyCmd.MarkFlagRequired("private-key-file")
	_ = skeyCmd.MarkFlagRequired("public-key-file")
	genCmd.AddCommand(skeyCmd)

	rootCmd.AddCommand(genCmd)
}
