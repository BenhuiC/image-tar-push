package cmd

import (
	"image-tar-push/logic"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "image-tar-push",
	Short: "A tool to push image tar to registry",
	Long:  `image-tar-push is a cli tool to push docker-style image tar to registry.`,
	Run: func(cmd *cobra.Command, args []string) {
		tarFile := args[0]
		p, err := logic.NewPusher(tarFile, registry, skipTls, username, password, chunkSize)
		if err != nil {
			panic(err)
		}
		err = p.Push()
		if err != nil {
			panic(err)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	registry  string
	skipTls   bool
	username  string
	password  string
	chunkSize int64
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&registry, "registry", "r", "", "registry address")
	rootCmd.PersistentFlags().BoolVarP(&skipTls, "skip-tls-verify", "s", false, "skip tls verify")
	rootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "username")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "password")
	rootCmd.PersistentFlags().Int64VarP(&chunkSize, "chunk-size", "c", 0, "chunk size(bytes)")
}
