package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "ghostenv",
	Short: "Keep secrets away from AI agents",
	Long:  "ghostenv locks your .env secrets in an encrypted vault and gives AI agents a masked version instead.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ghostenv version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ghostenv", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(removeCmd)
	rootCmd.AddCommand(execCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
