package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/logger"
)

var genCompletionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script to the stdout",
	Long: `To load completions:

Bash:

$ source <(sftpgo completion bash)

# To load completions for each session, execute once:
Linux:
  $ sftpgo completion bash > /etc/bash_completion.d/sftpgo-completion.bash
MacOS:
  $ sftpgo completion bash > /usr/local/etc/bash_completion.d/sftpgo-completion.bash

Zsh:

$ source <(sftpgo completion zsh)

# To load completions for each session, execute once:
$ sftpgo completion zsh > "${fpath[1]}/_sftpgo"

Fish:

$ sftpgo completion fish | source

# To load completions for each session, execute once:
$ sftpgo completion fish > ~/.config/fish/completions/sftpgo.fish
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		logger.DisableLogger()
		logger.EnableConsoleLogger(zerolog.DebugLevel)
		switch args[0] {
		case "bash":
			err = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			err = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			err = cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			err = cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
		if err != nil {
			logger.WarnToConsole("Unable to generate shell completion script: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	genCmd.AddCommand(genCompletionCmd)
}
