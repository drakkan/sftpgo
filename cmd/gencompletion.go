package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/logger"
)

var genCompletionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `To load completions:

Bash:

$ source <(sftpgo gen completion bash)

To load completions for each session, execute once:

Linux:

$ sudo sftpgo gen completion bash > /usr/share/bash-completion/completions/sftpgo

MacOS:

$ sudo sftpgo gen completion bash > /usr/local/etc/bash_completion.d/sftpgo

Zsh:

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions for each session, execute once:

$ sftpgo gen completion zsh > "${fpath[1]}/_sftpgo"

Fish:

$ sftpgo gen completion fish | source

To load completions for each session, execute once:

$ sftpgo gen completion fish > ~/.config/fish/completions/sftpgo.fish

Powershell:

PS> sftpgo gen completion powershell | Out-String | Invoke-Expression

To load completions for every new session, run:

PS> sftpgo gen completion powershell > sftpgo.ps1

and source this file from your powershell profile.
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
			err = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
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
