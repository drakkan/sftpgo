package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var genCompletionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate the autocompletion script for the specified shell",
	Long: `Generate the autocompletion script for sftpgo for the specified shell.

See each sub-command's help for details on how to use the generated script.
`,
}

var genCompletionBashCmd = &cobra.Command{
	Use:   "bash",
	Short: "Generate the autocompletion script for bash",
	Long: `Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package
manager.

To load completions in your current shell session:

$ source <(sftpgo gen completion bash)

To load completions for every new session, execute once:

Linux:
  $ sudo sftpgo gen completion bash > /usr/share/bash-completion/completions/sftpgo

MacOS:
  $ sudo sftpgo gen completion bash > /usr/local/etc/bash_completion.d/sftpgo

You will need to start a new shell for this setup to take effect.
`,
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Root().GenBashCompletionV2(os.Stdout, true)
	},
}

var genCompletionZshCmd = &cobra.Command{
	Use:   "zsh",
	Short: "Generate the autocompletion script for zsh",
	Long: `Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions for every new session, execute once:

Linux:
  $ sftpgo gen completion zsh > > "${fpath[1]}/_sftpgo"

macOS:
  $ sudo sftpgo gen completion zsh > /usr/local/share/zsh/site-functions/_sftpgo

You will need to start a new shell for this setup to take effect.
`,
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Root().GenZshCompletion(os.Stdout)
	},
}

var genCompletionFishCmd = &cobra.Command{
	Use:   "fish",
	Short: "Generate the autocompletion script for fish",
	Long: `Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

$ sftpgo gen completion fish | source

To load completions for every new session, execute once:

$ sftpgo gen completion fish > ~/.config/fish/completions/sftpgo.fish

You will need to start a new shell for this setup to take effect.
`,
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Root().GenFishCompletion(os.Stdout, true)
	},
}

var genCompletionPowerShellCmd = &cobra.Command{
	Use:   "powershell",
	Short: "Generate the autocompletion script for powershell",
	Long: `Generate the autocompletion script for powershell.

To load completions in your current shell session:

PS C:\> sftpgo gen completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.
`,
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
	},
}

func init() {
	genCompletionCmd.AddCommand(genCompletionBashCmd)
	genCompletionCmd.AddCommand(genCompletionZshCmd)
	genCompletionCmd.AddCommand(genCompletionFishCmd)
	genCompletionCmd.AddCommand(genCompletionPowerShellCmd)

	genCmd.AddCommand(genCompletionCmd)
}
