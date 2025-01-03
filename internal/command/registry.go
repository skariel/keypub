package command

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"keypub/internal/mail"

	"github.com/gliderlabs/ssh"
)

// Command represents a single SSH command
type Command struct {
	Name        string
	Usage       string
	Description string
	Category    string
	Handler     CommandHandlerFunc
	Subcommands map[string]Command // For commands that have subcommands
}

// CommandHandlerFunc is the function signature for command handlers
type CommandHandlerFunc func(ctx *CommandContext) (string, error)

// CommandContext holds all the context needed for command execution
type CommandContext struct {
	DB          *sql.DB
	Args        []string
	Fingerprint string
	MailSender  mail.MailSender
	Server      *ssh.Server // Optional, needed for shutdown command
}

// CommandRegistry manages all available commands
type CommandRegistry struct {
	commands map[string]Command
}

func NewCommandRegistry() *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]Command),
	}
}

func (r *CommandRegistry) Register(cmd Command) {
	r.commands[cmd.Name] = cmd
}

// getRequiredArgsCount returns the number of required arguments based on the usage string
func getRequiredArgsCount(usage string) int {
	parts := strings.Fields(usage)
	count := 0
	for _, part := range parts[1:] { // Skip the command name
		if strings.HasPrefix(part, "<") && strings.HasSuffix(part, ">") {
			count++
		}
	}
	return count
}

// Execute runs the specified command with given context
func (r *CommandRegistry) Execute(ctx *CommandContext) (string, error) {
	if len(ctx.Args) == 0 {
		return "", errors.New(r.GetHelpText())
	}

	cmd, exists := r.commands[ctx.Args[0]]
	if !exists {
		return "", fmt.Errorf("unknown command: %s\n\n%s", ctx.Args[0], r.GetHelpText())
	}

	// Handle subcommands if they exist
	if len(cmd.Subcommands) > 0 {
		return r.executeSubcommand(ctx, cmd)
	}

	// Regular command without subcommands
	argsCount := len(ctx.Args) - 1 // Subtract command name
	expectedArgs := getRequiredArgsCount(cmd.Usage)
	if argsCount != expectedArgs {
		return "", fmt.Errorf("Usage: %s", cmd.Usage)
	}

	return cmd.Handler(ctx)
}

// executeSubcommand handles execution of commands with subcommands
func (r *CommandRegistry) executeSubcommand(ctx *CommandContext, cmd Command) (string, error) {
	if len(ctx.Args) < 2 {
		return "", errors.New(r.getSubcommandHelp(cmd))
	}

	subcmd, exists := cmd.Subcommands[ctx.Args[1]]
	if !exists {
		return "", fmt.Errorf("unknown %s subcommand: %s\n\n%s",
			cmd.Name, ctx.Args[1], r.getSubcommandHelp(cmd))
	}

	argsCount := len(ctx.Args) - 2 // Subtract command and subcommand
	expectedArgs := getRequiredArgsCount(subcmd.Usage)
	if argsCount != expectedArgs {
		return "", fmt.Errorf("Usage: %s", subcmd.Usage)
	}

	return subcmd.Handler(ctx)
}

// getSubcommandHelp returns help text for a command's subcommands
func (r *CommandRegistry) getSubcommandHelp(cmd Command) string {
	var help strings.Builder
	help.WriteString(fmt.Sprintf("Available %s subcommands:\n\n", cmd.Name))

	var subcommands []Command
	for _, subcmd := range cmd.Subcommands {
		subcommands = append(subcommands, subcmd)
	}

	sort.Slice(subcommands, func(i, j int) bool {
		return subcommands[i].Name < subcommands[j].Name
	})

	for _, subcmd := range subcommands {
		help.WriteString(fmt.Sprintf("  %s\n    %s\n\n", subcmd.Usage, subcmd.Description))
	}

	return help.String()
}

// GetHelpText returns formatted help text for all commands
func (r *CommandRegistry) GetHelpText() string {
	var help strings.Builder
	help.WriteString("Available commands:\n\n")

	categories := make(map[string][]Command)
	for _, cmd := range r.commands {
		categories[cmd.Category] = append(categories[cmd.Category], cmd)
	}

	var categoryNames []string
	for cat := range categories {
		categoryNames = append(categoryNames, cat)
	}
	sort.Strings(categoryNames)

	for _, category := range categoryNames {
		cmds := categories[category]
		if len(cmds) > 0 {
			help.WriteString(fmt.Sprintf("%s:\n", category))

			sort.Slice(cmds, func(i, j int) bool {
				return cmds[i].Name < cmds[j].Name
			})

			for _, cmd := range cmds {
				help.WriteString(fmt.Sprintf("  %s\n", cmd.Usage))
				help.WriteString(fmt.Sprintf("    %s\n", cmd.Description))

				if len(cmd.Subcommands) > 0 {
					for _, subcmd := range cmd.Subcommands {
						help.WriteString(fmt.Sprintf("      %s\n", subcmd.Usage))
						help.WriteString(fmt.Sprintf("        %s\n", subcmd.Description))
					}
				}
				help.WriteString("\n")
			}
		}
	}

	return help.String()
}
