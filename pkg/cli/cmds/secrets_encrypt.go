package cmds

import (
	"github.com/k3s-io/k3s/pkg/version"
	"github.com/urfave/cli"
)

const SecretsEncryptCommand = "secrets-encrypt"

var (
	forceFlag = &cli.BoolFlag{
		Name:        "f,force",
		Usage:       "Force this stage.",
		Destination: &ServerConfig.EncryptForce,
	}
	keyTypeFlag = &cli.StringFlag{
		Name:        "k,key-type",
		Usage:       "Encryption key type. Options: aescbc, secretbox (Default: aescbc)",
		Destination: &ServerConfig.EncryptKeyType,
	}
	EncryptFlags = []cli.Flag{
		DataDirFlag,
		ServerToken,
		&cli.StringFlag{
			Name:        "server, s",
			Usage:       "(cluster) Server to connect to",
			EnvVar:      version.ProgramUpper + "_URL",
			Value:       "https://127.0.0.1:6443",
			Destination: &ServerConfig.ServerURL,
		},
	}
)

func NewSecretsEncryptCommands(status, enable, disable, prepare, rotate, reencrypt, rotateKeys func(ctx *cli.Context) error) cli.Command {
	return cli.Command{
		Name:           SecretsEncryptCommand,
		Usage:          "Control secrets encryption and keys rotation",
		SkipArgReorder: true,
		Subcommands: []cli.Command{
			{
				Name:           "status",
				Usage:          "Print current status of secrets encryption",
				SkipArgReorder: true,
				Action:         status,
				Flags: append(EncryptFlags, &cli.StringFlag{
					Name:        "output,o",
					Usage:       "Status format. Options: text, json (Default: text)",
					Destination: &ServerConfig.EncryptOutput,
				}),
			},
			{
				Name:           "enable",
				Usage:          "Enable secrets encryption",
				SkipArgReorder: true,
				Action:         enable,
				Flags:          append(EncryptFlags, keyTypeFlag),
			},
			{
				Name:           "disable",
				Usage:          "Disable secrets encryption",
				SkipArgReorder: true,
				Action:         disable,
				Flags:          EncryptFlags,
			},
			{
				Name:           "prepare",
				Usage:          "Prepare for encryption keys rotation",
				SkipArgReorder: true,
				Action:         prepare,
				Flags:          append(EncryptFlags, forceFlag, keyTypeFlag),
			},
			{
				Name:           "rotate",
				Usage:          "Rotate secrets encryption keys",
				SkipArgReorder: true,
				Action:         rotate,
				Flags:          append(EncryptFlags, forceFlag, keyTypeFlag),
			},
			{
				Name:           "reencrypt",
				Usage:          "Reencrypt all data with new encryption key",
				SkipArgReorder: true,
				Action:         reencrypt,
				Flags: append(EncryptFlags,
					forceFlag,
					keyTypeFlag,
					&cli.BoolFlag{
						Name:        "skip",
						Usage:       "Skip removing old key",
						Destination: &ServerConfig.EncryptSkip,
					}),
			},
			{
				Name:           "rotate-keys",
				Usage:          "(experimental) Dynamically rotates secrets encryption keys and re-encrypt secrets",
				SkipArgReorder: true,
				Action:         rotateKeys,
				Flags:          EncryptFlags,
			},
		},
	}
}
