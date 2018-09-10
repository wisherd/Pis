package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/wisherd/Pis/build"
)

var (
	// globalConfig is used by the cobra package to fill out the configuration
	// variables.
	globalConfig Config
)

// exit codes
// inspired by sysexits.h
const (
	exitCodeGeneral = 1  // Not in sysexits.h, but is standard practice.
	exitCodeUsage   = 64 // EX_USAGE in sysexits.h
)

// The Config struct contains all configurable variables for siad. It is
// compatible with gcfg.
type Config struct {
	// The APIPassword is input by the user after the daemon starts up, if the
	// --authenticate-api flag is set.
	APIPassword string

	// The Pisd variables are referenced directly by cobra, and are set
	// according to the flags.
	Pisd struct {
		APIaddr      string
		RPCaddr      string
		HostAddr     string
		AllowAPIBind bool

		Modules           string
		NoBootstrap       bool
		RequiredUserAgent string
		AuthenticateAPI   bool

		Profile    string
		ProfileDir string
		SiaDir     string
	}
}

// die prints its arguments to stderr, then exits the program with the default
// error code.
func die(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(exitCodeGeneral)
}

// versionCmd is a cobra command that prints the version of siad.
func versionCmd(*cobra.Command, []string) {
	switch build.Release {
	case "dev":
		fmt.Println("Pis Daemon v" + build.Version + "-dev")
	case "standard":
		fmt.Println("Pis Daemon v" + build.Version)
	case "testing":
		fmt.Println("Pis Daemon v" + build.Version + "-testing")
	default:
		fmt.Println("Pis Daemon v" + build.Version + "-???")
	}
}

// modulesCmd is a cobra command that prints help info about modules.
func modulesCmd(*cobra.Command, []string) {
	fmt.Println(`Use the -M or --modules flag to only run specific modules. Modules are
independent components of Pis. This flag should only be used by developers or
people who want to reduce overhead from unused modules. Modules are specified by
their first letter. If the -M or --modules flag is not specified the default
modules are run. The default modules are:
	gateway, consensus set, host, miner, renter, transaction pool, wallet
This is equivalent to:
	siad -M cghmrtw
Below is a list of all the modules available.

Gateway (g):
	The gateway maintains a peer to peer connection to the network and
	enables other modules to perform RPC calls on peers.
	The gateway is required by all other modules.
	Example:
		siad -M g
Consensus Set (c):
	The consensus set manages everything related to consensus and keeps the
	blockchain in sync with the rest of the network.
	The consensus set requires the gateway.
	Example:
		siad -M gc
Transaction Pool (t):
	The transaction pool manages unconfirmed transactions.
	The transaction pool requires the consensus set.
	Example:
		siad -M gct
Wallet (w):
	The wallet stores and manages siacoins and siafunds.
	The wallet requires the consensus set and transaction pool.
	Example:
		siad -M gctw
Miner (m):
	The miner provides a basic CPU mining implementation as well as an API
	for external miners to use.
	The miner requires the consensus set, transaction pool, and wallet.
	Example:
		siad -M gctwm
Explorer (e):
	The explorer provides statistics about the blockchain and can be
	queried for information about specific transactions or other objects on
	the blockchain.
	The explorer requires the consenus set.
	Example:
		siad -M gce`)
}

// main establishes a set of commands and flags using the cobra package.
func main() {
	if build.DEBUG {
		fmt.Println("Running with debugging enabled")
	}
	root := &cobra.Command{
		Use:   os.Args[0],
		Short: "Pis Daemon v" + build.Version,
		Long:  "Pis Daemon v" + build.Version,
		Run:   startDaemonCmd,
	}

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  "Print version information about the Pis Daemon",
		Run:   versionCmd,
	})

	root.AddCommand(&cobra.Command{
		Use:   "modules",
		Short: "List available modules for use with -M, --modules flag",
		Long:  "List available modules for use with -M, --modules flag and their uses",
		Run:   modulesCmd,
	})

	// Set default values, which have the lowest priority.
	root.Flags().StringVarP(&globalConfig.Pisd.RequiredUserAgent, "agent", "", "Pis-Agent", "required substring for the user agent")
	root.Flags().StringVarP(&globalConfig.Pisd.HostAddr, "host-addr", "", ":9982", "which port the host listens on")
	root.Flags().StringVarP(&globalConfig.Pisd.ProfileDir, "profile-directory", "", "profiles", "location of the profiling directory")
	root.Flags().StringVarP(&globalConfig.Pisd.APIaddr, "api-addr", "", "localhost:9980", "which host:port the API server listens on")
	root.Flags().StringVarP(&globalConfig.Pisd.SiaDir, "Pis-directory", "d", "", "location of the Pis directory")
	root.Flags().BoolVarP(&globalConfig.Pisd.NoBootstrap, "no-bootstrap", "", false, "disable bootstrapping on this run")
	root.Flags().StringVarP(&globalConfig.Pisd.Profile, "profile", "", "", "enable profiling with flags 'cmt' for CPU, memory, trace")
	root.Flags().StringVarP(&globalConfig.Pisd.RPCaddr, "rpc-addr", "", ":9981", "which port the gateway listens on")
	root.Flags().StringVarP(&globalConfig.Pisd.Modules, "modules", "M", "cghrtw", "enabled modules, see 'siad modules' for more info")
	root.Flags().BoolVarP(&globalConfig.Pisd.AuthenticateAPI, "authenticate-api", "", false, "enable API password protection")
	root.Flags().BoolVarP(&globalConfig.Pisd.AllowAPIBind, "disable-api-security", "", false, "allow siad to listen on a non-localhost address (DANGEROUS)")

	// Parse cmdline flags, overwriting both the default values and the config
	// file values.
	if err := root.Execute(); err != nil {
		// Since no commands return errors (all commands set Command.Run instead of
		// Command.RunE), Command.Execute() should only return an error on an
		// invalid command or flag. Therefore Command.Usage() was called (assuming
		// Command.SilenceUsage is false) and we should exit with exitCodeUsage.
		os.Exit(exitCodeUsage)
	}
}
