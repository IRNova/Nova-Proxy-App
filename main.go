package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"novaproxy/proxy"
)

func main() {
	coreMode := flag.Bool("core", false, "Run in core mode (RPC server)")
	deployMode := flag.Bool("deploy", false, "Auto-deploy GAS relay and CF worker")
	gasToken := flag.String("gas-token", "", "Google OAuth access token for Apps Script API")
	cfToken := flag.String("cf-token", "", "Cloudflare API token")
	cfAcct := flag.String("cf-account", "", "Cloudflare account ID")
	version := flag.Bool("version", false, "Show version")
	output := flag.String("output", "", "Output file for deploy results (JSON)")
	flag.Parse()

	if *version {
		fmt.Println("NovaProxy v1.0.0")
		return
	}

	if *coreMode {
		if err := runCoreMain(); err != nil {
			log.Fatalf("Core error: %v", err)
		}
		return
	}

	if *deployMode {
		token := *gasToken
		if token == "" {
			token = os.Getenv("NOVA_GAS_TOKEN")
		}
		cfAPIToken := *cfToken
		if cfAPIToken == "" {
			cfAPIToken = os.Getenv("NOVA_CF_TOKEN")
		}
		cfAccountID := *cfAcct
		if cfAccountID == "" {
			cfAccountID = os.Getenv("NOVA_CF_ACCOUNT")
		}

		if token == "" {
			fmt.Println("Error: NOVA_GAS_TOKEN required")
			fmt.Println("Usage: novaproxy --deploy --gas-token <TOKEN> [--cf-token <TOKEN>] [--cf-account <ID>]")
			os.Exit(1)
		}

		result, err := proxy.DeployAll(token, cfAPIToken, cfAccountID)
		if err != nil {
			log.Fatalf("Deploy failed: %v", err)
		}
		fmt.Println("Deploy succeeded!")
		for k, v := range result {
			fmt.Printf("  %s = %s\n", k, v)
		}
		if *output != "" {
			data, _ := json.MarshalIndent(result, "", "  ")
			os.WriteFile(*output, data, 0644)
		}
		return
	}

	switch {
	case len(os.Args) > 1 && os.Args[1] == "deploy":
		token := os.Getenv("NOVA_GAS_TOKEN")
		cfAPIToken := os.Getenv("NOVA_CF_TOKEN")
		cfAccountID := os.Getenv("NOVA_CF_ACCOUNT")
		if token == "" {
			fmt.Println("Error: NOVA_GAS_TOKEN env var required")
			os.Exit(1)
		}
		result, err := proxy.DeployAll(token, cfAPIToken, cfAccountID)
		if err != nil {
			log.Fatalf("Deploy failed: %v", err)
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

	case len(os.Args) > 1 && os.Args[1] == "core":
		if err := runCoreMain(); err != nil {
			log.Fatalf("Core error: %v", err)
		}

	default:
		fmt.Println("NovaProxy - Anti-censorship proxy")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  novaproxy core                    Run core proxy engine")
		fmt.Println("  novaproxy --deploy --gas-token T  Deploy GAS relay (also: NOVA_GAS_TOKEN env)")
		fmt.Println("  novaproxy --version               Show version")
	}
}
