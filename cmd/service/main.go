package main

import (
	"fmt"
	"github.com/george-coast/wazuh-jumpcloud-integration/pkg"
	"os"
)

func main() {
	// Panic if no arguments are provided
	if len(os.Args) < 3 {
		fmt.Println("Expected path to config file as argument but no path was provided.  Usage: wazuh-jumpcloud-integration <path to config file>.json <path to log file>")
		os.Exit(1)
	}
	conf, err := pkg.ReadConfigFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading config file: ", err)
		os.Exit(1)
	}
	jcAPI := pkg.NewJumpCloudAPI(pkg.NewJumpCloudAPIOptions{
		APIKey:  conf.APIKey,
		BaseURL: conf.BaseURL,
		OrgID:   conf.OrgID,
	})
	err = pkg.RunService(conf, jcAPI, os.Args[2])
	if err != nil {
		fmt.Println("Error fetching events from JumpCloud API: ", err)
		os.Exit(1)
	}
	fmt.Println("Successfully ran JumpCloud event service")
	return
}
