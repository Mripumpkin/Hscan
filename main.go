package main

import (
	"context"
	"fmt"
	"h_scan/scan"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"
)

func createScanner(ti *scan.TargetIterator, scanTypeStr string, timeout time.Duration, routines int) (scan.Scanner, error) {
	switch strings.ToLower(scanTypeStr) {
	case "stealth", "syn", "fast":
		if os.Geteuid() > 0 {
			return nil, fmt.Errorf("Access Denied: You must be a priviliged user to run this type of scan.")
		}
		return scan.NewSynScanner(ti, timeout, routines), nil
	case "connect":
		return scan.NewConnectScanner(ti, timeout, routines), nil
	case "device":
		return scan.NewDeviceScanner(ti, timeout), nil
	case "port":
		return scan.NewPortScanner(ti, timeout, routines), nil
	}

	return nil, fmt.Errorf("Unknown scan type '%s'", scanTypeStr)
}

func main() {

	go func() {
		fmt.Print(http.ListenAndServe("0.0.0.0:7890", nil))
	}()
	args := []string{"8.8.8.8"}
	// ports := []int{22, 443, 8443, 7077, 7777, 7022, 553, 80, 8090, 8080}
	ports := []int{}
	for _, target := range args {

		targetIterator := scan.NewTargetIterator(target)

		scanner, err := createScanner(targetIterator, "connect", time.Millisecond*time.Duration(1000), 100)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("Starting scanner...\n")
		if err := scanner.Start(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		ctx, _ := context.WithCancel(context.Background())

		fmt.Printf("Scanning target %s...\n", target)

		results, err := scanner.Scan(ctx, ports)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		for _, result := range results {
			scanner.OutputResult(result)
		}

	}
	// select {}
}
