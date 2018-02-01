package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"sync"

	"github.com/zero-os/gonbdserver/nbd"
)

func main() {
	flag.Parse()

	args := os.Args
	argn := len(args)
	if argn == 0 {
		log.Fatal("zero args given")
	}
	if argn == 1 {
		log.Fatal("no exports given (as pos args), " +
			"at least one is required")
	}

	exports, err := createExports(args[1:])
	if err != nil {
		log.Fatal(err)
	}

	err = os.MkdirAll(config.rootDir, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := nbd.NewListener(nil, nbd.ServerConfig{
		Protocol:      "tcp",
		Address:       config.address,
		DefaultExport: config.defaultExport,
		Exports:       exports,
	})
	if err != nil {
		log.Fatal(err)
	}

	var (
		wg  sync.WaitGroup
		ctx = context.Background()
	)
	listener.Listen(ctx, ctx, &wg)
}

func createExports(names []string) (cfgs []nbd.ExportConfig, err error) {
	seenNames := map[string]struct{}{}
	for _, name := range names {
		_, ok := seenNames[name]
		if ok {
			return nil, fmt.Errorf("export %s already exists", name)
		}
		seenNames[name] = struct{}{}
		cfg := nbd.ExportConfig{Name: name, Driver: "file"}
		path := path.Join(config.rootDir, name)
		cfg.DriverParameters = nbd.DriverParametersConfig{
			"path": path,
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs, nil
}

var config struct {
	address       string
	defaultExport string
	rootDir       string
}

func init() {
	flag.StringVar(&config.address, "address", "localhost:12345",
		"address to listen on")
	flag.StringVar(&config.defaultExport, "default", "",
		"optional default export")
	flag.StringVar(&config.rootDir, "dir", ".db",
		"root dir to store")
}
