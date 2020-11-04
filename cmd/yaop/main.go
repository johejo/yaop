package main

import (
	"log"

	"github.com/johejo/yaop"
)

func main() {
	log.SetFlags(log.Lmicroseconds | log.LstdFlags | log.Lshortfile)
	yaop.Run()
}
