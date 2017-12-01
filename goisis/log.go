package main

import (
	"log"
	"os"
)

var debug = log.New(os.Stderr, "DEBUG:", log.Ldate|log.Ltime|log.Lmicroseconds)
var logger = log.New(os.Stderr, "INFO", log.Ldate|log.Ltime|log.Lmicroseconds)
