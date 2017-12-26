package main

import (
	"log"
	"os"
)

// DbgFlag are flags for enabling debug output
type DbgFlag int

// -----------
// Debug flags
// -----------
const (
	DbgFPkt DbgFlag = 1 << iota
	DbgFAdj
	DbgFDIS
)

var dlogger = log.New(os.Stderr, "DEBUG:", log.Ldate|log.Ltime|log.Lmicroseconds)
var logger = log.New(os.Stderr, "INFO", log.Ldate|log.Ltime|log.Lmicroseconds)

func debug(flag DbgFlag, format string, a ...interface{}) {
	if (flag & GlbDebug) != 0 {
		dlogger.Printf(format, a...)
	}
}
