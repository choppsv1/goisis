package main

import (
	"log"
	"os"
)

// DbgFlags are flags for enabling debug output
type DbgFlags int

// -----------
// Debug flags
// -----------
const (
	DbgFPkt DbgFlags = 1 << iota
	DbgFAdj
	DbgFDIS
	DbgFLSP
)

var dlogger = log.New(os.Stderr, "DEBUG:", log.Ldate|log.Ltime|log.Lmicroseconds)
var logger = log.New(os.Stderr, "INFO", log.Ldate|log.Ltime|log.Lmicroseconds)

func debug(flag DbgFlags, format string, a ...interface{}) {
	if (flag & GlbDebug) != 0 {
		dlogger.Printf(format, a...)
	}
}
