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
	DbgFUpd
	DbgFFlags
)

var dlogger = log.New(os.Stderr, "DEBUG:", log.Ldate|log.Ltime|log.Lmicroseconds)
var logger = log.New(os.Stderr, "INFO", log.Ldate|log.Ltime|log.Lmicroseconds)

func debugIsSet(flag DbgFlags) bool {
	return (flag & GlbDebug) != 0
}

func debug(flag DbgFlags, format string, a ...interface{}) {
	if (flag & GlbDebug) != 0 {
		dlogger.Printf(format, a...)
	}
}

func logit(format string, a ...interface{}) {
	logger.Printf(format, a...)
}
