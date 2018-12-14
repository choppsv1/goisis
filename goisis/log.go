package main

import (
	"log"
	"os"
)

// DbgFlags are flags for enabling debug output
type DbgFlags uint

// -----------
// Debug flags
// -----------
const (
	DbgFPkt DbgFlags = 1 << iota
	DbgFAdj
	DbgFDIS
	DbgFLSP
	DbgFUpd
	DbgFFlags
)

var FlagNames = map[string]DbgFlags{
	"adj":    DbgFAdj,
	"dis":    DbgFDIS,
	"flags":  DbgFFlags,
	"lsp":    DbgFLSP,
	"packet": DbgFPkt,
	"update": DbgFUpd,
}
var FlagTags = map[DbgFlags]string{
	DbgFPkt:   "PACKET: ",
	DbgFAdj:   "ADJ: ",
	DbgFDIS:   "DIS: ",
	DbgFLSP:   "LSPGEN: ",
	DbgFUpd:   "UPDATE: ",
	DbgFFlags: "FLAGS: ",
}

var traplogger = log.New(os.Stderr, "TRAP: ", log.Ldate|log.Ltime|log.Lmicroseconds)
var tlogger = log.New(os.Stderr, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
var dlogger = log.New(os.Stderr, "DEBUG: ", log.Ldate|log.Ltime|log.Lmicroseconds)
var logger = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lmicroseconds)

func traceIsSet(flag DbgFlags) bool {
	return (flag & GlbTrace) != 0
}

func trace(flag DbgFlags, format string, a ...interface{}) {
	if traceIsSet(flag) {
		tlogger.Printf(FlagTags[flag]+format, a...)
	}
}

func debugIsSet(flag DbgFlags) bool {
	return (flag & (GlbTrace | GlbDebug)) != 0
}

func debug(flag DbgFlags, format string, a ...interface{}) {
	if debugIsSet(flag) {
		dlogger.Printf(FlagTags[flag]+format, a...)
	}
}

func info(format string, a ...interface{}) {
	logger.Printf(format, a...)
}

func trap(format string, a ...interface{}) {
	traplogger.Printf(format, a...)
}

func panicf(format string, a ...interface{}) {
	logger.Panicf(format, a...)
}
