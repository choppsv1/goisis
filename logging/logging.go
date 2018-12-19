package logging

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// DbgFlags are flags for enabling debug output
type DbgFlags uint

// The defined debug flags.
const (
	DbgFPkt DbgFlags = 1 << iota
	DbgFAdj
	DbgFDIS
	DbgFLSP
	DbgFUpd
	DbgFFlags
)

// FlagNames map a string name value to the flag bit value
var FlagNames = map[string]DbgFlags{
	"adj":    DbgFAdj,
	"dis":    DbgFDIS,
	"flags":  DbgFFlags,
	"lsp":    DbgFLSP,
	"packet": DbgFPkt,
	"update": DbgFUpd,
}

// FlagTags are the strings to prefix log messages with.
var FlagTags = map[DbgFlags]string{
	DbgFPkt:   "PACKET: ",
	DbgFAdj:   "ADJ: ",
	DbgFDIS:   "DIS: ",
	DbgFLSP:   "LSPGEN: ",
	DbgFUpd:   "UPDATE: ",
	DbgFFlags: "FLAGS: ",
}

// GlbDebug are the enabled debugs.
var GlbDebug DbgFlags

// GlbTrace are the enabled traces.
var GlbTrace DbgFlags

var traplogger = log.New(os.Stderr, "TRAP: ", log.Ldate|log.Ltime|log.Lmicroseconds)
var tlogger = log.New(os.Stderr, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
var dlogger = log.New(os.Stderr, "DEBUG: ", log.Ldate|log.Ltime|log.Lmicroseconds)
var logger = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lmicroseconds)

func splitArg(argp *string) []string {
	if argp == nil {
		return nil
	}
	return strings.FieldsFunc(*argp, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ','
	})
}

// InitLogging slightly non-standard naming here b/c we . import logging
func InitLogging(tracePtr, debugPtr *string) error {
	// Initialize trace flags.
	if strings.Compare(*tracePtr, "all") == 0 {
		for fstr := range FlagNames {
			GlbTrace |= FlagNames[fstr]
		}
	} else {
		for _, s := range splitArg(tracePtr) {
			flag, ok := FlagNames[s]
			if !ok {
				return fmt.Errorf("unknown trace flag: %s\n", s)
			}
			GlbTrace |= flag
		}
	}

	// Initialize debug flags.
	if strings.Compare(*debugPtr, "all") == 0 {
		for s := range FlagNames {
			GlbDebug |= FlagNames[s]
		}
	} else {
		for _, s := range splitArg(debugPtr) {
			flag, ok := FlagNames[s]
			if !ok {
				return fmt.Errorf("unknown debug flag: %s\n", s)
			}
			GlbDebug |= flag
		}
	}
	return nil
}

// TraceIsSet returns true if the given trace flag is set.
func TraceIsSet(flag DbgFlags) bool {
	return (flag & GlbTrace) != 0
}

// Trace logs to the tracing logger if the given trace flag is set.
func Trace(flag DbgFlags, format string, a ...interface{}) {
	if TraceIsSet(flag) {
		tlogger.Printf(FlagTags[flag]+format, a...)
	}
}

// DebugIsSet returns true if the given debug flag is set.
func DebugIsSet(flag DbgFlags) bool {
	return (flag & (GlbTrace | GlbDebug)) != 0
}

// Debug logs to the debug logger if the given debug flag is set.
func Debug(flag DbgFlags, format string, a ...interface{}) {
	if DebugIsSet(flag) {
		dlogger.Printf(FlagTags[flag]+format, a...)
	}
}

// Info logs to the info logger unconditionally.
func Info(format string, a ...interface{}) {
	logger.Printf(format, a...)
}

// Trap logs to the trap logger unconditionally.
func Trap(format string, a ...interface{}) {
	traplogger.Printf(format, a...)
}

// Panicf panics using the info logger and format string and args.
func Panicf(format string, a ...interface{}) {
	logger.Panicf(format, a...)
}
