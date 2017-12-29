// Update implements the update process (flooding)
package main

// UpdFlag Update process flooding flags
type UpdFlag int

// Update process flooding flags
const (
	SRM UpdFlag = 1 << iota
	SSN
)

var updFlagStrings = [3]string{
	"SRM",
	"SSN",
	"SRM|SSN",
}

func (flag UpdFlag) String() string {
	return updFlagStrings[flag]
}

// updRemoveLSP removes and LSP from the update LSP DB
func updRemoveLSP(lsp *LSPSegment) {
}
