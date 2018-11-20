package main

const (
	SRM = iota
	SSN
)

// ----------------------------------------
// LinkDB is a database of links we run on.
// ----------------------------------------
type LinkDB struct {
	links  map[string]interface{}
	inpkts chan *RecvFrame
}

// ------------------------------------------------------
// NewLinkDB allocate and initialize a new Link database.
// ------------------------------------------------------
func NewLinkDB() *LinkDB {
	linkdb := new(LinkDB)
	linkdb.links = make(map[string]interface{})
	linkdb.inpkts = make(chan *RecvFrame)
	return linkdb
}

func (db *LinkDB) SetAllFlag(seg *LSPSegment, flag int, notlink *LinkCommon) {
	// Set flag for all links except notlink
}
