package main

//
// CircuitDB is a database of circuits we run on.
//
type CircuitDB struct {
	links  map[string]interface{}
	inpkts chan *RecvPDU
}

//
// NewCircuitDB allocate and initialize a new circuit database.
//
func NewCircuitDB() *CircuitDB {
	cdb := new(CircuitDB)
	cdb.links = make(map[string]interface{})
	cdb.inpkts = make(chan *RecvPDU)
	return cdb
}

func (cdb *CircuitDB) SetAllSRM(lsp *LSPSegment) {
}
