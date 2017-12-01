package main

// LinkDB is a database of links we run on.
type LinkDB struct {
	links  map[string]interface{}
	inpkts chan *Frame
}

// NewLinkDB allocate and initialize a new Link database.
func NewLinkDB() *LinkDB {
	linkdb := new(LinkDB)
	linkdb.links = make(map[string]interface{})
	linkdb.inpkts = make(chan *Frame)
	return linkdb
}
