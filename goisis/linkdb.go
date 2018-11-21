package main

// // ----------------------------------------
// // LinkDB is a database of links we run on.
// // ----------------------------------------
// type LinkDB struct {
// 	links  map[string]Link
// 	inpkts chan *RecvFrame
// }

// // ------------------------------------------------------
// // NewLinkDB allocate and initialize a new Link database.
// // ------------------------------------------------------
// func NewLinkDB() *LinkDB {
// 	linkdb := new(LinkDB)
// 	linkdb.links = make(map[string]Link)
// 	linkdb.inpkts = make(chan *RecvFrame)
// 	return linkdb
// }

// // SetAllFlag sets the flag for seg on all links except notlink
// func (db *LinkDB) SetAllFlag(seg *LSPSegment, flag SxxFlag, notlink Link) {
// 	// Set flag for all links except notlink
// 	for _, link := range db.links {
// 		if link != notlink {
// 			link.SetFlag(seg, flag)
// 		}
// 	}
// }

// // ClearAllFlag clears the flag for seg on all links except notlink
// func (db *LinkDB) ClearAllFlag(seg *LSPSegment, flag SxxFlag, notlink Link) {
// 	for _, link := range db.links {
// 		if link != notlink {
// 			link.ClearFlag(seg, flag)
// 		}
// 	}
// }
