// -*- coding: utf-8 -*-
//
// December 21 2018, Christian Hopps <chopps@gmail.com>

//
package main

import (
	"encoding/json"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/gorilla/mux"
	"io"
	"net/http"
)

// YangRoot is the root of the yang module.
type YangRoot struct {
	Enable    bool           `json:"enable"`
	LevelType clns.LevelFlag `json:"level-type"`
	SystemID  clns.SystemID  `json:"system-id"`
	//...
}

func errToHTTP(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func muxRoot(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	root := YangRoot{
		Enable:    true,
		LevelType: GlbISType,
		SystemID:  GlbSystemID,
	}

	jvars, err := json.Marshal(root)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	if _, err = io.WriteString(w, string(jvars)); err != nil {
		errToHTTP(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func muxIntfs(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	vars := mux.Vars(r)
	jvars, err := json.Marshal(vars)
	if err != nil {
		errToHTTP(w, err)
	}
	_, err = io.WriteString(w, fmt.Sprintf(`{"result": { "string": "%v", json: "%s"} }`, vars, jvars))
	if err != nil {
		errToHTTP(w, err)
	}
}

// SetupManagement initializes the management interface.
func SetupManagement() error {
	r := mux.NewRouter()
	r.HandleFunc("/isis/", muxRoot)
	r.HandleFunc("/isis/interfaces", muxIntfs)
	r.HandleFunc("/isis/interfaces/interface", muxIntfs)
	r.HandleFunc("/isis/interfaces/interface={name}", muxIntfs)
	// r.HandleFunc("/system-id")

	return http.ListenAndServe("localhost:8080", r)
}
