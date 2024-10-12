// Command xgosumdb is a basic Go sumdb server that serves requests from its
// database, and reads unknown modules from a Go module proxy adding them to its
// database for future requests.
package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/mjl-/bstore"
)

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		log.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

var signer note.Signer

func main() {
	var manualadd bool
	var addr string
	var init, initkeys string
	var dbpath string
	var proxy string
	var loglevel slog.LevelVar
	flag.BoolVar(&manualadd, "manualadd", false, "read a record consisting of two lines (for zip and go.mod contents) from stdin and add to the database (without verification of content hashes!)")
	flag.StringVar(&addr, "addr", "localhost:3080", "address to listen on")
	flag.StringVar(&init, "init", "", "initialize new signer and database with given name (typically hostname, e.g. sumdb.example.com)")
	flag.StringVar(&initkeys, "initkeys", "", "initialize database existing signer and verifier key, separated by space; make sure to clean any sumdb cache state when resetting a sum db with existing keys")
	flag.StringVar(&dbpath, "db", "xgosum.db", "path to database")
	flag.StringVar(&proxy, "proxy", "https://proxy.golang.org", "base url of go module proxy")
	flag.TextVar(&loglevel, "loglevel", &loglevel, "for logging")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: xgosumdb [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) != 0 {
		flag.Usage()
	}

	slogOpts := slog.HandlerOptions{
		Level: &loglevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slogOpts))
	slog.SetDefault(logger)

	var db *bstore.DB
	var verifierKey string

	if init != "" || initkeys != "" {
		if init != "" && initkeys != "" {
			log.Printf("cannot have both -init and -initkeys")
			flag.Usage()
		}

		// Check database doesn't already exist.
		if _, err := os.Stat(dbpath); err == nil {
			xcheckf(fmt.Errorf("already exists"), "creating database")
		} else if !os.IsNotExist(err) {
			xcheckf(err, "creating database")
		}

		var skey, vkey string
		if initkeys != "" {
			// todo: would be nicer to generate the vkey from the skey. wondering why package note doesn't have a method for that...
			var ok bool
			skey, vkey, ok = strings.Cut(initkeys, " ")
			if !ok {
				xcheckf(fmt.Errorf(`-initkeys must be "skey vkey"`), "parsing keys")
			}
			ns, err := note.NewSigner(skey)
			xcheckf(err, "parsing initial signer key")
			signer = ns
			verifier, err := note.NewVerifier(vkey)
			xcheckf(err, "parsing initial verifier key")
			if signer.Name() != verifier.Name() {
				log.Fatalf("name of signer %q and verifier %q don't match", signer.Name(), verifier.Name())
			}
			if signer.KeyHash() != verifier.KeyHash() {
				log.Fatalf("key of signer and verifier don't match")
			}
		} else {
			// Generate a new key.
			var err error
			skey, vkey, err = note.GenerateKey(cryptorand.Reader, init)
			xcheckf(err, "generating signer key")

			ns, err := note.NewSigner(skey)
			xcheckf(err, "parsing initial signer key")
			signer = ns

			slog.Info("new signer key", "skey", skey)
		}

		// New database.
		var err error
		db, err = bstore.Open(context.Background(), dbpath, nil, State{}, Record{}, Hash{})
		xcheckf(err, "create db")

		// Write initial state with signed empty tree.
		err = db.Write(context.Background(), func(tx *bstore.Tx) error {
			state := State{1, skey, vkey, 0, 0, nil}
			err = tx.Insert(&state)
			xcheckf(err, "initializing database")

			err = signTree(tx, &state)
			xcheckf(err, "signing initial empty tree")
			return nil
		})
		xcheckf(err, "signing tree")

		verifierKey = vkey
	} else {
		// Open existing database.
		var err error
		db, err = bstore.Open(context.Background(), dbpath, &bstore.Options{MustExist: true}, State{}, Record{}, Hash{})
		xcheckf(err, "open db (hint: run with -init for first time)")

		state := State{ID: 1}
		err = db.Get(context.Background(), &state)
		xcheckf(err, "initializing database")
		verifierKey = state.VerifierKey

		ns, err := note.NewSigner(state.SignerKey)
		xcheckf(err, "parsing initial signer key")
		signer = ns
	}
	err := db.HintAppend(true, Record{}, Hash{})
	xcheckf(err, "setting append-only hint for record and hash database types")

	if manualadd {
		/*
			golang.org/toolchain v0.0.1-go1.22.1.linux-amd64 h1:zhaB0xtf1n7RI8+VTlFAxhfXYrkUUHHjr4cpEh+aEsA=
			golang.org/toolchain v0.0.1-go1.22.1.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
		*/

		slog.Info("reading record from stdin")
		data, err := io.ReadAll(os.Stdin)
		xcheckf(err, "reading record from stdin")

		lines := strings.Split(string(data), "\n")
		if len(lines) != 3 || lines[2] != "" {
			log.Fatalf("need 2 lines")
		}
		t := strings.Split(lines[0], " ")
		if len(t) != 3 {
			log.Fatalf("first line %q, expected 3 space-separated tokens (path, version, hash)", lines[0])
		}
		path := t[0]
		version := strings.TrimSuffix(t[1], "/go.mod")

		err = db.Write(context.Background(), func(tx *bstore.Tx) error {
			_, err := addRecord(tx, path, version, data)
			return err
		})
		xcheckf(err, "inserting record into database")
		slog.Info("module path/version added", "path", path, "version", version)

		os.Exit(0)
	}

	// Helpful for user.
	fmt.Printf("use with:\n\n\tGOSUMDB='%s http://%s'\n\n", verifierKey, addr)

	ops := &serverOps{db, proxy}
	sumsrv := NewServer(ops)
	for _, p := range ServerPaths {
		http.Handle(p, sumsrv)
	}

	slog.Info("starting", "listenaddr", addr, "version", version)
	err = http.ListenAndServe(addr, nil)
	log.Fatalln("listen and serve:", err)
}

type State struct {
	ID          int // Singleton, ID 1
	SignerKey   string
	VerifierKey string
	Records     int64  // Number of records (unique module path+version).
	Hashes      int64  // Number of hashes (of records and hash tree).
	TreeSig     []byte // Signed tree state.
}

// Adjust tlog ID/index to DB ID.
func tlog2dbID(tlogID int64) int64 {
	return tlogID + 1
}

// Adjust DB ID to tlog ID/index.
func db2tlogID(dbID int64) int64 {
	return dbID - 1
}

type Record struct {
	ID      int64  // DB ID is 1 higher than tlog ID. Use tlog2dbID and db2tlogID.
	Path    string `bstore:"nonzero,unique Path+Version"`
	Version string `bstore:"nonzero"`
	Data    []byte `bstore:"nonzero"`
}

type Hash struct {
	ID   int64 // DB ID is 1 higher than tlog ID. Use tlog2dbID and db2tlogID.
	Hash tlog.Hash
}

// sign latest tree state, to be called after adding a record and its hashes.
func signTree(tx *bstore.Tx, state *State) (rerr error) {
	slog.Info("signing tree", "size", state.Records)

	h, err := tlog.TreeHash(state.Records, hashReader{tx})
	if err != nil {
		return fmt.Errorf("calculating tree hash: %v", err)
	}
	text := tlog.FormatTree(tlog.Tree{N: state.Records, Hash: h})
	msg, err := note.Sign(&note.Note{Text: string(text)}, signer)
	if err != nil {
		return fmt.Errorf("signing new tree state: %v", err)
	}
	state.TreeSig = msg
	err = tx.Update(state)
	if err != nil {
		return fmt.Errorf("updating tree state: %v", err)
	}
	return err
}

type serverOps struct {
	db           *bstore.DB
	proxyBaseURL string
}

func (s *serverOps) Signed(ctx context.Context) ([]byte, error) {
	state := State{ID: 1}
	err := s.db.Get(ctx, &state)
	return state.TreeSig, err
}

// ReadRecords returns the content for the n records id through id+n-1.
func (s *serverOps) ReadRecords(ctx context.Context, id, n int64) (content [][]byte, err error) {
	slog.Debug("readrecords", "tlogid", id, "n", n)
	err = bstore.QueryDB[Record](ctx, s.db).FilterGreaterEqual("ID", tlog2dbID(id)).SortAsc("ID").Limit(int(n)).ForEach(func(r Record) error {
		content = append(content, r.Data)
		return nil
	})
	if err == nil && int64(len(content)) != n {
		err = fmt.Errorf("got %d, requested %d", len(content), n)
	}
	return
}

// Lookup looks up a record for the given module,
// returning the record ID.
func (s *serverOps) Lookup(ctx context.Context, m module.Version) (int64, error) {
	slog.Debug("looking up", "module", m)

	// Lookup in database. If we have it, we're done.
	r, err := bstore.QueryDB[Record](ctx, s.db).FilterEqual("Path", m.Path).FilterEqual("Version", m.Version).Get()
	if err != bstore.ErrAbsent {
		return db2tlogID(r.ID), err
	}

	slog.Debug("fetching module from proxy", "module", m)
	// This may take longer.

	escpath, err := module.EscapePath(m.Path)
	if err != nil {
		return 0, err
	}
	escversion, err := module.EscapeVersion(m.Version)
	if err != nil {
		return 0, err
	}

	// We will be fetching these URLs, calculating their hashes, making a record out of
	// them, and adding the record and new hashes to the tree, signing the new tree and
	// saving it all in the database.
	modurl := fmt.Sprintf("%s/%s/@v/%s.mod", s.proxyBaseURL, escpath, escversion)
	zipurl := fmt.Sprintf("%s/%s/@v/%s.zip", s.proxyBaseURL, escpath, escversion)

	modreq, err := http.NewRequestWithContext(ctx, "GET", modurl, nil)
	if err != nil {
		return 0, fmt.Errorf("go.mod http request: %v", err)
	}
	resp, err := http.DefaultClient.Do(modreq)
	if err != nil {
		return 0, fmt.Errorf("go.mod http transaction: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("get go.mod, status %v, expected 200 ok", resp.Status)
	}
	gomod, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read go.mod from proxy: %v", err)
	}

	zipreq, err := http.NewRequestWithContext(ctx, "GET", zipurl, nil)
	if err != nil {
		return 0, fmt.Errorf("module zip http request: %v", err)
	}
	resp, err = http.DefaultClient.Do(zipreq)
	if err != nil {
		return 0, fmt.Errorf("module zip http transaction: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("get module zip, status %v, expected 200 ok", resp.Status)
	}
	zf, err := os.CreateTemp("", "xgosumdb-zip-*")
	if err != nil {
		return 0, fmt.Errorf("create file for module zip: %v", err)
	}
	defer os.Remove(zf.Name())
	defer zf.Close()
	_, err = io.Copy(zf, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("copy module zip from proxy: %v", err)
	}

	h1gomod, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(gomod)), nil
	})
	if err != nil {
		return 0, fmt.Errorf("calculating go.mod hash: %v", err)
	}
	h1zip, err := dirhash.HashZip(zf.Name(), dirhash.Hash1)
	if err != nil {
		return 0, fmt.Errorf("calculating zip hash: %v", err)
	}

	data := []byte(fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", m.Path, m.Version, h1zip, m.Path, m.Version, h1gomod))

	err = s.db.Write(ctx, func(tx *bstore.Tx) error {
		// Lookup again, another request may have added it in the mean time.
		record, err := bstore.QueryTx[Record](tx).FilterEqual("Path", m.Path).FilterEqual("Version", m.Version).Get()
		if err == nil {
			slog.Debug("module made it into the database in the mean-time, not adding again", "module", m)
			r = record
			return nil
		}
		if err != bstore.ErrAbsent {
			return err
		}

		r, err = addRecord(tx, m.Path, m.Version, data)
		return err
	})
	if err != nil {
		slog.Error("adding record to database", "module", m, "err", err)
		return 0, err
	}
	return db2tlogID(r.ID), nil
}

func addRecord(tx *bstore.Tx, path, version string, data []byte) (Record, error) {
	state := State{ID: 1}
	if err := tx.Get(&state); err != nil {
		return Record{}, fmt.Errorf("get state: %v", err)
	}

	// Insert new record into database.
	record := Record{tlog2dbID(state.Records), path, version, data}
	if err := tx.Insert(&record); err != nil {
		return Record{}, fmt.Errorf("inserting record: %v", err)
	}
	state.Records++
	slog.Debug("inserting record into sumdb", "path", path, "version", version, "recordtlogid", db2tlogID(record.ID))

	// Insert one or more hashes.
	if hashIndex := tlog.StoredHashIndex(0, db2tlogID(record.ID)); hashIndex != state.Hashes {
		return Record{}, fmt.Errorf("tlog says we should store hashes at offset %d for tlog record %d, we are at offset %d", hashIndex, db2tlogID(record.ID), state.Hashes)
	}
	hl, err := tlog.StoredHashes(db2tlogID(record.ID), data, hashReader{tx})
	if err != nil {
		return Record{}, fmt.Errorf("calculating hashes to insert: %v", err)
	}
	slog.Debug("inserting hashes", "nhashes", len(hl))
	for _, h := range hl {
		nh := Hash{ID: tlog2dbID(state.Hashes), Hash: h}
		if err := tx.Insert(&nh); err != nil {
			return Record{}, fmt.Errorf("inserting hash: %v", err)
		}
		state.Hashes++
	}

	// Sign and save new tree state.
	if err := signTree(tx, &state); err != nil {
		return Record{}, fmt.Errorf("signing tree after adding record and hashes: %v", err)
	}

	return record, nil
}

// ReadTileData reads the content of tile t.
// It is only invoked for hash tiles (t.L ≥ 0).
func (s *serverOps) ReadTileData(ctx context.Context, t tlog.Tile) (tileData []byte, rerr error) {
	slog.Debug("read tile data", "tile", t)

	rerr = s.db.Read(ctx, func(tx *bstore.Tx) error {
		tileData, rerr = tlog.ReadTileData(t, hashReader{tx})
		return rerr
	})
	return tileData, rerr
}

type hashReader struct {
	tx *bstore.Tx
}

// ReadHashes returns the hashes with the given stored hash indexes.
func (r hashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	slog.Debug("hashreader readhashes", "indexes", indexes)
	l := make([]tlog.Hash, len(indexes))
	for i, id := range indexes {
		h := Hash{ID: tlog2dbID(id)}
		if err := r.tx.Get(&h); err != nil {
			return nil, err
		}
		l[i] = h.Hash
	}
	return l, nil
}
