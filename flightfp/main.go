// Command flightfp fingerprints flight source/state files in parallel.
//
// Mirrors scripts/record_flights.py + scripts/measure_flights.py hashing:
// sha256 over raw bytes, hex-encoded, one JSON object per line.
// Go wins here with goroutines + stdlib crypto/sha256: dozens of state
// files hash concurrently with no GIL and no interpreter startup per file.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type FileFP struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func shaFile(path string) (FileFP, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return FileFP{}, err
	}
	sum := sha256.Sum256(b)
	return FileFP{
		Name:   filepath.Base(path),
		SHA256: hex.EncodeToString(sum[:]),
		Size:   int64(len(b)),
	}, nil
}

func fingerprintDir(dir, ext string, workers int) []FileFP {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flightfp: %v\n", err)
		os.Exit(1)
	}
	type job struct{ path string }
	jobs := make(chan job)
	results := make(chan FileFP)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				fp, err := shaFile(j.path)
				if err != nil {
					continue
				}
				results <- fp
			}
		}()
	}
	go func() {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if ext != "" && filepath.Ext(e.Name()) != ext {
				continue
			}
			jobs <- job{path: filepath.Join(dir, e.Name())}
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	var out []FileFP
	for fp := range results {
		out = append(out, fp)
	}
	return out
}

func main() {
	dir := flag.String("dir", ".", "directory to fingerprint")
	ext := flag.String("ext", ".json", "only files with this extension (empty = all)")
	workers := flag.Int("workers", 16, "parallel hash workers")
	flag.Parse()
	enc := json.NewEncoder(os.Stdout)
	for _, fp := range fingerprintDir(*dir, *ext, *workers) {
		if err := enc.Encode(fp); err != nil {
			fmt.Fprintf(os.Stderr, "flightfp: %v\n", err)
			os.Exit(1)
		}
	}
}
