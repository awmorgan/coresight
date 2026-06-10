package main

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Check if the reference implementation directory exists and is a directory
	stat, err := os.Stat("OpenCSD")
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("./OpenCSD directory does not exist")
		}
		return fmt.Errorf("stat ./OpenCSD: %w", err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("./OpenCSD is not a directory")
	}

	// 2. Glob all *.ppl files in cmd/trc_pkt_lister/testdata/
	pattern := filepath.Join("cmd", "trc_pkt_lister", "testdata", "*.ppl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob ppl files: %w", err)
	}

	resultsDir := filepath.Join("OpenCSD", "decoder", "tests", "results")
	eteResultsDir := filepath.Join("OpenCSD", "decoder", "tests", "results-ete")

	for _, match := range matches {
		filename := filepath.Base(match)

		// bugfix-exact-match.ppl is a special case (compressed in the repo)
		if filename == "bugfix-exact-match.ppl" {
			continue
		}

		srcPath := filepath.Join(resultsDir, filename)
		if _, err := os.Stat(srcPath); err != nil {
			if os.IsNotExist(err) {
				// Try ete-results
				srcPath = filepath.Join(eteResultsDir, filename)
				if _, err := os.Stat(srcPath); err != nil {
					if os.IsNotExist(err) {
						fmt.Printf("Warning: %s not found in either OpenCSD results directory\n", filename)
						continue
					}
					return fmt.Errorf("stat %s: %w", srcPath, err)
				}
			} else {
				return fmt.Errorf("stat %s: %w", srcPath, err)
			}
		}

		fmt.Printf("Updating %s -> %s\n", srcPath, match)
		if err := copyFile(srcPath, match); err != nil {
			return fmt.Errorf("copy %s to %s: %w", srcPath, match, err)
		}
	}

	// 3. Special case: bugfix-exact-match.ppl.gz
	bugfixSrc := filepath.Join(resultsDir, "bugfix-exact-match.ppl")
	bugfixDstGz := filepath.Join("cmd", "trc_pkt_lister", "testdata", "bugfix-exact-match.ppl.gz")

	if _, err := os.Stat(bugfixSrc); err == nil {
		fmt.Printf("Compressing and updating %s -> %s\n", bugfixSrc, bugfixDstGz)
		if err := compressGzip(bugfixSrc, bugfixDstGz); err != nil {
			return fmt.Errorf("failed to compress bugfix-exact-match: %w", err)
		}

		// Also remove the uncompressed file from the repo folder if it exists
		bugfixDstUncompressed := filepath.Join("cmd", "trc_pkt_lister", "testdata", "bugfix-exact-match.ppl")
		if _, err := os.Stat(bugfixDstUncompressed); err == nil {
			if err := os.Remove(bugfixDstUncompressed); err != nil {
				fmt.Printf("Warning: failed to remove uncompressed bugfix file %s: %v\n", bugfixDstUncompressed, err)
			} else {
				fmt.Printf("Removed uncompressed file %s\n", bugfixDstUncompressed)
			}
		}
	} else if os.IsNotExist(err) {
		fmt.Printf("Warning: %s not found\n", bugfixSrc)
	} else {
		return fmt.Errorf("stat %s: %w", bugfixSrc, err)
	}

	// 4. Special internal files
	specialInternalFiles := []struct {
		srcName string
		dstPath string
	}{
		{"frame_demux_test.ppl", filepath.Join("internal", "demux", "testdata", "frame_demux_test.ppl")},
		{"itm-decode-test.ppl", filepath.Join("internal", "itm", "testdata", "itm-decode-test.ppl")},
		{"mem_buff_demo.ppl", filepath.Join("internal", "memacc", "testdata", "mem_buff_demo.ppl")},
		{"mem_buff_demo_cb.ppl", filepath.Join("internal", "memacc", "testdata", "mem_buff_demo_cb.ppl")},
		{"c_api_test.ppl", filepath.Join("internal", "pipeline", "testdata", "c_api_test.ppl")},
	}

	for _, spec := range specialInternalFiles {
		srcPath := filepath.Join(resultsDir, spec.srcName)
		if _, err := os.Stat(srcPath); err == nil {
			fmt.Printf("Updating %s -> %s\n", srcPath, spec.dstPath)
			// Ensure parent directory exists, though it should since the file exists in the repo
			if err := os.MkdirAll(filepath.Dir(spec.dstPath), 0755); err != nil {
				return fmt.Errorf("mkdir for %s: %w", spec.dstPath, err)
			}
			if err := copyFile(srcPath, spec.dstPath); err != nil {
				return fmt.Errorf("copy %s to %s: %w", srcPath, spec.dstPath, err)
			}
		} else if os.IsNotExist(err) {
			fmt.Printf("Warning: special file %s not found\n", srcPath)
		} else {
			return fmt.Errorf("stat %s: %w", srcPath, err)
		}
	}

	fmt.Println("Golden files update completed successfully.")
	return nil
}

func getCleanedContent(src string) ([]byte, error) {
	content, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, "Library Version") {
			continue
		}
		filtered = append(filtered, line)
	}
	return []byte(strings.Join(filtered, "\n")), nil
}

func copyFile(src, dst string) error {
	cleaned, err := getCleanedContent(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, cleaned, 0644)
}

func compressGzip(src, dst string) error {
	cleaned, err := getCleanedContent(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer gz.Close()

	if _, err = gz.Write(cleaned); err != nil {
		return err
	}
	return gz.Close()
}
