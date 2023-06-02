package util

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Exists check if the file or directory exists
func Exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// GetFileSize return file size
func GetFileSize(file string) (int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	stat, err := f.Stat()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return stat.Size(), nil
}

// Sha256Hash calculates the sha256 hash of a file
func Sha256Hash(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	chunkSize := 65536
	buf := make([]byte, chunkSize)
	h := sha256.New()
	for {
		n, err := f.Read(buf)
		if err == io.EOF {
			break
		}
		chunk := buf[0:n]
		h.Write(chunk)
	}
	sum := h.Sum(nil)
	hash := hex.EncodeToString(sum)
	return hash, nil
}
