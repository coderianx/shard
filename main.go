/*
MIT License

Copyright (c) 2025 Coderian

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// workers: number of concurrent workers (used as user-visible "speed" setting).
// rate: rate limiter (words per second). If 0 -> unlimited (no rate limiting).
var workers int = 1
var rate int = 0

// printBanner prints ASCII art
func printBanner() {
	banner := `
  _________.__                     .___
 /   _____/|  |__ _____ _______  __| _/
 \_____  \ |  |  \\__  \\_  __ \/ __ | 
 /        \|   Y  \/ __ \|  | \/ /_/ | 
/_______  /|___|  (____  /__|  \____ | 
        \/      \/     \/           \/ 

Shard - Hash Cracker. created by @coderianx
`
	fmt.Println(banner)
}

// main: program entry point. Shows a menu and routes to the selected hash function.
// All user prompts and outputs are in English.
func main() {
	printBanner()

	var hash_type int
	fmt.Println("============================")
	fmt.Println("Hash Type:")
	fmt.Println("[1]  MD5")
	fmt.Println("[2]  SHA1")
	fmt.Println("[3]  SHA-256")
	fmt.Println("[4]  SHA-512")
	fmt.Println("[5]  SHA3-256")
	fmt.Println("[6]  SHA3-512")
	fmt.Println("[7]  BLAKE2s-128")
	fmt.Println("[8]  BLAKE2s-256")
	fmt.Println("[9]  BLAKE2b-256")
	fmt.Println("[10] BLAKE2b-512")
	fmt.Println("============================\n")
	fmt.Print("Enter Hash Type Number: ")
	fmt.Scanln(&hash_type)
	switch hash_type {
	case 1:
		Md5()
	case 2:
		Sha1()
	case 3:
		Sha256()
	case 4:
		Sha512()
	case 5:
		Sha3_256()
	case 6:
		Sha3_512()
	case 7:
		Blake2s_128()
	case 8:
		Blake2s_256()
	case 9:
		Blake2b_256()
	case 10:
		Blake2b_512()
	default:
		fmt.Println("Invalid option.")
	}
}

// askSpeed prompts the user for the "speed" setting (number of workers).
// If empty input is provided, defaults to 1 worker and unlimited rate.
// If a positive integer is provided, workers and rate are set to that value.
// Invalid input falls back to default.
func askSpeed() {
	var speedInput string
	fmt.Print("Enter speed (number of workers). Press Enter for default 1: ")
	fmt.Scanln(&speedInput)
	speedInput = strings.TrimSpace(speedInput)
	if speedInput == "" {
		workers = 1
		rate = 0 // unlimited
		return
	}

	if v, err := strconv.Atoi(speedInput); err == nil && v > 0 {
		workers = v
		rate = v
	} else {
		fmt.Println("Invalid speed input, using default 1 (no rate limit).")
		workers = 1
		rate = 0
	}
}

// Md5 tries to crack an MD5 hash using the provided wordlist.
// Prompts user for hash and wordlist file path. Uses optional rate limiter.
func Md5() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter the MD5 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}
	defer file.Close()

	// If rate > 0, create a ticker to limit attempts per second.
	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// rate limiter: if ticker is set, wait before processing next word
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		hashedWord := md5.Sum([]byte(word))
		if hex.EncodeToString(hashedWord[:]) == strings.ToLower(strings.TrimSpace(hash)) {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

// Sha1 tries to crack a SHA-1 hash using the provided wordlist.
func Sha1() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter the SHA-1 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}

	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		hashedWord := sha1.Sum([]byte(word))
		if hex.EncodeToString(hashedWord[:]) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

// Sha256 tries to crack a SHA-256 hash using the provided wordlist.
// Behavior mirrors Md5 function but uses SHA-256 hashing.
func Sha256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter the SHA-256 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}
	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		hashedWord := sha256.Sum256([]byte(word))
		if hex.EncodeToString(hashedWord[:]) == strings.ToLower(strings.TrimSpace(hash)) {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

// Sha512 tries to crack a SHA-512 hash using the provided wordlist.
// Uses sha512.Sum512 to compute digests.
func Sha512() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA-512 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to the wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening Wordlist File", err.Error())
		return
	}
	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		hashedWord := sha512.Sum512([]byte(word))
		if hex.EncodeToString(hashedWord[:]) == strings.ToLower(strings.TrimSpace(hash)) {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

// Sha3_256 tries to crack a SHA3-256 hash using the provided wordlist.
// Uses the sha3.New256 hasher so streaming input is supported.
func Sha3_256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA3-256 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}
	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		hasher := sha3.New256()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)
		if hex.EncodeToString(hashedWord) == strings.ToLower(strings.TrimSpace(hash)) {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

// Sha3_512 tries to crack a SHA3-512 hash using the provided wordlist.
// Uses sha3.New512 hasher.
func Sha3_512() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA3-512 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}
	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		hasher := sha3.New512()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)
		if hex.EncodeToString(hashedWord) == strings.ToLower(strings.TrimSpace(hash)) {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

func Blake2s_128() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter BLAKE2s-128 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Print(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}

	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		elapsed := time.Since(start)
		word := scanner.Text()
		hasher, err := blake2s.New128(nil)
		if err != nil {
			fmt.Println("Error creating hasher:", err)
			return
		}
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

func Blake2s_256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter BLAKE2s-256 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Print(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}

	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		elapsed := time.Since(start)
		word := scanner.Text()
		hasher, err := blake2s.New256(nil)
		if err != nil {
			fmt.Println("Error creating hasher:", err)
			return
		}
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

func Blake2b_256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter BLAKE2b-256 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Print(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}

	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		elapsed := time.Since(start)
		word := scanner.Text()
		hasher, err := blake2b.New256(nil)
		if err != nil {
			fmt.Println("Error creating hasher:", err)
			return
		}
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}

func Blake2b_512() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter BLAKE2b-512 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Print(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file: ", err.Error())
		return
	}

	defer file.Close()

	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	start := time.Now()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		elapsed := time.Since(start)
		word := scanner.Text()
		hasher, err := blake2b.New512(nil)
		if err != nil {
			fmt.Println("Error creating hasher:", err)
			return
		}
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.2f seconds\n", elapsed.Seconds())
	}
}
