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
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/jzelinskie/whirlpool"
	"github.com/mimoo/GoKangarooTwelve/K12"
	argon2d "github.com/tobischo/argon2"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
	sha3_fork "golang.org/x/crypto/sha3"
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
	fmt.Println("==============================================")
	fmt.Println("                  Hash Types                  ")
	fmt.Println("==============================================")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[1]", "MD4", "[16]", "BLAKE3-256")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[2]", "MD5", "[17]", "BLAKE3-512")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[3]", "SHA1", "[18]", "NTLM")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[4]", "SHA224", "[19]", "Bcrypt")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[5]", "SHA256", "[20]", "Whirlpool")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[6]", "SHA384", "[21]", "Argon2id")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[7]", "SHA512", "[22]", "Argon2i")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[8]", "SHA3-224", "[23]", "Argon2d")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[9]", "SHA3-256", "[24]", "Scrypt (Encoded)")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[10]", "SHA3-384", "[25]", "Keccak-256")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[11]", "SHA3-512", "[26]", "Keccak-512")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[12]", "BLAKE2s-128", "[27]", "SHAKE128")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[13]", "BLAKE2s-256", "[28]", "SHAKE256")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[14]", "BLAKE2b-256", "[29]", "RIPEMD-160")
	fmt.Printf("%-4s %-15s %-4s %-15s\n", "[15]", "BLAKE2b-512", "[30]", "KangrooTwelwe")
	fmt.Println("==============================================")
	fmt.Print("Enter Hash Type Number: ")
	fmt.Scanln(&hash_type)
	switch hash_type {
	case 1:
		Md4()
	case 2:
		Md5()
	case 3:
		Sha1()
	case 4:
		Sha224()
	case 5:
		Sha256()
	case 6:
		Sha384()
	case 7:
		Sha512()
	case 8:
		Sha3_224()
	case 9:
		Sha3_256()
	case 10:
		Sha3_384()
	case 11:
		Sha3_512()
	case 12:
		Blake2s_128()
	case 13:
		Blake2s_256()
	case 14:
		Blake2b_256()
	case 15:
		Blake2b_512()
	case 16:
		Blake3_256()
	case 17:
		Blake3_512()
	case 18:
		Ntlm()
	case 19:
		Bcrypt()
	case 20:
		Whirlpool()
	case 21:
		Argon2id()
	case 22:
		Argon2i()
	case 23:
		Argon2d()
	case 24:
		Scrypt()
	case 25:
		Keccak256()
	case 26:
		Keccak512()
	case 27:
		Shake128()
	case 28:
		Shake256()
	case 29:
		RIPEMD_160()
	case 30:
		KangarooTwelve()
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

func Md4() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter the MD4 hash: ")
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
		hasher := md4.New()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)
		if hex.EncodeToString(hashedWord) == hash {
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
	}
}

// Sha224 tries to crack a SHA-224 hash using the provided wordlist.
func Sha224() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA-224 hash: ")
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
		hashedWord := sha256.Sum224([]byte(word))
		if hex.EncodeToString(hashedWord[:]) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken %.7f seconds", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
	}
}

// Sha384 tries to crack a SHA-384 hash using the provided wordlist.
func Sha384() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA-384 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
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
		hashedWord := sha512.Sum384([]byte(word))
		if hex.EncodeToString(hashedWord[:]) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken %.7f seconds\n", elapsed.Seconds())
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist file:", err)
	} else {
		fmt.Println("No match found in the wordlist.")
		elapsed := time.Since(start)
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
	}
}

// Sha3_256 tries to crack a SHA3-256 hash using the provided wordlist.
func Sha3_224() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA3-224 hash: ")
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
		hasher := sha3.New224()
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
	}
}

// Sha3_512 tries to crack a SHA3-512 hash using the provided wordlist.
func Sha3_384() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHA3-384 hash: ")
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
		hasher := sha3.New384()
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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
		fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
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

func Blake3_256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter BLAKE3-256 hash: ")
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

		elapsed := time.Since(start)
		word := scanner.Text()
		hashedWord := blake3.Sum256([]byte(word))

		if hex.EncodeToString(hashedWord[:]) == hash {
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

func Blake3_512() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter BLAKE3-512 hash: ")
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

		elapsed := time.Since(start)
		word := scanner.Text()
		hashedWord := blake3.Sum512([]byte(word))

		if hex.EncodeToString(hashedWord[:]) == hash {
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time elapsed: %.7f seconds\n", elapsed.Seconds())
			return
		}

	}
}

// Ntlm tries to crack an NTLM hash (MD4 of UTF-16LE password) using the provided wordlist.
// Ntlm tries to crack an NTLM hash (MD4 of UTF-16LE password) using the provided wordlist.
func Ntlm() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter NTLM hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error Opening wordlist file:", err.Error())
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

		// Convert to UTF-16LE bytes
		utf16Chars := utf16.Encode([]rune(word))
		utf16Bytes := make([]byte, len(utf16Chars)*2)
		for i, char := range utf16Chars {
			utf16Bytes[i*2] = byte(char)
			utf16Bytes[i*2+1] = byte(char >> 8)
		}

		// Hash with MD4
		h := md4.New()
		h.Write(utf16Bytes)
		hashedWord := h.Sum(nil)

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

// Bcrypt tries to crack a bcrypt hash using the provided wordlist.
func Bcrypt() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter bcrypt hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err.Error())
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

		// bcrypt comparison
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(word))
		if err == nil {
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

// Whirlpool tries to crack a WHIRLPOOL-512 hash using the provided wordlist.
func Whirlpool() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter WHIRLPOOL hash (hex): ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err.Error())
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
	target := strings.ToLower(strings.TrimSpace(hash))

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}

		word := scanner.Text()
		w := whirlpool.New()
		w.Write([]byte(word))
		hashed := w.Sum(nil) // []byte of 64 bytes (512 bits)
		if hex.EncodeToString(hashed) == target {
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

func Argon2id() {
	var encodedHash string
	var wordlistPath string

	fmt.Print("Enter Argon2id encoded hash: ")
	fmt.Scanln(&encodedHash)
	encodedHash = strings.TrimSpace(encodedHash)

	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)
	wordlistPath = strings.TrimSpace(wordlistPath)

	askSpeed()

	// parse encoded hash: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		fmt.Println("Invalid encoded Argon2id hash format.")
		return
	}

	// parse params
	var mem uint32
	var timeCost uint32
	var threads uint8

	paramPart := parts[3] // m=...,t=...,p=...
	params := strings.Split(paramPart, ",")
	for _, p := range params {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "m=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "m="), 10, 32)
			if err != nil {
				fmt.Println("Invalid memory parameter:", err)
				return
			}
			mem = uint32(v)
		} else if strings.HasPrefix(p, "t=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "t="), 10, 32)
			if err != nil {
				fmt.Println("Invalid time parameter:", err)
				return
			}
			timeCost = uint32(v)
		} else if strings.HasPrefix(p, "p=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "p="), 10, 8)
			if err != nil {
				fmt.Println("Invalid threads parameter:", err)
				return
			}
			threads = uint8(v)
		}
	}

	saltB64 := parts[4]
	hashB64 := parts[5]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		fmt.Println("Invalid base64 salt:", err)
		return
	}
	hash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		fmt.Println("Invalid base64 hash:", err)
		return
	}
	keyLen := uint32(len(hash))

	// open wordlist
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
	lineNo := 0

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}
		lineNo++
		word := scanner.Text()

		// compute argon2id with parsed params & salt
		computed := argon2.IDKey([]byte(word), salt, timeCost, mem, threads, keyLen)

		// constant-time compare
		if subtle.ConstantTimeCompare(computed, hash) == 1 {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(encodedHash, ":", word)
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

func Argon2i() {
	var encodedHash string
	var wordlistPath string

	fmt.Print("Enter Argon2i encoded hash: ")
	fmt.Scanln(&encodedHash)
	encodedHash = strings.TrimSpace(encodedHash)

	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)
	wordlistPath = strings.TrimSpace(wordlistPath)

	askSpeed()

	// expected format: $argon2i$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2i" {
		fmt.Println("Invalid encoded Argon2i hash format. Expected: $argon2i$...")
		return
	}

	// parse params
	var mem uint32
	var timeCost uint32
	var threads uint8

	paramPart := parts[3] // m=...,t=...,p=...
	params := strings.Split(paramPart, ",")
	for _, p := range params {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "m=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "m="), 10, 32)
			if err != nil {
				fmt.Println("Invalid memory parameter:", err)
				return
			}
			mem = uint32(v)
		} else if strings.HasPrefix(p, "t=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "t="), 10, 32)
			if err != nil {
				fmt.Println("Invalid time parameter:", err)
				return
			}
			timeCost = uint32(v)
		} else if strings.HasPrefix(p, "p=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "p="), 10, 8)
			if err != nil {
				fmt.Println("Invalid threads parameter:", err)
				return
			}
			threads = uint8(v)
		}
	}

	saltB64 := parts[4]
	hashB64 := parts[5]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		// fallback to StdEncoding if necessary
		salt, err = base64.StdEncoding.DecodeString(saltB64)
		if err != nil {
			fmt.Println("Invalid base64 salt:", err)
			return
		}
	}
	hash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		// fallback to StdEncoding if necessary
		hash, err = base64.StdEncoding.DecodeString(hashB64)
		if err != nil {
			fmt.Println("Invalid base64 hash:", err)
			return
		}
	}
	keyLen := uint32(len(hash))

	// open wordlist
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
	lineNo := 0

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}
		lineNo++
		word := scanner.Text()

		// compute Argon2i using argon2.Key (Argon2i variant)
		computed := argon2.Key([]byte(word), salt, timeCost, mem, threads, keyLen)

		// constant-time compare
		if subtle.ConstantTimeCompare(computed, hash) == 1 {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(encodedHash, ":", word)
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

func Argon2d() {
	var encodedHash string
	var wordlistPath string

	fmt.Print("Enter Argon2d encoded hash: ")
	fmt.Scanln(&encodedHash)
	encodedHash = strings.TrimSpace(encodedHash)

	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)
	wordlistPath = strings.TrimSpace(wordlistPath)

	askSpeed() // projende zaten varsa

	// Beklenen format: $argon2d$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2d" {
		fmt.Println("Invalid encoded Argon2d hash format. Expected: $argon2d$...")
		return
	}

	// parse params (m=...,t=...,p=...)
	var mem uint32
	var timeCost uint32
	var threads uint8

	paramPart := parts[3]
	params := strings.Split(paramPart, ",")
	for _, p := range params {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "m=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "m="), 10, 32)
			if err != nil {
				fmt.Println("Invalid memory parameter:", err)
				return
			}
			mem = uint32(v)
		} else if strings.HasPrefix(p, "t=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "t="), 10, 32)
			if err != nil {
				fmt.Println("Invalid time parameter:", err)
				return
			}
			timeCost = uint32(v)
		} else if strings.HasPrefix(p, "p=") {
			v, err := strconv.ParseUint(strings.TrimPrefix(p, "p="), 10, 8)
			if err != nil {
				fmt.Println("Invalid threads parameter:", err)
				return
			}
			threads = uint8(v)
		}
	}

	saltB64 := parts[4]
	hashB64 := parts[5]

	// decode base64 (önce Raw, sonra Std fallback)
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		salt, err = base64.StdEncoding.DecodeString(saltB64)
		if err != nil {
			fmt.Println("Invalid base64 salt:", err)
			return
		}
	}
	hash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		hash, err = base64.StdEncoding.DecodeString(hashB64)
		if err != nil {
			fmt.Println("Invalid base64 hash:", err)
			return
		}
	}
	keyLen := uint32(len(hash))

	// open wordlist
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
	lineNo := 0

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}
		lineNo++
		word := scanner.Text()

		computed := argon2d.DKey([]byte(word), salt, timeCost, mem, threads, keyLen)

		// sabit-zamanlı karşılaştırma
		if subtle.ConstantTimeCompare(computed, hash) == 1 {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(encodedHash, ":", word)
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

func Scrypt() {
	var encoded string
	var wordlistPath string

	fmt.Print("Enter scrypt encoded hash: ")
	fmt.Scanln(&encoded)
	encoded = strings.TrimSpace(encoded)

	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)
	wordlistPath = strings.TrimSpace(wordlistPath)

	askSpeed()

	// parse encoded string
	parts := strings.Split(encoded, "$")
	// expected: ["", "scrypt", "N=...,r=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 5 || parts[1] != "scrypt" {
		fmt.Println("Invalid scrypt encoded format. Expected: $scrypt$N=...,r=...,p=...$<salt>$<hash>")
		return
	}

	// parse params
	var N int
	var r int
	var p int

	paramPart := parts[2]
	params := strings.Split(paramPart, ",")
	for _, pstr := range params {
		pstr = strings.TrimSpace(pstr)
		if strings.HasPrefix(pstr, "N=") {
			v, err := strconv.ParseInt(strings.TrimPrefix(pstr, "N="), 10, 32)
			if err != nil {
				fmt.Println("Invalid N parameter:", err)
				return
			}
			N = int(v)
		} else if strings.HasPrefix(pstr, "r=") {
			v, err := strconv.ParseInt(strings.TrimPrefix(pstr, "r="), 10, 32)
			if err != nil {
				fmt.Println("Invalid r parameter:", err)
				return
			}
			r = int(v)
		} else if strings.HasPrefix(pstr, "p=") {
			v, err := strconv.ParseInt(strings.TrimPrefix(pstr, "p="), 10, 32)
			if err != nil {
				fmt.Println("Invalid p parameter:", err)
				return
			}
			p = int(v)
		}
	}

	if N <= 1 || r <= 0 || p <= 0 {
		fmt.Println("Invalid scrypt parameters (N,r,p).")
		return
	}

	saltB64 := parts[3]
	hashB64 := parts[4]

	// decode base64 salt & hash (try RawStd then Std)
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		salt, err = base64.StdEncoding.DecodeString(saltB64)
		if err != nil {
			fmt.Println("Invalid base64 salt:", err)
			return
		}
	}
	hash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		hash, err = base64.StdEncoding.DecodeString(hashB64)
		if err != nil {
			fmt.Println("Invalid base64 hash:", err)
			return
		}
	}
	keyLen := len(hash)
	if keyLen == 0 {
		fmt.Println("Decoded hash length is zero.")
		return
	}

	// open wordlist
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
	lineNo := 0

	for scanner.Scan() {
		if ticker != nil {
			<-ticker.C
		}
		lineNo++
		word := scanner.Text()

		// compute scrypt
		computed, err := scrypt.Key([]byte(word), salt, N, r, p, keyLen)
		if err != nil {
			// scrypt.Key can return errors on invalid params; print and continue
			fmt.Printf("scrypt error at line %d: %v\n", lineNo, err)
			continue
		}

		// constant-time compare
		if subtle.ConstantTimeCompare(computed, hash) == 1 {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(encoded, ":", word)
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

func Keccak256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter Keccak-256 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
		hasher := sha3_fork.NewLegacyKeccak256()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)
		if hex.EncodeToString(hashedWord) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken %.7f seconds", elapsed.Seconds())
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

func Keccak512() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter Keccak-512 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
		hasher := sha3_fork.NewLegacyKeccak512()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)
		if hex.EncodeToString(hashedWord) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken %.7f seconds", elapsed.Seconds())
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

func Shake128() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHAKE128 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
		hasher := sha3_fork.NewShake128()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time take %.7f seconds\n", elapsed.Seconds())
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

func Shake256() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter SHAKE256 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
		hasher := sha3_fork.NewShake256()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time take %.7f seconds\n", elapsed.Seconds())
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

func RIPEMD_160() {
	var hash string
	var wordlistPath string

	fmt.Print("Enter RIPEMD-160 hash: ")
	fmt.Scanln(&hash)
	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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
		hasher := ripemd160.New()
		hasher.Write([]byte(word))
		hashedWord := hasher.Sum(nil)

		if hex.EncodeToString(hashedWord) == hash {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(hash, ":", word)
			fmt.Printf("Time taken %.7f", elapsed.Seconds())
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

func KangarooTwelve() {
	var targetHex string
	var wordlistPath string
	var outBytes int

	fmt.Print("Enter KangarooTwelve target hex: ")
	fmt.Scanln(&targetHex)
	targetHex = strings.TrimSpace(strings.ToLower(targetHex))

	fmt.Print("Enter the path to wordlist file: ")
	fmt.Scanln(&wordlistPath)
	wordlistPath = strings.TrimSpace(wordlistPath)

	fmt.Print("Output length in bytes (press Enter for auto/default 32): ")
	_, err := fmt.Scanln(&outBytes)
	if err != nil || outBytes <= 0 {
		// try to infer from provided hex
		if len(targetHex) > 0 && len(targetHex)%2 == 0 {
			outBytes = len(targetHex) / 2
		} else {
			outBytes = 32 // default
		}
	}

	askSpeed()

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening wordlist file:", err)
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

		out := make([]byte, outBytes)

		K12.K12Sum(nil, []byte(word), out)

		hexOut := hex.EncodeToString(out)
		if strings.EqualFold(hexOut, targetHex) {
			elapsed := time.Since(start)
			fmt.Println("[!] Hash Cracked")
			fmt.Println(targetHex, ":", word)
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
