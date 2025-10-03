# Shard — Hash Cracker

A simple dictionary-based hash cracker written in Go.

## Features

* Supports: MD4, MD5, SHA-256, SHA-512, SHA3-256, SHA3-512...
* Wordlist-based cracking
* Optional rate limit per second

## Requirements

* Go 1.21+ (Linux/macOS)

## Installation & Run

```bash
go build -o shard  # Build
./shard             # Run
# or
go run main.go     # Run without build
```

## Usage

1. Choose hash type (1-30)
2. Enter the hash
3. Enter wordlist path
4. Optionally set speed (workers)

If a match is found, the cracked hash and word will be displayed.

## Note

* Wordlist: one word per line
* Rate limits delay each attempt if set
* Only use on hashes you have permission to test

## Author

Created by @coderianx
