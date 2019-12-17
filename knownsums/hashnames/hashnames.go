package hashnames

import (
	"crypto"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

const invalid = "invalid"

var knownNames []string
var knownHashes []crypto.Hash
var reverseKnownHashNames map[string]crypto.Hash
var knownHashNames = map[crypto.Hash]string{
	crypto.MD4:         "md4",
	crypto.MD5:         "md5",
	crypto.SHA1:        "sha1",
	crypto.SHA224:      "sha224",
	crypto.SHA256:      "sha256",
	crypto.SHA384:      "sha384",
	crypto.SHA512:      "sha512",
	crypto.MD5SHA1:     "md5sha1",
	crypto.RIPEMD160:   "ripemd160",
	crypto.SHA3_224:    "sha3_224",
	crypto.SHA3_256:    "sha3_256",
	crypto.SHA3_384:    "sha3_384",
	crypto.SHA3_512:    "sha3_512",
	crypto.SHA512_224:  "sha512_224",
	crypto.SHA512_256:  "sha512_256",
	crypto.BLAKE2s_256: "blake2s_256",
	crypto.BLAKE2b_256: "blake2b_256",
	crypto.BLAKE2b_384: "blake2b_384",
	crypto.BLAKE2b_512: "blake2b_512",
}

func init() {
	mux.Lock()
	resetValues()
	mux.Unlock()
}

func resetValues() {
	knownHashes = make([]crypto.Hash, 0, len(knownHashNames))
	reverseKnownHashNames = make(map[string]crypto.Hash, len(knownHashNames))
	for hash, name := range knownHashNames {
		reverseKnownHashNames[name] = hash
		knownHashes = append(knownHashes, hash)
	}
	sort.Slice(knownHashes, func(i, j int) bool {
		return knownHashes[i] < knownHashes[j]
	})
	knownNames = make([]string, len(knownHashes))
	for i, hash := range knownHashes {
		knownNames[i] = knownHashNames[hash]
	}
}

var mux sync.RWMutex

func UpdateHashName(hash crypto.Hash, name string) error {
	mux.Lock()
	defer mux.Unlock()
	_, duplicate := reverseKnownHashNames[name]
	if duplicate {
		return fmt.Errorf("duplicate names are not allowed")
	}
	knownHashNames[hash] = name
	resetValues()
	return nil
}

//AvailableHashes lists all available crypto.Hashes
func AvailableHashes() []crypto.Hash {
	result := make([]crypto.Hash, 0, 256)
	for i := crypto.Hash(0); i < 256; i++ {
		if i.Available() {
			result = append(result, i)
		}
	}
	return result
}

func AvailableHashNames() []string {
	hashes := AvailableHashes()
	result := make([]string, len(hashes))
	for i, hash := range hashes {
		result[i] = HashName(hash)
	}
	return result
}

//HashName returns either the name mapped in KnownHashNames of "unknown(%d)"
func HashName(hash crypto.Hash) string {
	name, ok := knownHashNames[hash]
	if ok {
		return name
	}
	if hash == 0 {
		return invalid
	}
	return fmt.Sprintf("unknown(%d)", hash)
}

var reNameLookup = regexp.MustCompile(`unknown\((\d+)\)`)

func LookupHash(name string) crypto.Hash {
	if result, ok := reverseKnownHashNames[name]; ok {
		return result
	}
	if name == invalid {
		return 0
	}
	matches := reNameLookup.FindStringSubmatch(name)
	if len(matches) > 0 {
		n, err := strconv.ParseUint(matches[1], 10, 32)
		if err != nil {
			return 0
		}
		return crypto.Hash(n)
	}
	return 0
}
