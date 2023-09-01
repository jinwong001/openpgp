package algorithm

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"strconv"
	
	"github.com/jinwong001/openpgp/internal/md2"
)

// Hash is an official hash function algorithm. See RFC 4880, section 9.4.
type Hash interface {
	// Id returns the algorithm ID, as a byte, of Hash.
	Id() uint8
	// Available reports whether the given hash function is linked into the binary.
	Available() bool
	// HashFunc simply returns the value of h so that Hash implements SignerOpts.
	HashFunc() crypto.Hash
	// New returns a new hash.Hash calculating the given hash function. New
	// panics if the hash function is not linked into the binary.
	New() hash.Hash
	// Size returns the length, in bytes, of a digest resulting from the given
	// hash function. It doesn't require that the hash function in question be
	// linked into the program.
	Size() int
	// String is the name of the hash function corresponding to the given
	// OpenPGP hash id.
	String() string
}

//{1, crypto.MD5, "MD5"},
//{2, crypto.SHA1, "SHA1"},
//{3, crypto.RIPEMD160, "RIPEMD160"},
//{8, crypto.SHA256, "SHA256"},
//{9, crypto.SHA384, "SHA384"},
//{10, crypto.SHA512, "SHA512"},
//{11, crypto.SHA224, "SHA224"},

// The following vars mirror the crypto/Hash supported hash functions.
var (
	MD5       Hash = cryptoHash{1, crypto.MD5}
	SHA1      Hash = cryptoHash{2, crypto.SHA1}
	RIPEMD160 Hash = cryptoHash{3, crypto.RIPEMD160}
	MD2       Hash = cryptoHash{5, md2.MD2HashID}
	SHA256    Hash = cryptoHash{8, crypto.SHA256}
	SHA384    Hash = cryptoHash{9, crypto.SHA384}
	SHA512    Hash = cryptoHash{10, crypto.SHA512}
	SHA224    Hash = cryptoHash{11, crypto.SHA224}
	SHA3_256  Hash = cryptoHash{12, crypto.SHA3_256}
	SHA3_512  Hash = cryptoHash{14, crypto.SHA3_512}
)

// HashById represents the different hash functions specified for OpenPGP. See
// http://www.iana.org/assignments/pgp-parameters/pgp-parameters.xhtml#pgp-parameters-14
var (
	HashById = map[uint8]Hash{
		MD2.Id():       MD2,
		MD5.Id():       MD5,
		SHA1.Id():      SHA1,
		RIPEMD160.Id(): RIPEMD160,
		SHA256.Id():    SHA256,
		SHA384.Id():    SHA384,
		SHA512.Id():    SHA512,
		SHA224.Id():    SHA224,
		SHA3_256.Id():  SHA3_256,
		SHA3_512.Id():  SHA3_512,
	}
)

// cryptoHash contains pairs relating OpenPGP's hash identifier with
// Go's crypto.Hash type. See RFC 4880, section 9.4.
type cryptoHash struct {
	id uint8
	crypto.Hash
}

// Id returns the algorithm ID, as a byte, of cryptoHash.
func (h cryptoHash) Id() uint8 {
	return h.id
}

var hashNames = map[uint8]string{
	MD2.Id():       "MD2",
	MD5.Id():       "MD5",
	SHA1.Id():      "SHA1",
	RIPEMD160.Id(): "RIPEMD160",
	SHA256.Id():    "SHA256",
	SHA384.Id():    "SHA384",
	SHA512.Id():    "SHA512",
	SHA224.Id():    "SHA224",
	SHA3_256.Id():  "SHA3-256",
	SHA3_512.Id():  "SHA3-512",
}

func (h cryptoHash) String() string {
	s, ok := hashNames[h.id]
	if !ok {
		panic(fmt.Sprintf("Unsupported hash function %d", h.id))
	}
	return s
}

const maxHash = 20

func (h cryptoHash) New() hash.Hash {
	if h.Id() == MD2.Id() {
		return md2.New()
	}
	return h.Hash.New()
}

func (h cryptoHash) Size() int {
	if h.Id() == MD2.Id() {
		return 16
	}
	return h.Hash.Size()
}

// Available reports whether the given hash function is linked into the binary.
func (h cryptoHash) Available() bool {
	if h.Id() == MD2.Id() {
		return true
	}
	return h.Hash.Available()
}

func HashNew(hashId crypto.Hash) (hash.Hash, error) {
	if hashId == md2.MD2HashID {
		return md2.New(), nil
	}

	if !hashId.Available() {
		return nil, errors.New("hash not available: " + strconv.Itoa(int(hashId)))
	}
	return hashId.New(), nil
}

// HashIdToHash returns a crypto.Hash which corresponds to the given OpenPGP
// hash id.
func HashIdToHash(id byte) (h crypto.Hash, ok bool) {
	if hash, ok := HashById[id]; ok {
		return hash.HashFunc(), true
	}
	if id == MD2.Id() {
		return MD2.HashFunc(), true
	}
	return 0, false
}

// HashIdToString returns the name of the hash function corresponding to the
// given OpenPGP hash id.
func HashIdToString(id byte) (name string, ok bool) {
	if hash, ok := HashById[id]; ok {
		return hash.String(), true
	}
	if id == MD2.Id() {
		return MD2.String(), true
	}
	return "", false
}

// HashToHashId returns an OpenPGP hash id which corresponds the given Hash.
func HashToHashId(h crypto.Hash) (id byte, ok bool) {
	for id, hash := range HashById {
		if hash.HashFunc() == h {
			return id, true
		}
	}
	if h == MD2.HashFunc() {
		return MD5.Id(), true
	}
	return 0, false
}
