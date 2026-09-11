// Generates public fixtures with LND's actual scrypt parameters (N=32768).
// LND's own cipherseed_test.go lowers N to 16; those mnemonics are not
// production-compatible. Regenerate from this directory with:
// go run . > ../aezeed-vectors.json
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/aezeed"
)

type vector struct {
	Name            string
	Mnemonic        string
	Passphrase      string
	Entropy         string
	InternalVersion uint8
	MasterXprv      string
	MasterTprv      string
}

func main() {
	cases := []struct {
		name, entropy, pass string
		version             uint8
		days                int
	}{
		{"empty passphrase", "81b637d86359e6960de795e41e0b4cfd", "", 0, 0},
		{"ASCII passphrase", "81b637d86359e6960de795e41e0b4cfd", "!very_safe_55345_password*", 0, 3365},
		{"Unicode and whitespace passphrase", "000102030405060708090a0b0c0d0e0f", "  秘密 café 🗝  ", 0, 6000},
		{"zero entropy", "00000000000000000000000000000000", "aezeed", 0, 65535},
		{"Taproot version 1", "81b637d86359e6960de795e41e0b4cfd", "", 1, 17},
		{"Taproot version 1 with passphrase", "000102030405060708090a0b0c0d0e0f", "  秘密 café 🗝  ", 1, 6000},
		{"internal metadata version 2", "ffffffffffffffffffffffffffffffff", "", 2, 17},
		{"internal metadata version 255", "ffffffffffffffffffffffffffffffff", "", 255, 17},
	}
	var result []vector
	for idx, c := range cases {
		b, err := hex.DecodeString(c.entropy)
		must(err)
		var entropy [16]byte
		copy(entropy[:], b)
		salt := []byte{byte(idx), 1, 127, 128, 255}
		seed, err := aezeed.New(c.version, &entropy,
			aezeed.BitcoinGenesisDate.Add(time.Duration(c.days)*24*time.Hour),
			aezeed.WithRandomnessSource(bytes.NewReader(salt)))
		must(err)
		words, err := seed.ToMnemonic([]byte(c.pass))
		must(err)
		decoded, err := words.ToCipherSeed([]byte(c.pass))
		must(err)
		if decoded.Entropy != entropy {
			panic("reference roundtrip mismatch")
		}
		root, err := hdkeychain.NewMaster(entropy[:], &chaincfg.MainNetParams)
		must(err)
		testroot, err := hdkeychain.NewMaster(entropy[:], &chaincfg.TestNet3Params)
		must(err)
		result = append(result, vector{c.name, strings.Join(words[:], " "), c.pass,
			c.entropy, c.version, root.String(), testroot.String()})
	}
	data, err := json.MarshalIndent(result, "", "  ")
	must(err)
	fmt.Fprintln(os.Stdout, string(data))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
