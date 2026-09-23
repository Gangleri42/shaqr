// SPDX-License-Identifier: CC0-1.0

package shaqr_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/Gangleri42/shaqr"
)

func Example() {
	// This r reproduces the worked example of SPEC.md. A real session set
	// leaves Rand nil, which reads crypto/rand.
	r := make([]byte, 32)
	for i := range r {
		r[i] = byte(i)
	}
	sp := shaqr.Splitter{Rand: bytes.NewReader(r)}
	shares, err := sp.Split([]byte("JBSWY3DPEHPK3PXP"), shaqr.TypeText, 2, 3)
	if err != nil {
		log.Fatal(err)
	}
	for _, sh := range shares {
		h, _ := shaqr.ParseHeader(sh)
		fmt.Printf("%s %d/3\n%s\n", h.Tag(), h.X, shaqr.Encode(sh))
	}

	// Two plates typed back by hand, with their labels.
	text := "#B962 3/3\n" + strings.ToLower(shaqr.Encode(shares[2])) + "\n#B962 1/3\n" + shaqr.Encode(shares[0])
	held, rejected := shaqr.Decode(text)
	if rejected != nil {
		log.Fatal(rejected)
	}
	typ, payload, err := shaqr.Combine(held)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%c %s\n", typ, payload)

	// Output:
	// #B962 1/3
	// SHAQR:AEBADOLCDHWEF732KBEVS2JZMBTSGXFWZSSOEGJIC5I4S46CKE72JCKTE777EAWS2HVW5ZSO7WAG74LXDZKLBNSLXJY37QDLTRWP55A
	// #B962 2/3
	// SHAQR:AEBAFOLCDHWEF732KBEVS2JZMBTSGXBTLVLMIWHMXCBDYRZ6WJRBFJFZ6XVF37PBOA57QEWQ3EGUDO6CJSJLJOXYK62M3QA7L5YJSBA
	// #B962 3/3
	// SHAQR:AEBAHOLCDHWEF732KBEVS2JZMBTSGXFZ3PYS6Z2Z3U5G7ITKDKQITPYWXMIDRKHQ42BIVN2TYV3FW5CYRPIEDPTABT36HQBTA57K7HA
	// U JBSWY3DPEHPK3PXP
}

// An open set is for data that must survive lost plates and need not
// stay private. It has no key, so its shares are 32 bytes shorter than
// those of a sealed set, and every share shows part of the payload. The
// same payload, type and k give the same shares every time.
func ExampleSplitter_Split_open() {
	note := []byte("Box 1207, Main Street branch; the key is with the lawyer")
	sp := shaqr.Splitter{Open: true}
	shares, err := sp.Split(note, shaqr.TypeText, 2, 3)
	if err != nil {
		log.Fatal(err)
	}
	sealed, err := shaqr.Split(note, shaqr.TypeText, 2, 3)
	if err != nil {
		log.Fatal(err)
	}
	for _, sh := range shares {
		h, _ := shaqr.ParseHeader(sh)
		fmt.Printf("%s %d/3 open=%v\n%s\n", h.Tag(), h.X, h.Open, shaqr.Encode(sh))
	}
	fmt.Printf("%d bytes a share, %d in a sealed set\n", len(shares[0]), len(sealed[0]))
	_, payload, err := shaqr.Combine(shares[1:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", payload)

	// Output:
	// #40DB 1/3 open=true
	// SHAQR:AIBACQG344HEXC24MX4UA2CAZLTIGOKVIJXXQIBRGIYDOLBAJVQWS3RAKN2HEZLFOQQGE4TBNZRWQLZHDPLA
	// #40DB 2/3 open=true
	// SHAQR:AIBAEQG344HEXC24MX4UA2CAZLTIGOJ3EB2GQZJANNSXSIDJOMQHO2LUNAQHI2DFEBWGC53ZMVZIAI2OXKQA
	// #40DB 3/3 open=true
	// SHAQR:AIBAGQG344HEXC24MX4UA2CAZLTIGOPI656ZDLZPLRLEGJFHSAPX3HNRRDSXNGTF4WQWA5DRSV65QM6P5AWA
	// 52 bytes a share, 84 in a sealed set
	// Box 1207, Main Street branch; the key is with the lawyer
}

// A receiver reads whatever text it is given, sorts the shares into sets
// and recovers each set it holds k shares of. Nothing it rejects stops
// the others.
func ExampleGroup() {
	a, err := shaqr.Split([]byte("set a"), shaqr.TypeText, 2, 3)
	if err != nil {
		log.Fatal(err)
	}
	b, err := shaqr.Split([]byte("set b"), shaqr.TypeText, 2, 3)
	if err != nil {
		log.Fatal(err)
	}
	text := strings.Join([]string{
		shaqr.Encode(a[0]),
		shaqr.Encode(b[1]),
		shaqr.Encode(a[2]),
		"SHAQR:AEBA", // cut short
	}, "\n")

	held, rejected := shaqr.Decode(text)
	for _, err := range rejected {
		fmt.Println(err)
	}
	sets, dropped := shaqr.Group(held)
	for _, r := range dropped {
		fmt.Println(r.Index, r.Err)
	}
	for _, set := range sets {
		_, payload, err := shaqr.Combine(set)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("%s\n", payload)
	}

	// Output:
	// 3 shaqr: share check failed: 2 bytes cannot hold one
	// set a
	// shaqr: not enough shares: 1 of 2
}
