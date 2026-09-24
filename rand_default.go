// SPDX-License-Identifier: CC0-1.0

//go:build !baremetal

package shaqr

import "crypto/rand"

// On a host crypto/rand is the default source of r. A bare-metal build
// names no default: TinyGo backs crypto/rand with whatever the chip offers,
// on the RP2350 a ring oscillator LFSR unfit for cryptography, so a session
// set there needs Splitter.Rand. Derived and open sets read nothing.
func init() { defaultRand = rand.Reader }
