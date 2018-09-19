package main

import "fmt"

// #cgo CFLAGS: -I${SRCDIR}/knowdy/src/include
// #cgo LDFLAGS: ${SRCDIR}/knowdy/build/lib/libcore_static.a
import "C"

//import "unsafe"

func main() {
	fmt.Println("test")
}
