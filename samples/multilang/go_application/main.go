package main

import (
	"fmt"
	"os"
	"strconv"
)

// usage reports an ordinary usage failure and exits non-zero without touching
// the protected core. Argument parsing happens before any root is called, so a
// usage failure never triggers the native loader.
func usage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}

func i32(text string) int32 {
	v, err := strconv.ParseInt(text, 10, 32)
	if err != nil {
		usage("invalid int32 operand: " + text)
	}
	return int32(v)
}

func i64(text string) int64 {
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		usage("invalid int64 operand: " + text)
	}
	return v
}

func u32(text string) uint32 {
	v, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		usage("invalid uint32 operand: " + text)
	}
	return uint32(v)
}

func u64(text string) uint64 {
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		usage("invalid uint64 operand: " + text)
	}
	return v
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage("usage: app <fold|wide|mix|narrow> operands...")
	}
	op, operands := args[0], args[1:]
	switch op {
	case "fold":
		if len(operands) != 2 {
			usage("fold requires 2 operands")
		}
		fmt.Println(Fold(i32(operands[0]), i32(operands[1])))
	case "wide":
		if len(operands) != 2 {
			usage("wide requires 2 operands")
		}
		fmt.Println(Wide(i64(operands[0]), u64(operands[1])))
	case "mix":
		if len(operands) != 2 {
			usage("mix requires 2 operands")
		}
		fmt.Println(Mix(u32(operands[0]), u32(operands[1])))
	case "narrow":
		if len(operands) != 2 {
			usage("narrow requires 2 operands")
		}
		fmt.Println(Narrow(i64(operands[0]), u32(operands[1])))
	default:
		usage("unknown operation: " + op)
	}
}
