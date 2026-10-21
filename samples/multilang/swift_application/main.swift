// Ordinary ANTI-REA Swift application fixture.
//
// It calls every selected native-core root using both external argument label
// styles: swift_score / swift_signed use underscore (unlabelled) arguments,
// swift_unsigned32 / swift_signed32 use named `x:` / `y:` labels. In the
// original build this file links the unchanged core.swift; in the protected
// build the generated same-name facades forward to the packaged protected
// native core. These source bytes are identical in both builds, so external
// label preservation is what keeps the protected build compiling unchanged.
//
// Usage: <op> <x> <y>
//   op in {score, signed, unsigned32, signed32}
//   x, y: decimal integers parsed per the op's scalar type
// Exit codes: 0 success, 2 usage error (arity / unknown op),
//             1 operand parse error (non-integer / out of range).
import Foundation

func usage() -> Never { exit(2) }
func operandError() -> Never { exit(1) }

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.count != 3 {
    usage()
}

let op = arguments[0]
let rawX = arguments[1]
let rawY = arguments[2]

switch op {
case "score":
    guard let x = UInt64(rawX), let y = UInt64(rawY) else { operandError() }
    print(swift_score(x, y))
case "signed":
    guard let x = Int64(rawX), let y = Int64(rawY) else { operandError() }
    print(swift_signed(x, y))
case "unsigned32":
    guard let x = UInt32(rawX), let y = UInt32(rawY) else { operandError() }
    print(swift_unsigned32(x: x, y: y))
case "signed32":
    guard let x = Int32(rawX), let y = Int32(rawY) else { operandError() }
    print(swift_signed32(x: x, y: y))
default:
    usage()
}
