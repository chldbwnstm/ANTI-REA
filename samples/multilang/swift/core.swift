// Owned non-security scalar fixture. Real Swift helpers must also be protected.
@inline(never)
private func mixUnsigned(_ x: UInt64, _ y: UInt64) -> UInt64 {
    let a = (x &+ (y &* 0x9e3779b97f4a7c15)) ^ 0xd1b54a32d192ed03
    return (a &<< 17) ^ (a &>> 29)
}

@_cdecl("swift_score")
public func swift_score(_ x: UInt64, _ y: UInt64) -> UInt64 {
    var state = mixUnsigned(x, y)
    var index: UInt64 = 0
    while index < 5 {
        if ((state ^ y) & 1) == 0 {
            state = (state &* 33) &+ x
        } else {
            state = (state &- y) ^ (x &>> index)
        }
        state = mixUnsigned(state, index)
        index = index &+ 1
    }
    return state ^ y
}

@inline(never)
private func mixSigned(_ x: Int64, _ y: Int64) -> Int64 {
    let a = x &* 31
    return (a &+ y) ^ (a &>> 11)
}

@_cdecl("swift_signed")
public func swift_signed(_ x: Int64, _ y: Int64) -> Int64 {
    if x < y {
        return mixSigned(x, y) &- x
    }
    return mixSigned(y, x) &+ y
}

@inline(never)
private func mixUnsigned32(_ x: UInt32, _ y: UInt32) -> UInt32 {
    let folded = (x &+ (y &* 0x9e3779b9)) ^ 0x85ebca6b
    return (folded &<< 7) ^ (folded &>> 19)
}

@_cdecl("swift_unsigned32")
public func swift_unsigned32(x: UInt32, y: UInt32) -> UInt32 {
    let folded = mixUnsigned32(x, y)
    if (x & 3) < (y & 3) {
        return folded &+ (x &* 17)
    }
    return folded &- (y &* 13)
}

@inline(never)
private func mixSigned32(_ x: Int32, _ y: Int32) -> Int32 {
    return (x &* 73) ^ (y &>> 5)
}

@_cdecl("swift_signed32")
public func swift_signed32(x: Int32, y: Int32) -> Int32 {
    if x < 0 {
        return mixSigned32(x, y) &+ y
    }
    return mixSigned32(y, x) &- x
}
