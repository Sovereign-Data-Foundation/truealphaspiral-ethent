import Std

namespace TasSmt

structure Proof where
  value : ByteArray
  mask : ByteArray
  siblings : Array ByteArray
  deriving Repr

def maskBit (mask : ByteArray) (depth : Nat) : Option Bool :=
  if depth >= 256 then
    none
  else if h : depth / 8 < mask.size then
    some (((mask[depth / 8]'h) / 2 ^ (depth % 8)) % 2 == 1)
  else
    none

def popcount (mask : ByteArray) : Nat :=
  let rec loop (index count : Nat) : Nat :=
    if h : index < mask.size then
      let byte := mask[index]'h
      let byteCount :=
        (List.range 8).foldl
          (fun subtotal bit =>
            subtotal + (if (byte / 2 ^ bit) % 2 == 1 then 1 else 0))
          0
      loop (index + 1) (count + byteCount)
    else
      count
  loop 0 0

def decodeProof
    (value : ByteArray)
    (mask : ByteArray)
    (siblings : ByteArray)
    : Option Proof :=
  if value.size != 32 then
    none
  else if mask.size != 32 then
    none
  else if siblings.size != popcount mask * 32 then
    none
  else
    let rec collect (depth cursor : Nat) (out : Array ByteArray) :
        Option (Array ByteArray) :=
      if depth >= 256 then
        some out
      else
        match maskBit mask depth with
        | some true =>
            if h : cursor * 32 + 32 ≤ siblings.size then
              let sibling := siblings.extract (cursor * 32) (cursor * 32 + 32)
              collect (depth + 1) (cursor + 1) (out.push sibling)
            else
              none
        | some false => collect (depth + 1) cursor out
        | none => none
    match collect 0 0 #[] with
    | some packed => some { value := value, mask := mask, siblings := packed }
    | none => none

end TasSmt
