import Lean

def uint64Max : Nat := 18446744073709551615

def parseNatField (label value : String) : Except String Nat :=
  match value.toNat? with
  | some number => .ok number
  | none => .error s!"{label} is not a natural number"

def checkVector (line : String) : Except String Bool := do
  match line.splitOn "," with
  | [name, grossText, feeBpsText, balanceText, feeText, netText, validText, afterText] => do
      let gross ← parseNatField s!"{name}.gross" grossText
      let feeBps ← parseNatField s!"{name}.fee_bps" feeBpsText
      let balance ← parseNatField s!"{name}.balance" balanceText
      let expectedFee ← parseNatField s!"{name}.expected_fee" feeText
      let expectedNet ← parseNatField s!"{name}.expected_net" netText
      let expectedAfter ← parseNatField s!"{name}.expected_after" afterText
      let expectedValid := validText == "true"
      let fee := gross * feeBps / 10000
      let net := gross - fee
      let valid := gross ≤ balance
      let after := if valid then balance - gross else 0
      pure (
        gross ≤ uint64Max &&
        balance ≤ uint64Max &&
        feeBps ≤ 10000 &&
        fee + net == gross &&
        fee == expectedFee &&
        net == expectedNet &&
        valid == expectedValid &&
        after == expectedAfter
      )
  | _ => .error "vector row must contain eight comma-separated fields"

def main : IO Unit := do
  let args ← IO.getArgs
  let path ← match args with
    | [file] => pure file
    | _ => throw <| IO.userError "usage: lake exe tas_vectors <vector.csv>"
  let contents ← IO.FS.readFile path
  let rows := (contents.splitOn "\n").drop 1 |>.filter (· != "")
  if rows.length != 14 then
    throw <| IO.userError s!"expected 14 vectors, found {rows.length}"
  for row in rows do
    match checkVector row with
    | .ok true => pure ()
    | .ok false =>
        throw <| IO.userError s!"vector failed: {row}"
    | .error message =>
        throw <| IO.userError s!"invalid vector ({message}): {row}"
  IO.println s!"{rows.length} shared TAS arithmetic vectors passed"
