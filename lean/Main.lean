import Lean
import Reaction

def uint64Max : Nat := 18446744073709551615

def parseNatField (label value : String) : Except String Nat :=
  match value.toNat? with
  | some number => .ok number
  | none => .error s!"{label} is not a natural number"

def checkVector (line : String) : Except String Bool := do
  match line.trim.splitOn "," with
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
  | _ => .error "settlement row must contain eight comma-separated fields"

def checkLedgerVector (line : String) : Except String Bool := do
  match line.trim.splitOn "," with
  | [name, account, preBalanceText, preVersionText, tokenVersionText,
      ledgerBalanceText, debitText, status, expectedBalanceText, expectedVersionText] => do
      let preBalance ← parseNatField s!"{name}.pre_balance" preBalanceText
      let preVersion ← parseNatField s!"{name}.pre_state_version" preVersionText
      let tokenVersion ← parseNatField s!"{name}.token_state_version" tokenVersionText
      let ledgerBalance ← parseNatField s!"{name}.ledger_balance" ledgerBalanceText
      let debit ← parseNatField s!"{name}.total_debit" debitText
      let expectedBalance ← parseNatField s!"{name}.expected_balance" expectedBalanceText
      let expectedVersion ← parseNatField s!"{name}.expected_state_version" expectedVersionText
      let state : AccountState := {
        accountId := account
        authoritativeBalance := preBalance
        stateVersion := preVersion
      }
      let token : SettlementToken := {
        accountId := account
        expectedStateVersion := tokenVersion
        ledgerBalance := ledgerBalance
        totalDebit := debit
      }
      if status == "COMMITTED" then
        match applySettlement state token with
        | some result =>
            pure (
              result.authoritativeBalance == expectedBalance &&
              result.stateVersion == expectedVersion
            )
        | none => pure false
      else if status == "REFUSED" then
        match applySettlement state token with
        | none =>
            pure (expectedBalance == preBalance && expectedVersion == preVersion)
        | some _ => pure false
      else
        pure false
  | _ => .error "ledger row must contain ten comma-separated fields"

def main (args : List String) : IO Unit := do
  let paths ← match args with
    | [arithmeticFile, ledgerFile] => pure (arithmeticFile, ledgerFile)
    | _ => throw <| IO.userError "usage: lake exe tas_vectors <settlement.csv> <ledger.csv>"
  let arithmeticContents ← IO.FS.readFile paths.1
  let arithmeticRows :=
    (arithmeticContents.splitOn "\n").drop 1 |>.filter (· != "")
  if arithmeticRows.length != 14 then
    throw <| IO.userError s!"expected 14 arithmetic vectors, found {arithmeticRows.length}"
  for row in arithmeticRows do
    match checkVector row with
    | .ok true => pure ()
    | .ok false =>
        throw <| IO.userError s!"settlement vector failed: {row}"
    | .error message =>
        throw <| IO.userError s!"invalid settlement vector ({message}): {row}"

  let ledgerContents ← IO.FS.readFile paths.2
  let ledgerRows := (ledgerContents.splitOn "\n").drop 1 |>.filter (· != "")
  if ledgerRows.isEmpty then
    throw <| IO.userError "no optimistic escrow vectors were supplied"
  for row in ledgerRows do
    match checkLedgerVector row with
    | .ok true => pure ()
    | .ok false =>
        throw <| IO.userError s!"optimistic escrow vector failed: {row}"
    | .error message =>
        throw <| IO.userError s!"invalid ledger vector ({message}): {row}"
  IO.println s!"{arithmeticRows.length} settlement and {ledgerRows.length} optimistic escrow vectors passed"
