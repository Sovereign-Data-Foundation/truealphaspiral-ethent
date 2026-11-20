def sqliteIntMax : Nat := 9223372036854775807

structure AccountState where
  accountId : String
  authoritativeBalance : Nat
  stateVersion : Nat
  deriving BEq, Repr

structure SettlementToken where
  accountId : String
  expectedStateVersion : Nat
  ledgerBalance : Nat
  totalDebit : Nat
  deriving BEq, Repr

def applySettlement
    (state : AccountState)
    (token : SettlementToken) : Option AccountState :=
  if token.accountId != state.accountId then none
  else if token.expectedStateVersion != state.stateVersion then none
  else if token.ledgerBalance != state.authoritativeBalance then none
  else if state.authoritativeBalance > sqliteIntMax then none
  else if token.ledgerBalance > sqliteIntMax then none
  else if token.totalDebit > sqliteIntMax then none
  else if token.totalDebit > state.authoritativeBalance then none
  else if state.stateVersion >= sqliteIntMax then none
  else some {
    accountId := state.accountId
    authoritativeBalance := state.authoritativeBalance - token.totalDebit
    stateVersion := state.stateVersion + 1
  }
