import Lake
open Lake DSL

package tasCrossLang

lean_exe tas_vectors where
  root := `Main

lean_lib TasSmt where
  roots := #[`Smt]
