// Lean compiler output
// Module: Main
// Imports: Init Lean Reaction
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
static lean_object* l_checkLedgerVector___closed__7;
static lean_object* l_main___lambda__1___closed__2;
static lean_object* l_checkVector___closed__9;
static lean_object* l_List_forIn_loop___at_main___spec__3___closed__1;
LEAN_EXPORT lean_object* _lean_main(lean_object*, lean_object*);
static lean_object* l_checkLedgerVector___closed__9;
static lean_object* l_checkLedgerVector___closed__5;
lean_object* l_String_toNat_x3f(lean_object*);
LEAN_EXPORT lean_object* l_parseNatField___boxed(lean_object*, lean_object*);
static lean_object* l_checkLedgerVector___closed__3;
static lean_object* l_main___lambda__1___closed__1;
LEAN_EXPORT lean_object* l_checkLedgerVector___boxed(lean_object*);
lean_object* l_String_trim(lean_object*);
LEAN_EXPORT lean_object* l_uint64Max;
static lean_object* l_List_forIn_loop___at_main___spec__2___closed__2;
static lean_object* l_main___closed__3;
uint8_t lean_string_dec_eq(lean_object*, lean_object*);
lean_object* l_IO_println___at_Lean_instEval___spec__1(lean_object*, lean_object*);
static lean_object* l_checkVector___closed__6;
LEAN_EXPORT lean_object* l_checkVector___boxed(lean_object*);
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_List_forIn_loop___at_main___spec__2(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_main___lambda__2(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_List_filterTR_loop___at_main___spec__1(lean_object*, lean_object*);
lean_object* lean_nat_div(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_List_forIn_loop___at_main___spec__3(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_main___lambda__3(lean_object*, lean_object*);
static lean_object* l_main___closed__1;
static lean_object* l_main___lambda__2___closed__1;
uint8_t l_List_isEmpty___rarg(lean_object*);
LEAN_EXPORT lean_object* l_main___lambda__2___boxed(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l_checkLedgerVector___closed__10;
static lean_object* l_checkVector___closed__8;
static lean_object* l_main___lambda__3___closed__1;
static lean_object* l_checkLedgerVector___closed__6;
lean_object* l_List_lengthTRAux___rarg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_main___lambda__1___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l_checkVector___closed__1;
static lean_object* l_checkLedgerVector___closed__8;
static lean_object* l_checkLedgerVector___closed__1;
static lean_object* l_checkLedgerVector___closed__11;
lean_object* l_applySettlement(lean_object*, lean_object*);
lean_object* l_IO_FS_readFile(lean_object*, lean_object*);
static lean_object* l_checkVector___closed__4;
static lean_object* l_checkVector___closed__5;
static lean_object* l_checkVector___closed__11;
static lean_object* l_main___lambda__2___closed__2;
lean_object* l_List_drop___rarg(lean_object*, lean_object*);
static lean_object* l_checkVector___closed__10;
static lean_object* l_parseNatField___closed__2;
LEAN_EXPORT lean_object* l_checkVector(lean_object*);
LEAN_EXPORT lean_object* l_checkLedgerVector(lean_object*);
static lean_object* l_List_forIn_loop___at_main___spec__2___closed__3;
static lean_object* l_uint64Max___closed__1;
static lean_object* l_List_forIn_loop___at_main___spec__3___closed__2;
lean_object* lean_nat_sub(lean_object*, lean_object*);
lean_object* lean_nat_mul(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_main___lambda__1(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l_main___lambda__2___closed__3;
static lean_object* l_List_forIn_loop___at_main___spec__2___closed__1;
lean_object* l_List_reverse___rarg(lean_object*);
static lean_object* l_parseNatField___closed__1;
static lean_object* l_checkVector___closed__2;
LEAN_EXPORT lean_object* l_parseNatField(lean_object*, lean_object*);
static lean_object* l_main___closed__2;
lean_object* lean_string_append(lean_object*, lean_object*);
static lean_object* l_checkVector___closed__3;
LEAN_EXPORT lean_object* l_main___lambda__3___boxed(lean_object*, lean_object*);
uint8_t lean_nat_dec_le(lean_object*, lean_object*);
static lean_object* l_checkVector___closed__7;
lean_object* lean_nat_add(lean_object*, lean_object*);
static lean_object* l_checkLedgerVector___closed__2;
lean_object* l___private_Init_Data_Repr_0__Nat_reprFast(lean_object*);
lean_object* l_String_splitOn(lean_object*, lean_object*);
static lean_object* l_checkLedgerVector___closed__4;
static lean_object* _init_l_uint64Max___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_cstr_to_nat("18446744073709551615");
return x_1;
}
}
static lean_object* _init_l_uint64Max() {
_start:
{
lean_object* x_1; 
x_1 = l_uint64Max___closed__1;
return x_1;
}
}
static lean_object* _init_l_parseNatField___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("", 0, 0);
return x_1;
}
}
static lean_object* _init_l_parseNatField___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" is not a natural number", 24, 24);
return x_1;
}
}
LEAN_EXPORT lean_object* l_parseNatField(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_String_toNat_x3f(x_2);
if (lean_obj_tag(x_3) == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; 
x_4 = l_parseNatField___closed__1;
x_5 = lean_string_append(x_4, x_1);
x_6 = l_parseNatField___closed__2;
x_7 = lean_string_append(x_5, x_6);
x_8 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_8, 0, x_7);
return x_8;
}
else
{
uint8_t x_9; 
x_9 = !lean_is_exclusive(x_3);
if (x_9 == 0)
{
return x_3;
}
else
{
lean_object* x_10; lean_object* x_11; 
x_10 = lean_ctor_get(x_3, 0);
lean_inc(x_10);
lean_dec(x_3);
x_11 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_11, 0, x_10);
return x_11;
}
}
}
}
LEAN_EXPORT lean_object* l_parseNatField___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_parseNatField(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
static lean_object* _init_l_checkVector___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(",", 1, 1);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("settlement row must contain eight comma-separated fields", 56, 56);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l_checkVector___closed__2;
x_2 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l_checkVector___closed__4() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".gross", 6, 6);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__5() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".fee_bps", 8, 8);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__6() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".balance", 8, 8);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__7() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".expected_fee", 13, 13);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__8() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".expected_net", 13, 13);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__9() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".expected_after", 15, 15);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__10() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("true", 4, 4);
return x_1;
}
}
static lean_object* _init_l_checkVector___closed__11() {
_start:
{
uint8_t x_1; lean_object* x_2; lean_object* x_3; 
x_1 = 0;
x_2 = lean_box(x_1);
x_3 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_3, 0, x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_checkVector(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_2 = l_String_trim(x_1);
x_3 = l_checkVector___closed__1;
x_4 = l_String_splitOn(x_2, x_3);
if (lean_obj_tag(x_4) == 0)
{
lean_object* x_5; 
x_5 = l_checkVector___closed__3;
return x_5;
}
else
{
lean_object* x_6; 
x_6 = lean_ctor_get(x_4, 1);
lean_inc(x_6);
if (lean_obj_tag(x_6) == 0)
{
lean_object* x_7; 
lean_dec(x_4);
x_7 = l_checkVector___closed__3;
return x_7;
}
else
{
lean_object* x_8; 
x_8 = lean_ctor_get(x_6, 1);
lean_inc(x_8);
if (lean_obj_tag(x_8) == 0)
{
lean_object* x_9; 
lean_dec(x_6);
lean_dec(x_4);
x_9 = l_checkVector___closed__3;
return x_9;
}
else
{
lean_object* x_10; 
x_10 = lean_ctor_get(x_8, 1);
lean_inc(x_10);
if (lean_obj_tag(x_10) == 0)
{
lean_object* x_11; 
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_11 = l_checkVector___closed__3;
return x_11;
}
else
{
lean_object* x_12; 
x_12 = lean_ctor_get(x_10, 1);
lean_inc(x_12);
if (lean_obj_tag(x_12) == 0)
{
lean_object* x_13; 
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_13 = l_checkVector___closed__3;
return x_13;
}
else
{
lean_object* x_14; 
x_14 = lean_ctor_get(x_12, 1);
lean_inc(x_14);
if (lean_obj_tag(x_14) == 0)
{
lean_object* x_15; 
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_15 = l_checkVector___closed__3;
return x_15;
}
else
{
lean_object* x_16; 
x_16 = lean_ctor_get(x_14, 1);
lean_inc(x_16);
if (lean_obj_tag(x_16) == 0)
{
lean_object* x_17; 
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_17 = l_checkVector___closed__3;
return x_17;
}
else
{
lean_object* x_18; 
x_18 = lean_ctor_get(x_16, 1);
lean_inc(x_18);
if (lean_obj_tag(x_18) == 0)
{
lean_object* x_19; 
lean_dec(x_16);
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_19 = l_checkVector___closed__3;
return x_19;
}
else
{
lean_object* x_20; 
x_20 = lean_ctor_get(x_18, 1);
lean_inc(x_20);
if (lean_obj_tag(x_20) == 0)
{
lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; 
x_21 = lean_ctor_get(x_4, 0);
lean_inc(x_21);
lean_dec(x_4);
x_22 = lean_ctor_get(x_6, 0);
lean_inc(x_22);
lean_dec(x_6);
x_23 = lean_ctor_get(x_8, 0);
lean_inc(x_23);
lean_dec(x_8);
x_24 = lean_ctor_get(x_10, 0);
lean_inc(x_24);
lean_dec(x_10);
x_25 = lean_ctor_get(x_12, 0);
lean_inc(x_25);
lean_dec(x_12);
x_26 = lean_ctor_get(x_14, 0);
lean_inc(x_26);
lean_dec(x_14);
x_27 = lean_ctor_get(x_16, 0);
lean_inc(x_27);
lean_dec(x_16);
x_28 = lean_ctor_get(x_18, 0);
lean_inc(x_28);
lean_dec(x_18);
x_29 = l_parseNatField___closed__1;
x_30 = lean_string_append(x_29, x_21);
lean_dec(x_21);
x_31 = l_checkVector___closed__4;
lean_inc(x_30);
x_32 = lean_string_append(x_30, x_31);
x_33 = l_parseNatField(x_32, x_22);
lean_dec(x_22);
lean_dec(x_32);
if (lean_obj_tag(x_33) == 0)
{
uint8_t x_34; 
lean_dec(x_30);
lean_dec(x_28);
lean_dec(x_27);
lean_dec(x_26);
lean_dec(x_25);
lean_dec(x_24);
lean_dec(x_23);
x_34 = !lean_is_exclusive(x_33);
if (x_34 == 0)
{
return x_33;
}
else
{
lean_object* x_35; lean_object* x_36; 
x_35 = lean_ctor_get(x_33, 0);
lean_inc(x_35);
lean_dec(x_33);
x_36 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_36, 0, x_35);
return x_36;
}
}
else
{
lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; 
x_37 = lean_ctor_get(x_33, 0);
lean_inc(x_37);
lean_dec(x_33);
x_38 = l_checkVector___closed__5;
lean_inc(x_30);
x_39 = lean_string_append(x_30, x_38);
x_40 = l_parseNatField(x_39, x_23);
lean_dec(x_23);
lean_dec(x_39);
if (lean_obj_tag(x_40) == 0)
{
uint8_t x_41; 
lean_dec(x_37);
lean_dec(x_30);
lean_dec(x_28);
lean_dec(x_27);
lean_dec(x_26);
lean_dec(x_25);
lean_dec(x_24);
x_41 = !lean_is_exclusive(x_40);
if (x_41 == 0)
{
return x_40;
}
else
{
lean_object* x_42; lean_object* x_43; 
x_42 = lean_ctor_get(x_40, 0);
lean_inc(x_42);
lean_dec(x_40);
x_43 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_43, 0, x_42);
return x_43;
}
}
else
{
lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; 
x_44 = lean_ctor_get(x_40, 0);
lean_inc(x_44);
lean_dec(x_40);
x_45 = l_checkVector___closed__6;
lean_inc(x_30);
x_46 = lean_string_append(x_30, x_45);
x_47 = l_parseNatField(x_46, x_24);
lean_dec(x_24);
lean_dec(x_46);
if (lean_obj_tag(x_47) == 0)
{
uint8_t x_48; 
lean_dec(x_44);
lean_dec(x_37);
lean_dec(x_30);
lean_dec(x_28);
lean_dec(x_27);
lean_dec(x_26);
lean_dec(x_25);
x_48 = !lean_is_exclusive(x_47);
if (x_48 == 0)
{
return x_47;
}
else
{
lean_object* x_49; lean_object* x_50; 
x_49 = lean_ctor_get(x_47, 0);
lean_inc(x_49);
lean_dec(x_47);
x_50 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_50, 0, x_49);
return x_50;
}
}
else
{
lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; 
x_51 = lean_ctor_get(x_47, 0);
lean_inc(x_51);
lean_dec(x_47);
x_52 = l_checkVector___closed__7;
lean_inc(x_30);
x_53 = lean_string_append(x_30, x_52);
x_54 = l_parseNatField(x_53, x_25);
lean_dec(x_25);
lean_dec(x_53);
if (lean_obj_tag(x_54) == 0)
{
uint8_t x_55; 
lean_dec(x_51);
lean_dec(x_44);
lean_dec(x_37);
lean_dec(x_30);
lean_dec(x_28);
lean_dec(x_27);
lean_dec(x_26);
x_55 = !lean_is_exclusive(x_54);
if (x_55 == 0)
{
return x_54;
}
else
{
lean_object* x_56; lean_object* x_57; 
x_56 = lean_ctor_get(x_54, 0);
lean_inc(x_56);
lean_dec(x_54);
x_57 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_57, 0, x_56);
return x_57;
}
}
else
{
lean_object* x_58; lean_object* x_59; lean_object* x_60; lean_object* x_61; 
x_58 = lean_ctor_get(x_54, 0);
lean_inc(x_58);
lean_dec(x_54);
x_59 = l_checkVector___closed__8;
lean_inc(x_30);
x_60 = lean_string_append(x_30, x_59);
x_61 = l_parseNatField(x_60, x_26);
lean_dec(x_26);
lean_dec(x_60);
if (lean_obj_tag(x_61) == 0)
{
uint8_t x_62; 
lean_dec(x_58);
lean_dec(x_51);
lean_dec(x_44);
lean_dec(x_37);
lean_dec(x_30);
lean_dec(x_28);
lean_dec(x_27);
x_62 = !lean_is_exclusive(x_61);
if (x_62 == 0)
{
return x_61;
}
else
{
lean_object* x_63; lean_object* x_64; 
x_63 = lean_ctor_get(x_61, 0);
lean_inc(x_63);
lean_dec(x_61);
x_64 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_64, 0, x_63);
return x_64;
}
}
else
{
lean_object* x_65; lean_object* x_66; lean_object* x_67; lean_object* x_68; 
x_65 = lean_ctor_get(x_61, 0);
lean_inc(x_65);
lean_dec(x_61);
x_66 = l_checkVector___closed__9;
x_67 = lean_string_append(x_30, x_66);
x_68 = l_parseNatField(x_67, x_28);
lean_dec(x_28);
lean_dec(x_67);
if (lean_obj_tag(x_68) == 0)
{
uint8_t x_69; 
lean_dec(x_65);
lean_dec(x_58);
lean_dec(x_51);
lean_dec(x_44);
lean_dec(x_37);
lean_dec(x_27);
x_69 = !lean_is_exclusive(x_68);
if (x_69 == 0)
{
return x_68;
}
else
{
lean_object* x_70; lean_object* x_71; 
x_70 = lean_ctor_get(x_68, 0);
lean_inc(x_70);
lean_dec(x_68);
x_71 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_71, 0, x_70);
return x_71;
}
}
else
{
lean_object* x_72; lean_object* x_73; lean_object* x_74; uint8_t x_75; lean_object* x_76; lean_object* x_77; lean_object* x_78; lean_object* x_79; uint8_t x_80; lean_object* x_81; uint8_t x_82; lean_object* x_83; 
x_72 = lean_ctor_get(x_68, 0);
lean_inc(x_72);
if (lean_is_exclusive(x_68)) {
 lean_ctor_release(x_68, 0);
 x_73 = x_68;
} else {
 lean_dec_ref(x_68);
 x_73 = lean_box(0);
}
x_74 = l_checkVector___closed__10;
x_75 = lean_string_dec_eq(x_27, x_74);
lean_dec(x_27);
x_76 = lean_nat_mul(x_37, x_44);
x_77 = lean_unsigned_to_nat(10000u);
x_78 = lean_nat_div(x_76, x_77);
lean_dec(x_76);
x_79 = lean_nat_sub(x_37, x_78);
x_80 = lean_nat_dec_le(x_37, x_51);
x_81 = l_uint64Max;
x_82 = lean_nat_dec_le(x_37, x_81);
if (x_80 == 0)
{
lean_object* x_105; 
x_105 = lean_unsigned_to_nat(0u);
x_83 = x_105;
goto block_104;
}
else
{
lean_object* x_106; 
x_106 = lean_nat_sub(x_51, x_37);
x_83 = x_106;
goto block_104;
}
block_104:
{
if (x_82 == 0)
{
lean_object* x_84; 
lean_dec(x_83);
lean_dec(x_79);
lean_dec(x_78);
lean_dec(x_73);
lean_dec(x_72);
lean_dec(x_65);
lean_dec(x_58);
lean_dec(x_51);
lean_dec(x_44);
lean_dec(x_37);
x_84 = l_checkVector___closed__11;
return x_84;
}
else
{
uint8_t x_85; 
x_85 = lean_nat_dec_le(x_51, x_81);
lean_dec(x_51);
if (x_85 == 0)
{
lean_object* x_86; 
lean_dec(x_83);
lean_dec(x_79);
lean_dec(x_78);
lean_dec(x_73);
lean_dec(x_72);
lean_dec(x_65);
lean_dec(x_58);
lean_dec(x_44);
lean_dec(x_37);
x_86 = l_checkVector___closed__11;
return x_86;
}
else
{
uint8_t x_87; 
x_87 = lean_nat_dec_le(x_44, x_77);
lean_dec(x_44);
if (x_87 == 0)
{
lean_object* x_88; 
lean_dec(x_83);
lean_dec(x_79);
lean_dec(x_78);
lean_dec(x_73);
lean_dec(x_72);
lean_dec(x_65);
lean_dec(x_58);
lean_dec(x_37);
x_88 = l_checkVector___closed__11;
return x_88;
}
else
{
lean_object* x_89; uint8_t x_90; 
x_89 = lean_nat_add(x_78, x_79);
x_90 = lean_nat_dec_eq(x_89, x_37);
lean_dec(x_37);
lean_dec(x_89);
if (x_90 == 0)
{
lean_object* x_91; 
lean_dec(x_83);
lean_dec(x_79);
lean_dec(x_78);
lean_dec(x_73);
lean_dec(x_72);
lean_dec(x_65);
lean_dec(x_58);
x_91 = l_checkVector___closed__11;
return x_91;
}
else
{
uint8_t x_92; 
x_92 = lean_nat_dec_eq(x_78, x_58);
lean_dec(x_58);
lean_dec(x_78);
if (x_92 == 0)
{
lean_object* x_93; 
lean_dec(x_83);
lean_dec(x_79);
lean_dec(x_73);
lean_dec(x_72);
lean_dec(x_65);
x_93 = l_checkVector___closed__11;
return x_93;
}
else
{
uint8_t x_94; 
x_94 = lean_nat_dec_eq(x_79, x_65);
lean_dec(x_65);
lean_dec(x_79);
if (x_94 == 0)
{
lean_object* x_95; 
lean_dec(x_83);
lean_dec(x_73);
lean_dec(x_72);
x_95 = l_checkVector___closed__11;
return x_95;
}
else
{
if (x_80 == 0)
{
if (x_75 == 0)
{
uint8_t x_96; lean_object* x_97; lean_object* x_98; 
x_96 = lean_nat_dec_eq(x_83, x_72);
lean_dec(x_72);
lean_dec(x_83);
x_97 = lean_box(x_96);
if (lean_is_scalar(x_73)) {
 x_98 = lean_alloc_ctor(1, 1, 0);
} else {
 x_98 = x_73;
}
lean_ctor_set(x_98, 0, x_97);
return x_98;
}
else
{
lean_object* x_99; 
lean_dec(x_83);
lean_dec(x_73);
lean_dec(x_72);
x_99 = l_checkVector___closed__11;
return x_99;
}
}
else
{
if (x_75 == 0)
{
lean_object* x_100; 
lean_dec(x_83);
lean_dec(x_73);
lean_dec(x_72);
x_100 = l_checkVector___closed__11;
return x_100;
}
else
{
uint8_t x_101; lean_object* x_102; lean_object* x_103; 
x_101 = lean_nat_dec_eq(x_83, x_72);
lean_dec(x_72);
lean_dec(x_83);
x_102 = lean_box(x_101);
if (lean_is_scalar(x_73)) {
 x_103 = lean_alloc_ctor(1, 1, 0);
} else {
 x_103 = x_73;
}
lean_ctor_set(x_103, 0, x_102);
return x_103;
}
}
}
}
}
}
}
}
}
}
}
}
}
}
}
}
else
{
lean_object* x_107; 
lean_dec(x_20);
lean_dec(x_18);
lean_dec(x_16);
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_107 = l_checkVector___closed__3;
return x_107;
}
}
}
}
}
}
}
}
}
}
}
LEAN_EXPORT lean_object* l_checkVector___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_checkVector(x_1);
lean_dec(x_1);
return x_2;
}
}
static lean_object* _init_l_checkLedgerVector___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("ledger row must contain ten comma-separated fields", 50, 50);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l_checkLedgerVector___closed__1;
x_2 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l_checkLedgerVector___closed__3() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".pre_balance", 12, 12);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__4() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".pre_state_version", 18, 18);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__5() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".token_state_version", 20, 20);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__6() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".ledger_balance", 15, 15);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__7() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".total_debit", 12, 12);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__8() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".expected_balance", 17, 17);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__9() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(".expected_state_version", 23, 23);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__10() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("COMMITTED", 9, 9);
return x_1;
}
}
static lean_object* _init_l_checkLedgerVector___closed__11() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("REFUSED", 7, 7);
return x_1;
}
}
LEAN_EXPORT lean_object* l_checkLedgerVector(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_2 = l_String_trim(x_1);
x_3 = l_checkVector___closed__1;
x_4 = l_String_splitOn(x_2, x_3);
if (lean_obj_tag(x_4) == 0)
{
lean_object* x_5; 
x_5 = l_checkLedgerVector___closed__2;
return x_5;
}
else
{
lean_object* x_6; 
x_6 = lean_ctor_get(x_4, 1);
lean_inc(x_6);
if (lean_obj_tag(x_6) == 0)
{
lean_object* x_7; 
lean_dec(x_4);
x_7 = l_checkLedgerVector___closed__2;
return x_7;
}
else
{
lean_object* x_8; 
x_8 = lean_ctor_get(x_6, 1);
lean_inc(x_8);
if (lean_obj_tag(x_8) == 0)
{
lean_object* x_9; 
lean_dec(x_6);
lean_dec(x_4);
x_9 = l_checkLedgerVector___closed__2;
return x_9;
}
else
{
lean_object* x_10; 
x_10 = lean_ctor_get(x_8, 1);
lean_inc(x_10);
if (lean_obj_tag(x_10) == 0)
{
lean_object* x_11; 
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_11 = l_checkLedgerVector___closed__2;
return x_11;
}
else
{
lean_object* x_12; 
x_12 = lean_ctor_get(x_10, 1);
lean_inc(x_12);
if (lean_obj_tag(x_12) == 0)
{
lean_object* x_13; 
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_13 = l_checkLedgerVector___closed__2;
return x_13;
}
else
{
lean_object* x_14; 
x_14 = lean_ctor_get(x_12, 1);
lean_inc(x_14);
if (lean_obj_tag(x_14) == 0)
{
lean_object* x_15; 
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_15 = l_checkLedgerVector___closed__2;
return x_15;
}
else
{
lean_object* x_16; 
x_16 = lean_ctor_get(x_14, 1);
lean_inc(x_16);
if (lean_obj_tag(x_16) == 0)
{
lean_object* x_17; 
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_17 = l_checkLedgerVector___closed__2;
return x_17;
}
else
{
lean_object* x_18; 
x_18 = lean_ctor_get(x_16, 1);
lean_inc(x_18);
if (lean_obj_tag(x_18) == 0)
{
lean_object* x_19; 
lean_dec(x_16);
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_19 = l_checkLedgerVector___closed__2;
return x_19;
}
else
{
lean_object* x_20; 
x_20 = lean_ctor_get(x_18, 1);
lean_inc(x_20);
if (lean_obj_tag(x_20) == 0)
{
lean_object* x_21; 
lean_dec(x_18);
lean_dec(x_16);
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_21 = l_checkLedgerVector___closed__2;
return x_21;
}
else
{
lean_object* x_22; 
x_22 = lean_ctor_get(x_20, 1);
lean_inc(x_22);
if (lean_obj_tag(x_22) == 0)
{
lean_object* x_23; 
lean_dec(x_20);
lean_dec(x_18);
lean_dec(x_16);
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_23 = l_checkLedgerVector___closed__2;
return x_23;
}
else
{
lean_object* x_24; 
x_24 = lean_ctor_get(x_22, 1);
lean_inc(x_24);
if (lean_obj_tag(x_24) == 0)
{
lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; 
x_25 = lean_ctor_get(x_4, 0);
lean_inc(x_25);
lean_dec(x_4);
x_26 = lean_ctor_get(x_6, 0);
lean_inc(x_26);
lean_dec(x_6);
x_27 = lean_ctor_get(x_8, 0);
lean_inc(x_27);
lean_dec(x_8);
x_28 = lean_ctor_get(x_10, 0);
lean_inc(x_28);
lean_dec(x_10);
x_29 = lean_ctor_get(x_12, 0);
lean_inc(x_29);
lean_dec(x_12);
x_30 = lean_ctor_get(x_14, 0);
lean_inc(x_30);
lean_dec(x_14);
x_31 = lean_ctor_get(x_16, 0);
lean_inc(x_31);
lean_dec(x_16);
x_32 = lean_ctor_get(x_18, 0);
lean_inc(x_32);
lean_dec(x_18);
x_33 = lean_ctor_get(x_20, 0);
lean_inc(x_33);
lean_dec(x_20);
x_34 = lean_ctor_get(x_22, 0);
lean_inc(x_34);
lean_dec(x_22);
x_35 = l_parseNatField___closed__1;
x_36 = lean_string_append(x_35, x_25);
lean_dec(x_25);
x_37 = l_checkLedgerVector___closed__3;
lean_inc(x_36);
x_38 = lean_string_append(x_36, x_37);
x_39 = l_parseNatField(x_38, x_27);
lean_dec(x_27);
lean_dec(x_38);
if (lean_obj_tag(x_39) == 0)
{
uint8_t x_40; 
lean_dec(x_36);
lean_dec(x_34);
lean_dec(x_33);
lean_dec(x_32);
lean_dec(x_31);
lean_dec(x_30);
lean_dec(x_29);
lean_dec(x_28);
lean_dec(x_26);
x_40 = !lean_is_exclusive(x_39);
if (x_40 == 0)
{
return x_39;
}
else
{
lean_object* x_41; lean_object* x_42; 
x_41 = lean_ctor_get(x_39, 0);
lean_inc(x_41);
lean_dec(x_39);
x_42 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_42, 0, x_41);
return x_42;
}
}
else
{
lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; 
x_43 = lean_ctor_get(x_39, 0);
lean_inc(x_43);
lean_dec(x_39);
x_44 = l_checkLedgerVector___closed__4;
lean_inc(x_36);
x_45 = lean_string_append(x_36, x_44);
x_46 = l_parseNatField(x_45, x_28);
lean_dec(x_28);
lean_dec(x_45);
if (lean_obj_tag(x_46) == 0)
{
uint8_t x_47; 
lean_dec(x_43);
lean_dec(x_36);
lean_dec(x_34);
lean_dec(x_33);
lean_dec(x_32);
lean_dec(x_31);
lean_dec(x_30);
lean_dec(x_29);
lean_dec(x_26);
x_47 = !lean_is_exclusive(x_46);
if (x_47 == 0)
{
return x_46;
}
else
{
lean_object* x_48; lean_object* x_49; 
x_48 = lean_ctor_get(x_46, 0);
lean_inc(x_48);
lean_dec(x_46);
x_49 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_49, 0, x_48);
return x_49;
}
}
else
{
lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; 
x_50 = lean_ctor_get(x_46, 0);
lean_inc(x_50);
lean_dec(x_46);
x_51 = l_checkLedgerVector___closed__5;
lean_inc(x_36);
x_52 = lean_string_append(x_36, x_51);
x_53 = l_parseNatField(x_52, x_29);
lean_dec(x_29);
lean_dec(x_52);
if (lean_obj_tag(x_53) == 0)
{
uint8_t x_54; 
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_36);
lean_dec(x_34);
lean_dec(x_33);
lean_dec(x_32);
lean_dec(x_31);
lean_dec(x_30);
lean_dec(x_26);
x_54 = !lean_is_exclusive(x_53);
if (x_54 == 0)
{
return x_53;
}
else
{
lean_object* x_55; lean_object* x_56; 
x_55 = lean_ctor_get(x_53, 0);
lean_inc(x_55);
lean_dec(x_53);
x_56 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_56, 0, x_55);
return x_56;
}
}
else
{
lean_object* x_57; lean_object* x_58; lean_object* x_59; lean_object* x_60; 
x_57 = lean_ctor_get(x_53, 0);
lean_inc(x_57);
lean_dec(x_53);
x_58 = l_checkLedgerVector___closed__6;
lean_inc(x_36);
x_59 = lean_string_append(x_36, x_58);
x_60 = l_parseNatField(x_59, x_30);
lean_dec(x_30);
lean_dec(x_59);
if (lean_obj_tag(x_60) == 0)
{
uint8_t x_61; 
lean_dec(x_57);
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_36);
lean_dec(x_34);
lean_dec(x_33);
lean_dec(x_32);
lean_dec(x_31);
lean_dec(x_26);
x_61 = !lean_is_exclusive(x_60);
if (x_61 == 0)
{
return x_60;
}
else
{
lean_object* x_62; lean_object* x_63; 
x_62 = lean_ctor_get(x_60, 0);
lean_inc(x_62);
lean_dec(x_60);
x_63 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_63, 0, x_62);
return x_63;
}
}
else
{
lean_object* x_64; lean_object* x_65; lean_object* x_66; lean_object* x_67; 
x_64 = lean_ctor_get(x_60, 0);
lean_inc(x_64);
lean_dec(x_60);
x_65 = l_checkLedgerVector___closed__7;
lean_inc(x_36);
x_66 = lean_string_append(x_36, x_65);
x_67 = l_parseNatField(x_66, x_31);
lean_dec(x_31);
lean_dec(x_66);
if (lean_obj_tag(x_67) == 0)
{
uint8_t x_68; 
lean_dec(x_64);
lean_dec(x_57);
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_36);
lean_dec(x_34);
lean_dec(x_33);
lean_dec(x_32);
lean_dec(x_26);
x_68 = !lean_is_exclusive(x_67);
if (x_68 == 0)
{
return x_67;
}
else
{
lean_object* x_69; lean_object* x_70; 
x_69 = lean_ctor_get(x_67, 0);
lean_inc(x_69);
lean_dec(x_67);
x_70 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_70, 0, x_69);
return x_70;
}
}
else
{
lean_object* x_71; lean_object* x_72; lean_object* x_73; lean_object* x_74; 
x_71 = lean_ctor_get(x_67, 0);
lean_inc(x_71);
lean_dec(x_67);
x_72 = l_checkLedgerVector___closed__8;
lean_inc(x_36);
x_73 = lean_string_append(x_36, x_72);
x_74 = l_parseNatField(x_73, x_33);
lean_dec(x_33);
lean_dec(x_73);
if (lean_obj_tag(x_74) == 0)
{
uint8_t x_75; 
lean_dec(x_71);
lean_dec(x_64);
lean_dec(x_57);
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_36);
lean_dec(x_34);
lean_dec(x_32);
lean_dec(x_26);
x_75 = !lean_is_exclusive(x_74);
if (x_75 == 0)
{
return x_74;
}
else
{
lean_object* x_76; lean_object* x_77; 
x_76 = lean_ctor_get(x_74, 0);
lean_inc(x_76);
lean_dec(x_74);
x_77 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_77, 0, x_76);
return x_77;
}
}
else
{
lean_object* x_78; lean_object* x_79; lean_object* x_80; lean_object* x_81; 
x_78 = lean_ctor_get(x_74, 0);
lean_inc(x_78);
lean_dec(x_74);
x_79 = l_checkLedgerVector___closed__9;
x_80 = lean_string_append(x_36, x_79);
x_81 = l_parseNatField(x_80, x_34);
lean_dec(x_34);
lean_dec(x_80);
if (lean_obj_tag(x_81) == 0)
{
uint8_t x_82; 
lean_dec(x_78);
lean_dec(x_71);
lean_dec(x_64);
lean_dec(x_57);
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_32);
lean_dec(x_26);
x_82 = !lean_is_exclusive(x_81);
if (x_82 == 0)
{
return x_81;
}
else
{
lean_object* x_83; lean_object* x_84; 
x_83 = lean_ctor_get(x_81, 0);
lean_inc(x_83);
lean_dec(x_81);
x_84 = lean_alloc_ctor(0, 1, 0);
lean_ctor_set(x_84, 0, x_83);
return x_84;
}
}
else
{
uint8_t x_85; 
x_85 = !lean_is_exclusive(x_81);
if (x_85 == 0)
{
lean_object* x_86; lean_object* x_87; lean_object* x_88; lean_object* x_89; uint8_t x_90; 
x_86 = lean_ctor_get(x_81, 0);
lean_inc(x_50);
lean_inc(x_43);
lean_inc(x_26);
x_87 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_87, 0, x_26);
lean_ctor_set(x_87, 1, x_43);
lean_ctor_set(x_87, 2, x_50);
x_88 = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(x_88, 0, x_26);
lean_ctor_set(x_88, 1, x_57);
lean_ctor_set(x_88, 2, x_64);
lean_ctor_set(x_88, 3, x_71);
x_89 = l_checkLedgerVector___closed__10;
x_90 = lean_string_dec_eq(x_32, x_89);
if (x_90 == 0)
{
lean_object* x_91; uint8_t x_92; 
x_91 = l_checkLedgerVector___closed__11;
x_92 = lean_string_dec_eq(x_32, x_91);
lean_dec(x_32);
if (x_92 == 0)
{
lean_object* x_93; 
lean_dec(x_88);
lean_dec(x_87);
lean_free_object(x_81);
lean_dec(x_86);
lean_dec(x_78);
lean_dec(x_50);
lean_dec(x_43);
x_93 = l_checkVector___closed__11;
return x_93;
}
else
{
lean_object* x_94; 
x_94 = l_applySettlement(x_87, x_88);
lean_dec(x_88);
if (lean_obj_tag(x_94) == 0)
{
uint8_t x_95; 
x_95 = lean_nat_dec_eq(x_78, x_43);
lean_dec(x_43);
lean_dec(x_78);
if (x_95 == 0)
{
lean_object* x_96; 
lean_free_object(x_81);
lean_dec(x_86);
lean_dec(x_50);
x_96 = l_checkVector___closed__11;
return x_96;
}
else
{
uint8_t x_97; lean_object* x_98; 
x_97 = lean_nat_dec_eq(x_86, x_50);
lean_dec(x_50);
lean_dec(x_86);
x_98 = lean_box(x_97);
lean_ctor_set(x_81, 0, x_98);
return x_81;
}
}
else
{
lean_object* x_99; 
lean_dec(x_94);
lean_free_object(x_81);
lean_dec(x_86);
lean_dec(x_78);
lean_dec(x_50);
lean_dec(x_43);
x_99 = l_checkVector___closed__11;
return x_99;
}
}
}
else
{
lean_object* x_100; 
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_32);
x_100 = l_applySettlement(x_87, x_88);
lean_dec(x_88);
if (lean_obj_tag(x_100) == 0)
{
lean_object* x_101; 
lean_free_object(x_81);
lean_dec(x_86);
lean_dec(x_78);
x_101 = l_checkVector___closed__11;
return x_101;
}
else
{
lean_object* x_102; lean_object* x_103; uint8_t x_104; 
x_102 = lean_ctor_get(x_100, 0);
lean_inc(x_102);
lean_dec(x_100);
x_103 = lean_ctor_get(x_102, 1);
lean_inc(x_103);
x_104 = lean_nat_dec_eq(x_103, x_78);
lean_dec(x_78);
lean_dec(x_103);
if (x_104 == 0)
{
lean_object* x_105; 
lean_dec(x_102);
lean_free_object(x_81);
lean_dec(x_86);
x_105 = l_checkVector___closed__11;
return x_105;
}
else
{
lean_object* x_106; uint8_t x_107; lean_object* x_108; 
x_106 = lean_ctor_get(x_102, 2);
lean_inc(x_106);
lean_dec(x_102);
x_107 = lean_nat_dec_eq(x_106, x_86);
lean_dec(x_86);
lean_dec(x_106);
x_108 = lean_box(x_107);
lean_ctor_set(x_81, 0, x_108);
return x_81;
}
}
}
}
else
{
lean_object* x_109; lean_object* x_110; lean_object* x_111; lean_object* x_112; uint8_t x_113; 
x_109 = lean_ctor_get(x_81, 0);
lean_inc(x_109);
lean_dec(x_81);
lean_inc(x_50);
lean_inc(x_43);
lean_inc(x_26);
x_110 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_110, 0, x_26);
lean_ctor_set(x_110, 1, x_43);
lean_ctor_set(x_110, 2, x_50);
x_111 = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(x_111, 0, x_26);
lean_ctor_set(x_111, 1, x_57);
lean_ctor_set(x_111, 2, x_64);
lean_ctor_set(x_111, 3, x_71);
x_112 = l_checkLedgerVector___closed__10;
x_113 = lean_string_dec_eq(x_32, x_112);
if (x_113 == 0)
{
lean_object* x_114; uint8_t x_115; 
x_114 = l_checkLedgerVector___closed__11;
x_115 = lean_string_dec_eq(x_32, x_114);
lean_dec(x_32);
if (x_115 == 0)
{
lean_object* x_116; 
lean_dec(x_111);
lean_dec(x_110);
lean_dec(x_109);
lean_dec(x_78);
lean_dec(x_50);
lean_dec(x_43);
x_116 = l_checkVector___closed__11;
return x_116;
}
else
{
lean_object* x_117; 
x_117 = l_applySettlement(x_110, x_111);
lean_dec(x_111);
if (lean_obj_tag(x_117) == 0)
{
uint8_t x_118; 
x_118 = lean_nat_dec_eq(x_78, x_43);
lean_dec(x_43);
lean_dec(x_78);
if (x_118 == 0)
{
lean_object* x_119; 
lean_dec(x_109);
lean_dec(x_50);
x_119 = l_checkVector___closed__11;
return x_119;
}
else
{
uint8_t x_120; lean_object* x_121; lean_object* x_122; 
x_120 = lean_nat_dec_eq(x_109, x_50);
lean_dec(x_50);
lean_dec(x_109);
x_121 = lean_box(x_120);
x_122 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_122, 0, x_121);
return x_122;
}
}
else
{
lean_object* x_123; 
lean_dec(x_117);
lean_dec(x_109);
lean_dec(x_78);
lean_dec(x_50);
lean_dec(x_43);
x_123 = l_checkVector___closed__11;
return x_123;
}
}
}
else
{
lean_object* x_124; 
lean_dec(x_50);
lean_dec(x_43);
lean_dec(x_32);
x_124 = l_applySettlement(x_110, x_111);
lean_dec(x_111);
if (lean_obj_tag(x_124) == 0)
{
lean_object* x_125; 
lean_dec(x_109);
lean_dec(x_78);
x_125 = l_checkVector___closed__11;
return x_125;
}
else
{
lean_object* x_126; lean_object* x_127; uint8_t x_128; 
x_126 = lean_ctor_get(x_124, 0);
lean_inc(x_126);
lean_dec(x_124);
x_127 = lean_ctor_get(x_126, 1);
lean_inc(x_127);
x_128 = lean_nat_dec_eq(x_127, x_78);
lean_dec(x_78);
lean_dec(x_127);
if (x_128 == 0)
{
lean_object* x_129; 
lean_dec(x_126);
lean_dec(x_109);
x_129 = l_checkVector___closed__11;
return x_129;
}
else
{
lean_object* x_130; uint8_t x_131; lean_object* x_132; lean_object* x_133; 
x_130 = lean_ctor_get(x_126, 2);
lean_inc(x_130);
lean_dec(x_126);
x_131 = lean_nat_dec_eq(x_130, x_109);
lean_dec(x_109);
lean_dec(x_130);
x_132 = lean_box(x_131);
x_133 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_133, 0, x_132);
return x_133;
}
}
}
}
}
}
}
}
}
}
}
}
else
{
lean_object* x_134; 
lean_dec(x_24);
lean_dec(x_22);
lean_dec(x_20);
lean_dec(x_18);
lean_dec(x_16);
lean_dec(x_14);
lean_dec(x_12);
lean_dec(x_10);
lean_dec(x_8);
lean_dec(x_6);
lean_dec(x_4);
x_134 = l_checkLedgerVector___closed__2;
return x_134;
}
}
}
}
}
}
}
}
}
}
}
}
}
LEAN_EXPORT lean_object* l_checkLedgerVector___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_checkLedgerVector(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_List_filterTR_loop___at_main___spec__1(lean_object* x_1, lean_object* x_2) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_3; 
x_3 = l_List_reverse___rarg(x_2);
return x_3;
}
else
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; uint8_t x_8; 
x_5 = lean_ctor_get(x_1, 0);
x_6 = lean_ctor_get(x_1, 1);
x_7 = l_parseNatField___closed__1;
x_8 = lean_string_dec_eq(x_5, x_7);
if (x_8 == 0)
{
lean_ctor_set(x_1, 1, x_2);
{
lean_object* _tmp_0 = x_6;
lean_object* _tmp_1 = x_1;
x_1 = _tmp_0;
x_2 = _tmp_1;
}
goto _start;
}
else
{
lean_free_object(x_1);
lean_dec(x_5);
x_1 = x_6;
goto _start;
}
}
else
{
lean_object* x_11; lean_object* x_12; lean_object* x_13; uint8_t x_14; 
x_11 = lean_ctor_get(x_1, 0);
x_12 = lean_ctor_get(x_1, 1);
lean_inc(x_12);
lean_inc(x_11);
lean_dec(x_1);
x_13 = l_parseNatField___closed__1;
x_14 = lean_string_dec_eq(x_11, x_13);
if (x_14 == 0)
{
lean_object* x_15; 
x_15 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_15, 0, x_11);
lean_ctor_set(x_15, 1, x_2);
x_1 = x_12;
x_2 = x_15;
goto _start;
}
else
{
lean_dec(x_11);
x_1 = x_12;
goto _start;
}
}
}
}
}
static lean_object* _init_l_List_forIn_loop___at_main___spec__2___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("invalid settlement vector (", 27, 27);
return x_1;
}
}
static lean_object* _init_l_List_forIn_loop___at_main___spec__2___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("): ", 3, 3);
return x_1;
}
}
static lean_object* _init_l_List_forIn_loop___at_main___spec__2___closed__3() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("settlement vector failed: ", 26, 26);
return x_1;
}
}
LEAN_EXPORT lean_object* l_List_forIn_loop___at_main___spec__2(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_4; 
x_4 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_4, 0, x_2);
lean_ctor_set(x_4, 1, x_3);
return x_4;
}
else
{
uint8_t x_5; 
lean_dec(x_2);
x_5 = !lean_is_exclusive(x_1);
if (x_5 == 0)
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; 
x_6 = lean_ctor_get(x_1, 0);
x_7 = lean_ctor_get(x_1, 1);
x_8 = l_checkVector(x_6);
if (lean_obj_tag(x_8) == 0)
{
uint8_t x_9; 
lean_dec(x_7);
x_9 = !lean_is_exclusive(x_8);
if (x_9 == 0)
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; 
x_10 = lean_ctor_get(x_8, 0);
x_11 = l_List_forIn_loop___at_main___spec__2___closed__1;
x_12 = lean_string_append(x_11, x_10);
lean_dec(x_10);
x_13 = l_List_forIn_loop___at_main___spec__2___closed__2;
x_14 = lean_string_append(x_12, x_13);
x_15 = lean_string_append(x_14, x_6);
lean_dec(x_6);
x_16 = l_parseNatField___closed__1;
x_17 = lean_string_append(x_15, x_16);
lean_ctor_set_tag(x_8, 18);
lean_ctor_set(x_8, 0, x_17);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_8);
return x_1;
}
else
{
lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; 
x_18 = lean_ctor_get(x_8, 0);
lean_inc(x_18);
lean_dec(x_8);
x_19 = l_List_forIn_loop___at_main___spec__2___closed__1;
x_20 = lean_string_append(x_19, x_18);
lean_dec(x_18);
x_21 = l_List_forIn_loop___at_main___spec__2___closed__2;
x_22 = lean_string_append(x_20, x_21);
x_23 = lean_string_append(x_22, x_6);
lean_dec(x_6);
x_24 = l_parseNatField___closed__1;
x_25 = lean_string_append(x_23, x_24);
x_26 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_26, 0, x_25);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_26);
return x_1;
}
}
else
{
uint8_t x_27; 
x_27 = !lean_is_exclusive(x_8);
if (x_27 == 0)
{
lean_object* x_28; uint8_t x_29; 
x_28 = lean_ctor_get(x_8, 0);
x_29 = lean_unbox(x_28);
lean_dec(x_28);
if (x_29 == 0)
{
lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; 
lean_dec(x_7);
x_30 = l_List_forIn_loop___at_main___spec__2___closed__3;
x_31 = lean_string_append(x_30, x_6);
lean_dec(x_6);
x_32 = l_parseNatField___closed__1;
x_33 = lean_string_append(x_31, x_32);
lean_ctor_set_tag(x_8, 18);
lean_ctor_set(x_8, 0, x_33);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_8);
return x_1;
}
else
{
lean_object* x_34; 
lean_free_object(x_8);
lean_free_object(x_1);
lean_dec(x_6);
x_34 = lean_box(0);
x_1 = x_7;
x_2 = x_34;
goto _start;
}
}
else
{
lean_object* x_36; uint8_t x_37; 
x_36 = lean_ctor_get(x_8, 0);
lean_inc(x_36);
lean_dec(x_8);
x_37 = lean_unbox(x_36);
lean_dec(x_36);
if (x_37 == 0)
{
lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; 
lean_dec(x_7);
x_38 = l_List_forIn_loop___at_main___spec__2___closed__3;
x_39 = lean_string_append(x_38, x_6);
lean_dec(x_6);
x_40 = l_parseNatField___closed__1;
x_41 = lean_string_append(x_39, x_40);
x_42 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_42, 0, x_41);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_42);
return x_1;
}
else
{
lean_object* x_43; 
lean_free_object(x_1);
lean_dec(x_6);
x_43 = lean_box(0);
x_1 = x_7;
x_2 = x_43;
goto _start;
}
}
}
}
else
{
lean_object* x_45; lean_object* x_46; lean_object* x_47; 
x_45 = lean_ctor_get(x_1, 0);
x_46 = lean_ctor_get(x_1, 1);
lean_inc(x_46);
lean_inc(x_45);
lean_dec(x_1);
x_47 = l_checkVector(x_45);
if (lean_obj_tag(x_47) == 0)
{
lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; lean_object* x_58; 
lean_dec(x_46);
x_48 = lean_ctor_get(x_47, 0);
lean_inc(x_48);
if (lean_is_exclusive(x_47)) {
 lean_ctor_release(x_47, 0);
 x_49 = x_47;
} else {
 lean_dec_ref(x_47);
 x_49 = lean_box(0);
}
x_50 = l_List_forIn_loop___at_main___spec__2___closed__1;
x_51 = lean_string_append(x_50, x_48);
lean_dec(x_48);
x_52 = l_List_forIn_loop___at_main___spec__2___closed__2;
x_53 = lean_string_append(x_51, x_52);
x_54 = lean_string_append(x_53, x_45);
lean_dec(x_45);
x_55 = l_parseNatField___closed__1;
x_56 = lean_string_append(x_54, x_55);
if (lean_is_scalar(x_49)) {
 x_57 = lean_alloc_ctor(18, 1, 0);
} else {
 x_57 = x_49;
 lean_ctor_set_tag(x_57, 18);
}
lean_ctor_set(x_57, 0, x_56);
x_58 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_58, 0, x_57);
lean_ctor_set(x_58, 1, x_3);
return x_58;
}
else
{
lean_object* x_59; lean_object* x_60; uint8_t x_61; 
x_59 = lean_ctor_get(x_47, 0);
lean_inc(x_59);
if (lean_is_exclusive(x_47)) {
 lean_ctor_release(x_47, 0);
 x_60 = x_47;
} else {
 lean_dec_ref(x_47);
 x_60 = lean_box(0);
}
x_61 = lean_unbox(x_59);
lean_dec(x_59);
if (x_61 == 0)
{
lean_object* x_62; lean_object* x_63; lean_object* x_64; lean_object* x_65; lean_object* x_66; lean_object* x_67; 
lean_dec(x_46);
x_62 = l_List_forIn_loop___at_main___spec__2___closed__3;
x_63 = lean_string_append(x_62, x_45);
lean_dec(x_45);
x_64 = l_parseNatField___closed__1;
x_65 = lean_string_append(x_63, x_64);
if (lean_is_scalar(x_60)) {
 x_66 = lean_alloc_ctor(18, 1, 0);
} else {
 x_66 = x_60;
 lean_ctor_set_tag(x_66, 18);
}
lean_ctor_set(x_66, 0, x_65);
x_67 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_67, 0, x_66);
lean_ctor_set(x_67, 1, x_3);
return x_67;
}
else
{
lean_object* x_68; 
lean_dec(x_60);
lean_dec(x_45);
x_68 = lean_box(0);
x_1 = x_46;
x_2 = x_68;
goto _start;
}
}
}
}
}
}
static lean_object* _init_l_List_forIn_loop___at_main___spec__3___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("invalid ledger vector (", 23, 23);
return x_1;
}
}
static lean_object* _init_l_List_forIn_loop___at_main___spec__3___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("optimistic escrow vector failed: ", 33, 33);
return x_1;
}
}
LEAN_EXPORT lean_object* l_List_forIn_loop___at_main___spec__3(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_4; 
x_4 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_4, 0, x_2);
lean_ctor_set(x_4, 1, x_3);
return x_4;
}
else
{
uint8_t x_5; 
lean_dec(x_2);
x_5 = !lean_is_exclusive(x_1);
if (x_5 == 0)
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; 
x_6 = lean_ctor_get(x_1, 0);
x_7 = lean_ctor_get(x_1, 1);
x_8 = l_checkLedgerVector(x_6);
if (lean_obj_tag(x_8) == 0)
{
uint8_t x_9; 
lean_dec(x_7);
x_9 = !lean_is_exclusive(x_8);
if (x_9 == 0)
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; 
x_10 = lean_ctor_get(x_8, 0);
x_11 = l_List_forIn_loop___at_main___spec__3___closed__1;
x_12 = lean_string_append(x_11, x_10);
lean_dec(x_10);
x_13 = l_List_forIn_loop___at_main___spec__2___closed__2;
x_14 = lean_string_append(x_12, x_13);
x_15 = lean_string_append(x_14, x_6);
lean_dec(x_6);
x_16 = l_parseNatField___closed__1;
x_17 = lean_string_append(x_15, x_16);
lean_ctor_set_tag(x_8, 18);
lean_ctor_set(x_8, 0, x_17);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_8);
return x_1;
}
else
{
lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; 
x_18 = lean_ctor_get(x_8, 0);
lean_inc(x_18);
lean_dec(x_8);
x_19 = l_List_forIn_loop___at_main___spec__3___closed__1;
x_20 = lean_string_append(x_19, x_18);
lean_dec(x_18);
x_21 = l_List_forIn_loop___at_main___spec__2___closed__2;
x_22 = lean_string_append(x_20, x_21);
x_23 = lean_string_append(x_22, x_6);
lean_dec(x_6);
x_24 = l_parseNatField___closed__1;
x_25 = lean_string_append(x_23, x_24);
x_26 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_26, 0, x_25);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_26);
return x_1;
}
}
else
{
uint8_t x_27; 
x_27 = !lean_is_exclusive(x_8);
if (x_27 == 0)
{
lean_object* x_28; uint8_t x_29; 
x_28 = lean_ctor_get(x_8, 0);
x_29 = lean_unbox(x_28);
lean_dec(x_28);
if (x_29 == 0)
{
lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; 
lean_dec(x_7);
x_30 = l_List_forIn_loop___at_main___spec__3___closed__2;
x_31 = lean_string_append(x_30, x_6);
lean_dec(x_6);
x_32 = l_parseNatField___closed__1;
x_33 = lean_string_append(x_31, x_32);
lean_ctor_set_tag(x_8, 18);
lean_ctor_set(x_8, 0, x_33);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_8);
return x_1;
}
else
{
lean_object* x_34; 
lean_free_object(x_8);
lean_free_object(x_1);
lean_dec(x_6);
x_34 = lean_box(0);
x_1 = x_7;
x_2 = x_34;
goto _start;
}
}
else
{
lean_object* x_36; uint8_t x_37; 
x_36 = lean_ctor_get(x_8, 0);
lean_inc(x_36);
lean_dec(x_8);
x_37 = lean_unbox(x_36);
lean_dec(x_36);
if (x_37 == 0)
{
lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; 
lean_dec(x_7);
x_38 = l_List_forIn_loop___at_main___spec__3___closed__2;
x_39 = lean_string_append(x_38, x_6);
lean_dec(x_6);
x_40 = l_parseNatField___closed__1;
x_41 = lean_string_append(x_39, x_40);
x_42 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_42, 0, x_41);
lean_ctor_set(x_1, 1, x_3);
lean_ctor_set(x_1, 0, x_42);
return x_1;
}
else
{
lean_object* x_43; 
lean_free_object(x_1);
lean_dec(x_6);
x_43 = lean_box(0);
x_1 = x_7;
x_2 = x_43;
goto _start;
}
}
}
}
else
{
lean_object* x_45; lean_object* x_46; lean_object* x_47; 
x_45 = lean_ctor_get(x_1, 0);
x_46 = lean_ctor_get(x_1, 1);
lean_inc(x_46);
lean_inc(x_45);
lean_dec(x_1);
x_47 = l_checkLedgerVector(x_45);
if (lean_obj_tag(x_47) == 0)
{
lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; lean_object* x_58; 
lean_dec(x_46);
x_48 = lean_ctor_get(x_47, 0);
lean_inc(x_48);
if (lean_is_exclusive(x_47)) {
 lean_ctor_release(x_47, 0);
 x_49 = x_47;
} else {
 lean_dec_ref(x_47);
 x_49 = lean_box(0);
}
x_50 = l_List_forIn_loop___at_main___spec__3___closed__1;
x_51 = lean_string_append(x_50, x_48);
lean_dec(x_48);
x_52 = l_List_forIn_loop___at_main___spec__2___closed__2;
x_53 = lean_string_append(x_51, x_52);
x_54 = lean_string_append(x_53, x_45);
lean_dec(x_45);
x_55 = l_parseNatField___closed__1;
x_56 = lean_string_append(x_54, x_55);
if (lean_is_scalar(x_49)) {
 x_57 = lean_alloc_ctor(18, 1, 0);
} else {
 x_57 = x_49;
 lean_ctor_set_tag(x_57, 18);
}
lean_ctor_set(x_57, 0, x_56);
x_58 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_58, 0, x_57);
lean_ctor_set(x_58, 1, x_3);
return x_58;
}
else
{
lean_object* x_59; lean_object* x_60; uint8_t x_61; 
x_59 = lean_ctor_get(x_47, 0);
lean_inc(x_59);
if (lean_is_exclusive(x_47)) {
 lean_ctor_release(x_47, 0);
 x_60 = x_47;
} else {
 lean_dec_ref(x_47);
 x_60 = lean_box(0);
}
x_61 = lean_unbox(x_59);
lean_dec(x_59);
if (x_61 == 0)
{
lean_object* x_62; lean_object* x_63; lean_object* x_64; lean_object* x_65; lean_object* x_66; lean_object* x_67; 
lean_dec(x_46);
x_62 = l_List_forIn_loop___at_main___spec__3___closed__2;
x_63 = lean_string_append(x_62, x_45);
lean_dec(x_45);
x_64 = l_parseNatField___closed__1;
x_65 = lean_string_append(x_63, x_64);
if (lean_is_scalar(x_60)) {
 x_66 = lean_alloc_ctor(18, 1, 0);
} else {
 x_66 = x_60;
 lean_ctor_set_tag(x_66, 18);
}
lean_ctor_set(x_66, 0, x_65);
x_67 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_67, 0, x_66);
lean_ctor_set(x_67, 1, x_3);
return x_67;
}
else
{
lean_object* x_68; 
lean_dec(x_60);
lean_dec(x_45);
x_68 = lean_box(0);
x_1 = x_46;
x_2 = x_68;
goto _start;
}
}
}
}
}
}
static lean_object* _init_l_main___lambda__1___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" settlement and ", 16, 16);
return x_1;
}
}
static lean_object* _init_l_main___lambda__1___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" optimistic escrow vectors passed", 33, 33);
return x_1;
}
}
LEAN_EXPORT lean_object* l_main___lambda__1(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; lean_object* x_6; 
x_5 = lean_box(0);
lean_inc(x_1);
x_6 = l_List_forIn_loop___at_main___spec__3(x_1, x_5, x_4);
if (lean_obj_tag(x_6) == 0)
{
lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; 
x_7 = lean_ctor_get(x_6, 1);
lean_inc(x_7);
lean_dec(x_6);
x_8 = lean_unsigned_to_nat(0u);
x_9 = l_List_lengthTRAux___rarg(x_2, x_8);
x_10 = l___private_Init_Data_Repr_0__Nat_reprFast(x_9);
x_11 = l_parseNatField___closed__1;
x_12 = lean_string_append(x_11, x_10);
lean_dec(x_10);
x_13 = l_main___lambda__1___closed__1;
x_14 = lean_string_append(x_12, x_13);
x_15 = l_List_lengthTRAux___rarg(x_1, x_8);
lean_dec(x_1);
x_16 = l___private_Init_Data_Repr_0__Nat_reprFast(x_15);
x_17 = lean_string_append(x_14, x_16);
lean_dec(x_16);
x_18 = l_main___lambda__1___closed__2;
x_19 = lean_string_append(x_17, x_18);
x_20 = l_IO_println___at_Lean_instEval___spec__1(x_19, x_7);
return x_20;
}
else
{
uint8_t x_21; 
lean_dec(x_1);
x_21 = !lean_is_exclusive(x_6);
if (x_21 == 0)
{
return x_6;
}
else
{
lean_object* x_22; lean_object* x_23; lean_object* x_24; 
x_22 = lean_ctor_get(x_6, 0);
x_23 = lean_ctor_get(x_6, 1);
lean_inc(x_23);
lean_inc(x_22);
lean_dec(x_6);
x_24 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_24, 0, x_22);
lean_ctor_set(x_24, 1, x_23);
return x_24;
}
}
}
}
static lean_object* _init_l_main___lambda__2___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("\n", 1, 1);
return x_1;
}
}
static lean_object* _init_l_main___lambda__2___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("no optimistic escrow vectors were supplied", 42, 42);
return x_1;
}
}
static lean_object* _init_l_main___lambda__2___closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l_main___lambda__2___closed__2;
x_2 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_main___lambda__2(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5) {
_start:
{
lean_object* x_6; lean_object* x_7; 
x_6 = lean_box(0);
lean_inc(x_1);
x_7 = l_List_forIn_loop___at_main___spec__2(x_1, x_6, x_5);
if (lean_obj_tag(x_7) == 0)
{
lean_object* x_8; lean_object* x_9; lean_object* x_10; 
x_8 = lean_ctor_get(x_7, 1);
lean_inc(x_8);
lean_dec(x_7);
x_9 = lean_ctor_get(x_2, 1);
x_10 = l_IO_FS_readFile(x_9, x_8);
if (lean_obj_tag(x_10) == 0)
{
uint8_t x_11; 
x_11 = !lean_is_exclusive(x_10);
if (x_11 == 0)
{
lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; uint8_t x_19; 
x_12 = lean_ctor_get(x_10, 0);
x_13 = lean_ctor_get(x_10, 1);
x_14 = l_main___lambda__2___closed__1;
x_15 = l_String_splitOn(x_12, x_14);
x_16 = lean_unsigned_to_nat(1u);
x_17 = l_List_drop___rarg(x_16, x_15);
lean_dec(x_15);
x_18 = l_List_filterTR_loop___at_main___spec__1(x_17, x_3);
x_19 = l_List_isEmpty___rarg(x_18);
if (x_19 == 0)
{
lean_object* x_20; 
lean_free_object(x_10);
x_20 = l_main___lambda__1(x_18, x_1, x_6, x_13);
lean_dec(x_1);
return x_20;
}
else
{
lean_object* x_21; 
lean_dec(x_18);
lean_dec(x_1);
x_21 = l_main___lambda__2___closed__3;
lean_ctor_set_tag(x_10, 1);
lean_ctor_set(x_10, 0, x_21);
return x_10;
}
}
else
{
lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; uint8_t x_29; 
x_22 = lean_ctor_get(x_10, 0);
x_23 = lean_ctor_get(x_10, 1);
lean_inc(x_23);
lean_inc(x_22);
lean_dec(x_10);
x_24 = l_main___lambda__2___closed__1;
x_25 = l_String_splitOn(x_22, x_24);
x_26 = lean_unsigned_to_nat(1u);
x_27 = l_List_drop___rarg(x_26, x_25);
lean_dec(x_25);
x_28 = l_List_filterTR_loop___at_main___spec__1(x_27, x_3);
x_29 = l_List_isEmpty___rarg(x_28);
if (x_29 == 0)
{
lean_object* x_30; 
x_30 = l_main___lambda__1(x_28, x_1, x_6, x_23);
lean_dec(x_1);
return x_30;
}
else
{
lean_object* x_31; lean_object* x_32; 
lean_dec(x_28);
lean_dec(x_1);
x_31 = l_main___lambda__2___closed__3;
x_32 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_32, 0, x_31);
lean_ctor_set(x_32, 1, x_23);
return x_32;
}
}
}
else
{
uint8_t x_33; 
lean_dec(x_3);
lean_dec(x_1);
x_33 = !lean_is_exclusive(x_10);
if (x_33 == 0)
{
return x_10;
}
else
{
lean_object* x_34; lean_object* x_35; lean_object* x_36; 
x_34 = lean_ctor_get(x_10, 0);
x_35 = lean_ctor_get(x_10, 1);
lean_inc(x_35);
lean_inc(x_34);
lean_dec(x_10);
x_36 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_36, 0, x_34);
lean_ctor_set(x_36, 1, x_35);
return x_36;
}
}
}
else
{
uint8_t x_37; 
lean_dec(x_3);
lean_dec(x_1);
x_37 = !lean_is_exclusive(x_7);
if (x_37 == 0)
{
return x_7;
}
else
{
lean_object* x_38; lean_object* x_39; lean_object* x_40; 
x_38 = lean_ctor_get(x_7, 0);
x_39 = lean_ctor_get(x_7, 1);
lean_inc(x_39);
lean_inc(x_38);
lean_dec(x_7);
x_40 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_40, 0, x_38);
lean_ctor_set(x_40, 1, x_39);
return x_40;
}
}
}
}
static lean_object* _init_l_main___lambda__3___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("expected 14 arithmetic vectors, found ", 38, 38);
return x_1;
}
}
LEAN_EXPORT lean_object* l_main___lambda__3(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; 
x_3 = lean_ctor_get(x_1, 0);
x_4 = l_IO_FS_readFile(x_3, x_2);
if (lean_obj_tag(x_4) == 0)
{
uint8_t x_5; 
x_5 = !lean_is_exclusive(x_4);
if (x_5 == 0)
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; uint8_t x_17; 
x_6 = lean_ctor_get(x_4, 0);
x_7 = lean_ctor_get(x_4, 1);
x_8 = l_main___lambda__2___closed__1;
x_9 = l_String_splitOn(x_6, x_8);
x_10 = lean_unsigned_to_nat(1u);
x_11 = l_List_drop___rarg(x_10, x_9);
lean_dec(x_9);
x_12 = lean_box(0);
x_13 = l_List_filterTR_loop___at_main___spec__1(x_11, x_12);
x_14 = lean_unsigned_to_nat(0u);
x_15 = l_List_lengthTRAux___rarg(x_13, x_14);
x_16 = lean_unsigned_to_nat(14u);
x_17 = lean_nat_dec_eq(x_15, x_16);
if (x_17 == 0)
{
lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; 
lean_dec(x_13);
x_18 = l___private_Init_Data_Repr_0__Nat_reprFast(x_15);
x_19 = l_main___lambda__3___closed__1;
x_20 = lean_string_append(x_19, x_18);
lean_dec(x_18);
x_21 = l_parseNatField___closed__1;
x_22 = lean_string_append(x_20, x_21);
x_23 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_23, 0, x_22);
lean_ctor_set_tag(x_4, 1);
lean_ctor_set(x_4, 0, x_23);
return x_4;
}
else
{
lean_object* x_24; lean_object* x_25; 
lean_dec(x_15);
lean_free_object(x_4);
x_24 = lean_box(0);
x_25 = l_main___lambda__2(x_13, x_1, x_12, x_24, x_7);
return x_25;
}
}
else
{
lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; uint8_t x_37; 
x_26 = lean_ctor_get(x_4, 0);
x_27 = lean_ctor_get(x_4, 1);
lean_inc(x_27);
lean_inc(x_26);
lean_dec(x_4);
x_28 = l_main___lambda__2___closed__1;
x_29 = l_String_splitOn(x_26, x_28);
x_30 = lean_unsigned_to_nat(1u);
x_31 = l_List_drop___rarg(x_30, x_29);
lean_dec(x_29);
x_32 = lean_box(0);
x_33 = l_List_filterTR_loop___at_main___spec__1(x_31, x_32);
x_34 = lean_unsigned_to_nat(0u);
x_35 = l_List_lengthTRAux___rarg(x_33, x_34);
x_36 = lean_unsigned_to_nat(14u);
x_37 = lean_nat_dec_eq(x_35, x_36);
if (x_37 == 0)
{
lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; 
lean_dec(x_33);
x_38 = l___private_Init_Data_Repr_0__Nat_reprFast(x_35);
x_39 = l_main___lambda__3___closed__1;
x_40 = lean_string_append(x_39, x_38);
lean_dec(x_38);
x_41 = l_parseNatField___closed__1;
x_42 = lean_string_append(x_40, x_41);
x_43 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_43, 0, x_42);
x_44 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_44, 0, x_43);
lean_ctor_set(x_44, 1, x_27);
return x_44;
}
else
{
lean_object* x_45; lean_object* x_46; 
lean_dec(x_35);
x_45 = lean_box(0);
x_46 = l_main___lambda__2(x_33, x_1, x_32, x_45, x_27);
return x_46;
}
}
}
else
{
uint8_t x_47; 
x_47 = !lean_is_exclusive(x_4);
if (x_47 == 0)
{
return x_4;
}
else
{
lean_object* x_48; lean_object* x_49; lean_object* x_50; 
x_48 = lean_ctor_get(x_4, 0);
x_49 = lean_ctor_get(x_4, 1);
lean_inc(x_49);
lean_inc(x_48);
lean_dec(x_4);
x_50 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_50, 0, x_48);
lean_ctor_set(x_50, 1, x_49);
return x_50;
}
}
}
}
static lean_object* _init_l_main___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("usage: lake exe tas_vectors <settlement.csv> <ledger.csv>", 57, 57);
return x_1;
}
}
static lean_object* _init_l_main___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l_main___closed__1;
x_2 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l_main___closed__3() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_main___lambda__3___boxed), 2, 0);
return x_1;
}
}
LEAN_EXPORT lean_object* _lean_main(lean_object* x_1, lean_object* x_2) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_3; lean_object* x_4; 
x_3 = l_main___closed__2;
x_4 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_4, 0, x_3);
lean_ctor_set(x_4, 1, x_2);
return x_4;
}
else
{
lean_object* x_5; 
x_5 = lean_ctor_get(x_1, 1);
lean_inc(x_5);
if (lean_obj_tag(x_5) == 0)
{
uint8_t x_6; 
x_6 = !lean_is_exclusive(x_1);
if (x_6 == 0)
{
lean_object* x_7; lean_object* x_8; lean_object* x_9; 
x_7 = lean_ctor_get(x_1, 1);
lean_dec(x_7);
x_8 = lean_ctor_get(x_1, 0);
lean_dec(x_8);
x_9 = l_main___closed__2;
lean_ctor_set(x_1, 1, x_2);
lean_ctor_set(x_1, 0, x_9);
return x_1;
}
else
{
lean_object* x_10; lean_object* x_11; 
lean_dec(x_1);
x_10 = l_main___closed__2;
x_11 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_11, 0, x_10);
lean_ctor_set(x_11, 1, x_2);
return x_11;
}
}
else
{
lean_object* x_12; 
x_12 = lean_ctor_get(x_5, 1);
lean_inc(x_12);
if (lean_obj_tag(x_12) == 0)
{
lean_object* x_13; uint8_t x_14; 
x_13 = lean_ctor_get(x_1, 0);
lean_inc(x_13);
lean_dec(x_1);
x_14 = !lean_is_exclusive(x_5);
if (x_14 == 0)
{
lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; 
x_15 = lean_ctor_get(x_5, 0);
x_16 = lean_ctor_get(x_5, 1);
lean_dec(x_16);
x_17 = l_main___closed__3;
lean_ctor_set_tag(x_5, 0);
lean_ctor_set(x_5, 1, x_15);
lean_ctor_set(x_5, 0, x_13);
x_18 = lean_apply_2(x_17, x_5, x_2);
return x_18;
}
else
{
lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; 
x_19 = lean_ctor_get(x_5, 0);
lean_inc(x_19);
lean_dec(x_5);
x_20 = l_main___closed__3;
x_21 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_21, 0, x_13);
lean_ctor_set(x_21, 1, x_19);
x_22 = lean_apply_2(x_20, x_21, x_2);
return x_22;
}
}
else
{
uint8_t x_23; 
lean_dec(x_5);
lean_dec(x_1);
x_23 = !lean_is_exclusive(x_12);
if (x_23 == 0)
{
lean_object* x_24; lean_object* x_25; lean_object* x_26; 
x_24 = lean_ctor_get(x_12, 1);
lean_dec(x_24);
x_25 = lean_ctor_get(x_12, 0);
lean_dec(x_25);
x_26 = l_main___closed__2;
lean_ctor_set(x_12, 1, x_2);
lean_ctor_set(x_12, 0, x_26);
return x_12;
}
else
{
lean_object* x_27; lean_object* x_28; 
lean_dec(x_12);
x_27 = l_main___closed__2;
x_28 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_28, 0, x_27);
lean_ctor_set(x_28, 1, x_2);
return x_28;
}
}
}
}
}
}
LEAN_EXPORT lean_object* l_main___lambda__1___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_main___lambda__1(x_1, x_2, x_3, x_4);
lean_dec(x_3);
lean_dec(x_2);
return x_5;
}
}
LEAN_EXPORT lean_object* l_main___lambda__2___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5) {
_start:
{
lean_object* x_6; 
x_6 = l_main___lambda__2(x_1, x_2, x_3, x_4, x_5);
lean_dec(x_4);
lean_dec(x_2);
return x_6;
}
}
LEAN_EXPORT lean_object* l_main___lambda__3___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_main___lambda__3(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Lean(uint8_t builtin, lean_object*);
lean_object* initialize_Reaction(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_Main(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Lean(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Reaction(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_uint64Max___closed__1 = _init_l_uint64Max___closed__1();
lean_mark_persistent(l_uint64Max___closed__1);
l_uint64Max = _init_l_uint64Max();
lean_mark_persistent(l_uint64Max);
l_parseNatField___closed__1 = _init_l_parseNatField___closed__1();
lean_mark_persistent(l_parseNatField___closed__1);
l_parseNatField___closed__2 = _init_l_parseNatField___closed__2();
lean_mark_persistent(l_parseNatField___closed__2);
l_checkVector___closed__1 = _init_l_checkVector___closed__1();
lean_mark_persistent(l_checkVector___closed__1);
l_checkVector___closed__2 = _init_l_checkVector___closed__2();
lean_mark_persistent(l_checkVector___closed__2);
l_checkVector___closed__3 = _init_l_checkVector___closed__3();
lean_mark_persistent(l_checkVector___closed__3);
l_checkVector___closed__4 = _init_l_checkVector___closed__4();
lean_mark_persistent(l_checkVector___closed__4);
l_checkVector___closed__5 = _init_l_checkVector___closed__5();
lean_mark_persistent(l_checkVector___closed__5);
l_checkVector___closed__6 = _init_l_checkVector___closed__6();
lean_mark_persistent(l_checkVector___closed__6);
l_checkVector___closed__7 = _init_l_checkVector___closed__7();
lean_mark_persistent(l_checkVector___closed__7);
l_checkVector___closed__8 = _init_l_checkVector___closed__8();
lean_mark_persistent(l_checkVector___closed__8);
l_checkVector___closed__9 = _init_l_checkVector___closed__9();
lean_mark_persistent(l_checkVector___closed__9);
l_checkVector___closed__10 = _init_l_checkVector___closed__10();
lean_mark_persistent(l_checkVector___closed__10);
l_checkVector___closed__11 = _init_l_checkVector___closed__11();
lean_mark_persistent(l_checkVector___closed__11);
l_checkLedgerVector___closed__1 = _init_l_checkLedgerVector___closed__1();
lean_mark_persistent(l_checkLedgerVector___closed__1);
l_checkLedgerVector___closed__2 = _init_l_checkLedgerVector___closed__2();
lean_mark_persistent(l_checkLedgerVector___closed__2);
l_checkLedgerVector___closed__3 = _init_l_checkLedgerVector___closed__3();
lean_mark_persistent(l_checkLedgerVector___closed__3);
l_checkLedgerVector___closed__4 = _init_l_checkLedgerVector___closed__4();
lean_mark_persistent(l_checkLedgerVector___closed__4);
l_checkLedgerVector___closed__5 = _init_l_checkLedgerVector___closed__5();
lean_mark_persistent(l_checkLedgerVector___closed__5);
l_checkLedgerVector___closed__6 = _init_l_checkLedgerVector___closed__6();
lean_mark_persistent(l_checkLedgerVector___closed__6);
l_checkLedgerVector___closed__7 = _init_l_checkLedgerVector___closed__7();
lean_mark_persistent(l_checkLedgerVector___closed__7);
l_checkLedgerVector___closed__8 = _init_l_checkLedgerVector___closed__8();
lean_mark_persistent(l_checkLedgerVector___closed__8);
l_checkLedgerVector___closed__9 = _init_l_checkLedgerVector___closed__9();
lean_mark_persistent(l_checkLedgerVector___closed__9);
l_checkLedgerVector___closed__10 = _init_l_checkLedgerVector___closed__10();
lean_mark_persistent(l_checkLedgerVector___closed__10);
l_checkLedgerVector___closed__11 = _init_l_checkLedgerVector___closed__11();
lean_mark_persistent(l_checkLedgerVector___closed__11);
l_List_forIn_loop___at_main___spec__2___closed__1 = _init_l_List_forIn_loop___at_main___spec__2___closed__1();
lean_mark_persistent(l_List_forIn_loop___at_main___spec__2___closed__1);
l_List_forIn_loop___at_main___spec__2___closed__2 = _init_l_List_forIn_loop___at_main___spec__2___closed__2();
lean_mark_persistent(l_List_forIn_loop___at_main___spec__2___closed__2);
l_List_forIn_loop___at_main___spec__2___closed__3 = _init_l_List_forIn_loop___at_main___spec__2___closed__3();
lean_mark_persistent(l_List_forIn_loop___at_main___spec__2___closed__3);
l_List_forIn_loop___at_main___spec__3___closed__1 = _init_l_List_forIn_loop___at_main___spec__3___closed__1();
lean_mark_persistent(l_List_forIn_loop___at_main___spec__3___closed__1);
l_List_forIn_loop___at_main___spec__3___closed__2 = _init_l_List_forIn_loop___at_main___spec__3___closed__2();
lean_mark_persistent(l_List_forIn_loop___at_main___spec__3___closed__2);
l_main___lambda__1___closed__1 = _init_l_main___lambda__1___closed__1();
lean_mark_persistent(l_main___lambda__1___closed__1);
l_main___lambda__1___closed__2 = _init_l_main___lambda__1___closed__2();
lean_mark_persistent(l_main___lambda__1___closed__2);
l_main___lambda__2___closed__1 = _init_l_main___lambda__2___closed__1();
lean_mark_persistent(l_main___lambda__2___closed__1);
l_main___lambda__2___closed__2 = _init_l_main___lambda__2___closed__2();
lean_mark_persistent(l_main___lambda__2___closed__2);
l_main___lambda__2___closed__3 = _init_l_main___lambda__2___closed__3();
lean_mark_persistent(l_main___lambda__2___closed__3);
l_main___lambda__3___closed__1 = _init_l_main___lambda__3___closed__1();
lean_mark_persistent(l_main___lambda__3___closed__1);
l_main___closed__1 = _init_l_main___closed__1();
lean_mark_persistent(l_main___closed__1);
l_main___closed__2 = _init_l_main___closed__2();
lean_mark_persistent(l_main___closed__2);
l_main___closed__3 = _init_l_main___closed__3();
lean_mark_persistent(l_main___closed__3);
return lean_io_result_mk_ok(lean_box(0));
}
void lean_initialize();

  #if defined(WIN32) || defined(_WIN32)
  #include <windows.h>
  #endif

  int main(int argc, char ** argv) {
  #if defined(WIN32) || defined(_WIN32)
  SetErrorMode(SEM_FAILCRITICALERRORS);
  #endif
  lean_object* in; lean_object* res;
lean_initialize();
lean_set_panic_messages(false);
res = initialize_Main(1 /* builtin */, lean_io_mk_world());
lean_set_panic_messages(true);
lean_io_mark_end_initialization();
if (lean_io_result_is_ok(res)) {
lean_dec_ref(res);
lean_init_task_manager();
in = lean_box(0);
int i = argc;
while (i > 1) {
 lean_object* n;
 i--;
 n = lean_alloc_ctor(1,2,0); lean_ctor_set(n, 0, lean_mk_string(argv[i])); lean_ctor_set(n, 1, in);
 in = n;
}
res = _lean_main(in, lean_io_mk_world());
}
lean_finalize_task_manager();
if (lean_io_result_is_ok(res)) {
  int ret = 0;
  lean_dec_ref(res);
  return ret;
} else {
  lean_io_result_show_error(res);
  lean_dec_ref(res);
  return 1;
}
}
#ifdef __cplusplus
}
#endif
