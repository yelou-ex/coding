# 论文原文摘录（从 Submission_usenix_232.pdf 提取）

> 来源：`paper_layout.txt`（pdftotext -layout 提取，双语栏，同一行左右两栏内容会混排）
> 用途：实现 ANSWER 时的**唯一依据**，替代此前 README 的转述。

## Algorithm 1 FusePIR（正文 §4.1）
```
Algorithm 1 FusePIR
    S ETUP(1λ , DB = {Ki 7→ VKi = {vi,1 , . . . , vi,mi }}ni=1 )                               7: q := (q0 , q1 , q2 ), stC ← K.
 1: (D, H , fp) ← BFF.Setup(n, 3).                                                             8: return (q, stC ).
 2: LBFF ← |D|, m ← maxi∈[n] |VKi |.                                                              A NSWER(stS , q)
 3: Select public parameters (N, d,t, q), and generate HE keys sk = (sL , sR ) .               1: Parse stS = ({Pc,b }c,b , pp).
 4: Select R,C such that RC ≥ LBFF , R ≤ N.                                                    2: for a = 0 to 2 do
 5: for i = 1 to n do                                                                          3:      Parse (qcol      row
                                                                                                                a , qa ) from q.
                                                                                    B
 6:     Pad VKi to m values and set yKi ← fp(Ki ) ∥ mi ∥ vi,1 ∥ · · · ∥ vi,m ∈ Zt pay .        4:      for b = 1 to Bpay do
 7: end for                                                                                                Acca,b ← ∑C−1                      col
                                                                                               5:                          c=0 CtPtMul(qa [c], Pc,b (X)).
 8: (D, H ) ← BFF.Encode D, H , {(Ki , yKi )}ni=1 .
                                                              
                                                                                               6:          Acc′a,b ← BlindRotate(qrow       a , Acca,b ).
 9: for u = LBFF to RC − 1 do                                                                  7:          cta,b ← SampleExtract0 (Acc′a,b ).
                          B
10:     D[u] ← 0 ∈ Zt pay .                                                                    8:      end for
11: end for                                                                                    9: end for
12: for c = 0 to C − 1 do                                                                     10: for b = 1 to Bpay do
13:     for b = 1 to Bpay do
                                                                                                                                                          
                                                                                              11:      ctpay,b ← CtCtAdd CtCtAdd(ct0,b , ct1,b ), ct2,b .
14:          Pc,b (X) ← ∑R−1  r=0 D[r + cR][b]X .
                                                      r
                                                                                              12: end for
                                                                                                                                  Bpay
15:     end for                                                                               13: resp ← Pack({ctpay,b }b=1            ).
16: end for                                                                                   14: return resp.
17: pp ← (H , fp, R,C, N, d,t, q).                                                                D ECODE(sk, stC , resp)
18: stS ← ({Pc,b }c,b , pp).                                                                   1: K ← stC .
19: return (pp, stS , sk).                                                                     2: for each packed ciphertext ctpay,β ∈ resp do
    Q UERY(pp, sk, K)                                                                          3:      y[β] ← DecsR (ctpay,β ).
 1: q ← [ ].                                                                                   4: end for
 2: for a = 0 to 2 do                                                                          5: Recover ( f , mK , v1 , . . . , vm ) ← y.
 3:     ua ← ha (K), ra ← ua mod R, ca ← ⌊ua /R⌋.                                              6: if f ̸= fp(K) then
 4:     eca ← (0, . . . , 0, 1, 0, . . . , 0) ∈ {0, 1}C , with the 1 at index ca .            7:      return ⊥.
 5:     qa = (qcol      row
                  a , qa ) = RLWE.EncsR (eca ), LWE.EncsL (ra ) .                              8: end if
 6: end for                                                                                    9: return {v1 , . . . , vmK }.

```

## 正文对 Query/Answer 的说明（§4.1）
```
FusePIR follows the single-keyword PIR syntax defined in             encrypted payload obtained during A NSWER can also be used
Section 2.2. We instantiate the arithmetic BFF with three po-        directly by the subsequent computation in CAPE.
sition functions and use the same pair of HE keys throughout         Query-compressed variant. FusePIR-C preserves the
the three retrieval paths.                                           database representation and encrypted reconstruction of
   Encoding. For each keyword Ki , the server forms a fixed-         FusePIR, but replaces its one-hot RLWE selectors with com-
length payload containing its fingerprint, the number of asso-       pact LWE encryptions of the corresponding coordinates. The
ciated values, and the value set padded to m. The fingerprint        server expands these compact queries homomorphically be-
identifies invalid reconstruction, while padding ensures that        fore executing the same retrieval procedure. FusePIR-C there-
the representation and response length do not depend on the          fore trades additional server computation for substantially
number of values associated with the queried keyword.                smaller upload communication. Its detailed construction is
   The keyword–payload pairs are then encoded using the              given in Appendix B.
BFF of Section 2.4, with three positions assigned to each key-
word. We further represent the array into a two-dimensional          3.2     Correctness and Security
layout and pack each column into polynomial coefficients.
This design allows the server to select the target column ho-        We now show that FusePIR satisfies the correctness and se-
momorphically and then extract the desired entry using the           curity definitions of Section 2.2. Full proofs are given in
encrypted row index .                                                Appendix D.
   Query and Answer. The client generates encrypted row
                                                                     Theorem 1 (Correctness). Assuming the correctness of the
and column selectors for the three BFF positions of K
                                                                     BFF construction and the underlying homomorphic encryp-
(Lines 2–6 of Q UERY in Algorithm 1). The server evalu-
                                                                     tion procedures, the construction FusePIR in Algorithm 1
ates the three selections over the packed BFF representation
```

## 附录 B：CAPE 的 query-compressed 变体（含同态展开选择子）
```
                                                                                  9:     Ccol
                                                                                           a ← (Ca,0 , . . . , Ca,ℓc −1 ).
 1: ℓc ← ⌈log2 C⌉, ℓr ← ⌈log2 R⌉.
       $
                                                                                 10:     Crow
                                                                                           a ← (Ca,ℓc , . . . , Ca,ℓc +ℓr −1 ).
 2: ρ ← {0, 1}λ .                                                                        Homomorphically expand Ccol                qcol
                                                                                 11:                                        a into b a , an encryption of eca .
 3: for a = 0 to 2 do                                                            12:     for b = 1 to Bpay do
 4:     ua ← ha (K), ra ← ua mod R, ca ← ⌊ua /R⌋.                                                        C−1
 5:     za ← binℓc (ca ) ∥ binℓr (ra ).                                          13:                             qcol
                                                                                              Acca,b ← ∑ CtPtMul(ba [c], Pc,b (X)).
 6:     for j = 0 to ℓc + ℓr − 1 do                                                                      c=0
 7:         aa, j ← PRG(ρ, a, j) ∈ Zdq .                                         14:         Acc′a,b ← BlindRotate(Crow
                                                                                                                     a , Acca,b ).
 8:         βa, j ← ⟨aa, j , sL ⟩ + ∆za [ j] + ea, j (mod q).                    15:         cta,b ← SampleExtract0 (Acc′a,b ).
 9:     end for                                                                  16:     end for
10: end for                                                                      17: end for
11: q ← (ρ, {βa, j }a, j ).                                                      18: for b = 1 to Bpay do                                
12: stC ← K.                                                                     19:     ctpay,b ← CtCtAdd CtCtAdd(ct0,b , ct1,b ), ct2,b .
13: return (q, stC ).                                                            20: end for
                                                                                                             Bpay
    A NSWER(stS , q)                                                             21: resp ← Pack({ctpay,b }b=1    ).
 1: Parse stS = ({Pc,b }c,b , pp).                                               22: return resp.
 2: Parse q = (ρ, {βa, j }a, j ).                                                    D ECODE(sk, stC , resp)
 3: for a = 0 to 2 do                                                             1: return FusePIR.Decode(sk, stC , resp).


```
