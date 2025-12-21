# GNARK Based Pairing Crypto Algorithms

## Introduction
We implement some pairing-based crypto algorithms.

pairing-library: https://github.com/Consensys/gnark

## Digital Signature
| Scheme Abbr.      | Paper Title                                                                 | Paper Link | Core Chapter                              | Code Repository                                                                                           | Security Assumption         |
|:------------------|:----------------------------------------------------------------------------| :--- |:------------------------------------------|:----------------------------------------------------------------------------------------------------------|:----------------------------|
| **BLS Signature** | *Short Signatures from the Weil Pairing*                                    | [Link](https://link.springer.com/chapter/10.1007/3-540-45682-1_30) | §2.2 The GDH Signature Scheme             | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/signature/bf01_ibe/bls01/bls_signature.go) | Random Oracle Model         |
| **ZSS Signature** | *An Efficient Signature Scheme from Bilinear Pairings and Its Applications* | [Link](https://link.springer.com/chapter/10.1007/978-3-540-24632-9_20) | §3.1 The Basic Signature Scheme           | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/signature/zss04/zss04_signature.go)        | Random Oracle Model         |
| **BB Signature**  | *Short Signatures Without Random Oracles*                                   | [Link](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_4) | §3 Short Signatures Without Random Oracles| [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/signature/bb04/bb04_signature.go)          | Standard Model |

## Identity Based Encryption Implementation
| Scheme Abbr. | Paper Title | Paper Link | Core Chapter | Code Repository                                                                                          | Security Assumption               |
| :--- | :--- | :--- | :--- |:---------------------------------------------------------------------------------------------------------|:----------------------------------|
| **BF01** | *Identity-Based Encryption from the Weil Pairing* | [Link](https://link.springer.com/chapter/10.1007/3-540-44647-8_13) | §4.2 BasicIdent | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/ibe/bf01_ibe/bf01_ibe.go)                 | CPA (Random Oracle Model)         |
| **BB04 (Selective)** | *Efficient Selective-ID Secure IBE Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_14) | §5 More Efficient Selective Identity IBE | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/ibe/bb04_sibe/bb04_sibe.go)               | Selective-ID CPA (Standard Model) |
| **BB04 (Full)** | *Secure Identity Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/978-3-540-28628-8_27) | §4 Secure IBE Construction | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/ibe/bb04_ibe/bb04_ibe.go)                 | Full-ID CPA (Standard Model)      |
| **Waters05** | *Efficient Identity-Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/11426639_7) | §4 Construction | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/ibe/waters05_ibe/waters05_ibe.go)         | Full-ID CPA (Standard Model)      |
| **Gentry06 (CPA)** | *Practical Identity-Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/11761679_27) | §3 Construction I: Chosen-Plaintext Security | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/ibe/gentry06_cpa_ibe/gentry06_cpa_ibe.go) | Full-ID CPA (Standard Model)      |
| **Gentry06 (CCA)** | *Practical Identity-Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/11761679_27) | §4 Construction II: Chosen-Ciphertext Security | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/ibe/gentry06_ibe/gentry06_ibe.go)                     | Full-ID CCA (Standard Model)      |


## Fuzzy Identity Based Encryption Implementation


| Scheme Abbr.              | Paper Title | Paper Link | Core Chapter | Code Repository                                                                                  | Security Assumption               |
|:--------------------------| :--- | :--- | :--- |:-------------------------------------------------------------------------------------------------|:----------------------------------|
| **SW05**                  | *Fuzzy Identity-Based Encryption* | [Link](https://eprint.iacr.org/2004/086.pdf) | §4 Our Construction | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/fibe/sw05_fibe_common.go)         | Selective-ID CPA         |
| **SW05 (Large Universe)** | *Fuzzy Identity-Based Encryption* | [Link](https://eprint.iacr.org/2004/086.pdf) | §6 Large Universe Construction | [code](https://github.com/mmsyan/GnarkPairingProject/blob/main/fibe/sw05_fibe_large_universe.go) | Selective-ID CPA  |



## How to use our code


To use our implementation:
```
go get github.com/mmsyan/GnarkPairingProject