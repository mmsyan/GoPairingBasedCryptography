# GNARK Based Pairing Crypto Algorithms

## Introduction
This repository implements a collection of cryptographic schemes based on bilinear pairings.

We utilize the **BN254** pairing implementation from the [gnark](https://github.com/Consensys/gnark) library (specifically the pairing-library module) as our underlying bilinear pairing primitive.

Implemented Schemes includes: 
- Digital signatures
- Identity-Based Encryption (IBE)
- Fuzzy Identity-Based Encryption (Fuzzy IBE)
- Ciphertext-Policy Attribute-Based Encryption (CP-ABE)
- Key-Policy Attribute-Based Encryption (KP-ABE)
- Batch Identity Based Encryption (BIBE)

## Digital Signature

We have implemented three classic pairing-based digital signature schemes:

- **BLS Signature**: The most well-known and classic scheme, but it relies on a "map-to-curve-point" operation (hashing arbitrary messages directly to points on the G1 curve), which results in relatively slower performance.
- **ZSS Signature**: This scheme eliminates the need for map-to-curve-point, requiring only mapping to a field element, leading to significantly improved performance.
- **BB Signature**: Achieves security in the **standard model** (without relying on the random oracle assumption).

The first two schemes (BLS and ZSS) are proven secure in the **random oracle model**, while the third (BB) provides security in the more rigorous **standard model**.


| Scheme Abbr.      | Paper Title                                                                 | Paper Link | Core Chapter                              | Code Repository                                                                                           | Security Assumption         |
|:------------------|:----------------------------------------------------------------------------| :--- |:------------------------------------------|:----------------------------------------------------------------------------------------------------------|:----------------------------|
| **BLS Signature** | *Short Signatures from the Weil Pairing*                                    | [Link](https://link.springer.com/chapter/10.1007/3-540-45682-1_30) | §2.2 The GDH Signature Scheme             | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/signature/bls01_signature/bls_signature.go) | Random Oracle Model         |
| **ZSS Signature** | *An Efficient Signature Scheme from Bilinear Pairings and Its Applications* | [Link](https://link.springer.com/chapter/10.1007/978-3-540-24632-9_20) | §3.1 The Basic Signature Scheme           | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/signature/zss04_signature/zss04_signature.go)        | Random Oracle Model         |
| **BB Signature**  | *Short Signatures Without Random Oracles*                                   | [Link](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_4) | §3 Short Signatures Without Random Oracles| [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/signature/bb04_signature/bb04_signature.go)          | Standard Model |

## Identity Based Encryption Implementation

We have implemented six representative IBE schemes, covering the evolution from the foundational random-oracle construction to fully secure schemes in the standard model:

| Scheme Abbr. | Paper Title | Paper Link | Core Chapter | Code Repository                                                                                          | Security Assumption               |
| :--- | :--- | :--- | :--- |:---------------------------------------------------------------------------------------------------------|:----------------------------------|
| **BF01** | *Identity-Based Encryption from the Weil Pairing* | [Link](https://link.springer.com/chapter/10.1007/3-540-44647-8_13) | §4.2 BasicIdent | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/ibe/bf01_ibe/bf01_ibe.go)                 | CPA (Random Oracle Model)         |
| **BB04 (Selective)** | *Efficient Selective-ID Secure IBE Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_14) | §5 More Efficient Selective Identity IBE | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/ibe/bb04_sibe/bb04_sibe.go)               | Selective-ID CPA (Standard Model) |
| **BB04 (Full)** | *Secure Identity Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/978-3-540-28628-8_27) | §4 Secure IBE Construction | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/ibe/bb04_ibe/bb04_ibe.go)                 | Full-ID CPA (Standard Model)      |
| **Waters05** | *Efficient Identity-Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/11426639_7) | §4 Construction | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/ibe/waters05_ibe/waters05_ibe.go)         | Full-ID CPA (Standard Model)      |
| **Gentry06 (CPA)** | *Practical Identity-Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/11761679_27) | §3 Construction I: Chosen-Plaintext Security | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/ibe/gentry06_cpa_ibe/gentry06_cpa_ibe.go) | Full-ID CPA (Standard Model)      |
| **Gentry06 (CCA)** | *Practical Identity-Based Encryption Without Random Oracles* | [Link](https://link.springer.com/chapter/10.1007/11761679_27) | §4 Construction II: Chosen-Ciphertext Security | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/ibe/gentry06_ibe/gentry06_ibe.go)                     | Full-ID CCA (Standard Model)      |


## Fuzzy Identity Based Encryption Implementation


| Scheme Abbr.              | Paper Title | Paper Link | Core Chapter | Code Repository                                                                                  | Security Assumption               |
|:--------------------------| :--- | :--- | :--- |:-------------------------------------------------------------------------------------------------|:----------------------------------|
| **SW05**                  | *Fuzzy Identity-Based Encryption* | [Link](https://eprint.iacr.org/2004/086.pdf) | §4 Our Construction | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/fibe/sw05_fibe_common.go)         | Selective-ID CPA         |
| **SW05 (Large Universe)** | *Fuzzy Identity-Based Encryption* | [Link](https://eprint.iacr.org/2004/086.pdf) | §6 Large Universe Construction | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/fibe/sw05_fibe_large_universe.go) | Selective-ID CPA  |


## Batch Identity Based Encryption Implementation
In a batched identity-based encryption (IBE) scheme, ciphertexts are associated with a batch label tg∗ and an identity id∗ while secret keys are associated with a batch label tg and a set of identities S. Decryption is possible whenever tg = tg∗ and id∗ ∈ S. The primary efficiency property in a batched IBE scheme is that the size of the decryption key for a set S should be independent of the size of S.

We have implemented two BIBE shcemes:

- **AFP25**: This is the first BIBE scheme
- **GWWW25**: A BIBE scheme that is secure under plain model.

| Scheme Abbr. | Paper Title | Paper Link | Core Chapter                                          | Code Repository                                                                                        | Security Assumption        |
|:-------------| :--- | :--- |:------------------------------------------------------|:-------------------------------------------------------------------------------------------------------|:---------------------------|
| **AFP25**    | *Efficiently-Thresholdizable Batched Identity Based Encryption, with Applications.* | [Link](https://doi.org/10.1007/978-3-032-01881-6_3) | §6 Our Batched Identity Based Encryption construction | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/bibe/afp25_bibe/afp25_bibe.go)   | BIBE Security(GCM)         |
| **GWWW25**   | *Threshold Batched Identity-Based Encryption from Pairings in the Plain Model*      | [Link](https://eprint.iacr.org/2025/2103) | §4 Batched Identity-Based Encryption                  | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/bibe/gwww25_bibe/gwww25_bibe.go) | Selective Security(q-type) |


## Group Key Agreement
Some group key agreement protocols use bilinear pairings as a building block. Our implementation includes the following:
- ASBB: The ASBB(Aggregatable Signature-Based Broadcast) is a combination of digital signature and broadcast scheme. It was proposed in *Asymmetric Group Key Agreement*.

| Scheme Abbr. | Paper Title                       | Paper Link | Core Chapter                                          | Code Repository                                                                         | Security Assumption |
|:-------------|:----------------------------------| :--- |:------------------------------------------------------|:----------------------------------------------------------------------------------------|:--------------------|
| **AGKA**     | *Asymmetric Group Key Agreement.* | [Link](https://link.springer.com/chapter/10.1007/978-3-642-01001-9_9) | §4.1 An Efficient ASBB Scheme | [code](https://github.com/mmsyan/GoPairingBasedCryptography/blob/main/gka/agka/asbb.go) | CPA Secure(ROM)     |


## How to use our code


To use our implementation:
```
go get github.com/mmsyan/GoPairingBasedCryptography