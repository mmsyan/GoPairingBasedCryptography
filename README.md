# GNARK Based Pairing Crypto Algorithms

## Introduction
We implement some pairing-based crypto algorithms.

pairing-library: https://github.com/Consensys/gnark

* bls signature
* identity based encryption
  * __BF01 §4.2__ [《Identity-Based Encryption from the Weil Pairing》](https://link.springer.com/chapter/10.1007/3-540-44647-8_13)
  * __BB04 §5.1__ [《Efficient Selective-ID Secure Identity-Based Encryption Without Random Oracles》](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_14) 
* fuzzy identity based encryption:
  * __SW05 §4.1__ [Fuzzy Identity-Based Encryption](https://link.springer.com/chapter/10.1007/11426639_27)

## How to use our code


To use our implementation:
```
go get github.com/mmsyan/GnarkPairingProject