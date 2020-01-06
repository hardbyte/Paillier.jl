```@meta
CurrentModule = Paillier
```


# Core Cryptosystem

```@docs
Paillier
```

## Methods


```@docs
Paillier.generate_paillier_keypair

encrypt

decrypt

encrypt_raw

obfuscate

decrease_exponent_to
```

### Homomorphic Operations

```@docs
+(::Encrypted, ::Number)


*(::Encrypted, ::Number)
```



## Types

```@docs

PublicKey

PrivateKey

Encrypted

Ciphertext

```
