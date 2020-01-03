var documenterSearchIndex = {"docs":
[{"location":"core/#","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"CurrentModule = Paillier","category":"page"},{"location":"core/#Core-Cryptosystem-1","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"","category":"section"},{"location":"core/#Types-1","page":"Core Cryptosystem","title":"Types","text":"","category":"section"},{"location":"core/#","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"Encrypted","category":"page"},{"location":"core/#Paillier.Encrypted","page":"Core Cryptosystem","title":"Paillier.Encrypted","text":"Encrypted(ciphertext, public_key)\nEncrypted(ciphertext, public_key, is_obfuscated::Bool)\n\nAn Encrypted is the Paillier.jl library's low level encrypted type. This simple object that includes the ciphertext, public_key and tracks whether obfuscation has occurred (assumed as false if not provided).\n\n\n\n\n\n","category":"type"},{"location":"core/#Methods-1","page":"Core Cryptosystem","title":"Methods","text":"","category":"section"},{"location":"core/#","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"encrypt","category":"page"},{"location":"core/#Paillier.encrypt","page":"Core Cryptosystem","title":"Paillier.encrypt","text":"encrypt(public_key, message)\n\nEncrypt a message with a given public key and return an Encrypted. The message must be a positive integer under public_key.n - following Julia's Int64 type larger numbers will wrap around and not throw an error.\n\nSee decrypt if you'd like your original message back.\n\n\n\n\n\nencrypt(::Array{Encoded}, ::Encoding)\nencrypt(::Array{Encoded}, ::PublicKey)\n\nEncrypt an array of encoded instances\n\n\n\n\n\n","category":"function"},{"location":"core/#","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"decrypt","category":"page"},{"location":"core/#Paillier.decrypt","page":"Core Cryptosystem","title":"Paillier.decrypt","text":"decrypt(private_key, ciphertext::Ciphertext)\ndecrypt(private_key, ciphertext::Encrypted)\n\nThe inverse of encrypt, uses the private_key to decrypt an encrypted message (ciphertext) to a positive integer less than public_key.n. The result is always a BigInt.\n\nExamples\n\njulia> publickey, privatekey = generate_paillier_keypair(128);\njulia> ciphertext = encrypt(publickey, 10);\njulia> decrypt(privatekey, ciphertext)\n10\n\n\n\n\n\n\n","category":"function"},{"location":"core/#","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"encrypt_raw","category":"page"},{"location":"core/#Paillier.encrypt_raw","page":"Core Cryptosystem","title":"Paillier.encrypt_raw","text":"encrypt_raw(public_key, message)\n\nInternal version of encrypt that returns the raw Ciphertext - which is just a BigInt. Note this includes obfuscation so a directly encrypted unsigned integer is safe to share.\n\n\n\n\n\n","category":"function"},{"location":"core/#","page":"Core Cryptosystem","title":"Core Cryptosystem","text":"obfuscate","category":"page"},{"location":"core/#Paillier.obfuscate","page":"Core Cryptosystem","title":"Paillier.obfuscate","text":"obfuscate(encrypted)\nobfuscate(rng, encrypted)\n\nSalt the Encrypted with a new random number. Required before sharing ciphertexts with another party.\n\n\n\n\n\n","category":"function"},{"location":"usage/#Usage-1","page":"Usage","title":"Usage","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"After installing the package, you can start using it with","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"using Paillier","category":"page"},{"location":"usage/#Key-Generation-1","page":"Usage","title":"Key Generation","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"To begin you will need a keypair - a public and private Paillier key.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Paillier.generate_paillier_keypair","category":"page"},{"location":"usage/#Paillier.generate_paillier_keypair","page":"Usage","title":"Paillier.generate_paillier_keypair","text":"generate_paillier_keypair([rng=GLOBAL_RNG], n_length=2048)\n\nGenerate a new Paillier keypair of given bit length.\n\nReturns a 2-tuple of the public and private key.\n\n\n\n\n\n","category":"function"},{"location":"usage/#Raw-Paillier-cryptosystem-1","page":"Usage","title":"Raw Paillier cryptosystem","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"At the lowest level we can encrypt and decrypt (positive) integers using the  raw paillier cryptosystem - that is with no encoding.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"julia> using Paillier\njulia> pub, priv = generate_paillier_keypair(1024)\njulia> a = encrypt(pub, 10)\njulia> b = encrypt(pub, 50)\njulia> decrypt(priv, a)\n10\njulia> decrypt(priv, a + 5)\n15\njulia> c = 2a + b;\njulia> typeof(c)\nEncrypted\njulia> decrypt(priv, c)\n70","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Note that addition between encrypted numbers, and multiplication of an encrypted number and a plaintext number works.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"note: Note\nThe raw encrypted numbers above are not ready for sharing. Users must manually call obfuscate once all the mathematical operations have been completed.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Paillier.obfuscate","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Always obfuscate before sharing an encrypted number:","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"julia> (2a + b).is_obfuscated\nfalse\njulia> c = obfuscate(2a + b)\njulia> c.is_obfuscated\ntrue","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"note: Note\nAttempting to encrypt a negative integer will result in a DomainError:julia> encrypt(pub, -10)\nERROR: DomainError with Can't encrypt negative integers without encoding:","category":"page"},{"location":"usage/#Floating-point-encoding-1","page":"Usage","title":"Floating point encoding","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"To work with negative and floating point numbers we follow the encoding scheme of  python-paillier.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Create an Encoding for the type to encode.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Paillier.Encoding","category":"page"},{"location":"usage/#Example-encoding-Float32-numbers-1","page":"Usage","title":"Example encoding Float32 numbers","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"julia> keysize = 2048\njulia> publickey, privatekey = generate_paillier_keypair(keysize)\njulia> encoding = Encoding{Float32}(publickey)\njulia> a = Float32(π)\njulia> b = 100\njulia> enc1 = encode_and_encrypt(a, encoding)\njulia> decrypt_and_decode(privatekey, enc1)\n3.1415927f0\njulia> enc1.exponent\n-6\njulia> enc2 = encode_and_encrypt(b, encoding)\njulia> enc3 = decrypt_and_decode(privatekey, enc1 + enc2)\njulia> enc3\n103.141594f0\njulia> decrypt_and_decode(privatekey, enc1 - 20.0)\n-16.858408f0","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"note: Note\nThere are still rough edges when working with higher precision datatypes such as BigFloat. For now I'd recommend encoding either Float32 or Float64.  ","category":"page"},{"location":"usage/#User-Defined-Encoding-1","page":"Usage","title":"User Defined Encoding","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"See encoding for an example creating a custom Encoding to take a  Measurement and encode it for encryption as an EncryptedArray containing both the value and the uncertainty in encrypted form.","category":"page"},{"location":"usage/#Array-Support-1","page":"Usage","title":"Array Support","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"To avoid wasting space having multiple copies of the same PublicKey use the  EncryptedArray type that behaves like an array of EncryptedNumber objects, but only stores one copy of shared metadata such as the public  key, the encoding and the exponent along with the underlying ciphertexts.","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Paillier.EncryptedArray","category":"page"},{"location":"usage/#Paillier.EncryptedArray","page":"Usage","title":"Paillier.EncryptedArray","text":"EncryptedArray\n\nA vector version of EncryptedNumber.\n\n\n\n\n\n","category":"type"},{"location":"usage/#Paillier-operations-on-an-encrypted-vector-of-floats-1","page":"Usage","title":"Paillier operations on an encrypted vector of floats","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"julia> publickey, privatekey = generate_paillier_keypair(2048)\njulia> a = [0.0, 1.2e3, 3.14, π]\njulia> encoding = Encoding{Float32}(publickey)\njulia> enca = encode_and_encrypt(a, encoding);\njulia> decrypt_and_decode(privatekey, enca)\n4-element Array{Float32,1}:\n    0.0      \n 1200.0      \n    3.1399999\n    3.1415927\njulia> encb = 2 * enca;\njulia> decrypt_and_decode(privatekey, encb)\n4-element Array{Float32,1}:\n    0.0      \n 2400.0      \n    6.2799997\n    6.2831855\njulia> decrypt_and_decode(privatekey, reduce(+, encb))\n2412.5632f0\njulia> enca.is_obfuscated\ntrue\njulia> encb.is_obfuscated\nfalse\njulia> encb = obfuscate(encb);\njulia> encb.is_obfuscated\ntrue","category":"page"},{"location":"usage/#Broadcasting-1","page":"Usage","title":"Broadcasting","text":"","category":"section"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Paillier.jl makes some effort towards supporting multidimensional arrays:","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"julia> x = [[0, 1] [345, 32410] [3, 784564]]\njulia> publickey, privatekey = generate_paillier_keypair(4096)\njulia> encoding = Encoding{Float32}(publickey)\njulia> encrypted = encode_and_encrypt(x, encoding)\njulia> encrypted.public_key == publickey\ntrue\njulia> typeof(encrypted), size(encrypted)\n(EncryptedArray{BigInt,2}, (2, 3))\njulia> decrypt_and_decode(privatekey, encrypted)\n2×3 Array{Float32,2}:\n 0.0    345.0       3.0\n 1.0  32410.0  784564.0\njulia> decrypt_and_decode(privatekey, [4, 2] .* encrypted .+ 100)\n2×3 Array{Float32,2}:\n 100.0   1480.0  112.0      \n 102.0  64920.0    1.56923e6","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"Finally an example calling dot from LinearAlgebra between an encrypted and non encrypted matrix:","category":"page"},{"location":"usage/#","page":"Usage","title":"Usage","text":"julia> using Paillier, LinearAlgebra\njulia> a = [[1,2] [2,3]]\njulia> b = [[1,2] [2,3]]\njulia> publickey, privatekey = generate_paillier_keypair(4096)\njulia> encoding = Encoding{Float32}(publickey)\njulia> ea = encode_and_encrypt(a, encoding)\njulia> decrypt_and_decode(privatekey, dot(ea, b))\n18.0f0","category":"page"},{"location":"#Paillier.jl-1","page":"Paillier.jl","title":"Paillier.jl","text":"","category":"section"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"","category":"page"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"Paillier.jl is divided into two layers: the core cryptosystem, and a higher level layer which can deal with encoding floating point numbers and vectors of encrypted numbers.","category":"page"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"note: Note\nImportant notes on security.We don't obfuscate the results of encrypted math operations by default. This is an optimization copied from python-paillier, however after any homomorphic operation - before sharing an EncryptedNumber or EncryptedArray you must call obfuscate() to secure the ciphertext. Ideally this will occur behind the scenes at serialization time, but this library does not help with serialization (yet).Be warned that constant time functions have not been used, proceed with extreme caution if your application could be susceptible to timing side channel attacks.","category":"page"},{"location":"#Installation-1","page":"Paillier.jl","title":"Installation","text":"","category":"section"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"Paillier.jl has been registered so install with Julia's package manager with:","category":"page"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"] add Paillier","category":"page"},{"location":"#Examples-1","page":"Paillier.jl","title":"Examples","text":"","category":"section"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"A number of examples can be found in the examples folder.","category":"page"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"Run individual examples with Julia:","category":"page"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"$ julia --project examples/raw_cryptosystem.jl","category":"page"},{"location":"#Changelog-1","page":"Paillier.jl","title":"Changelog","text":"","category":"section"},{"location":"#Version-0.3.0-1","page":"Paillier.jl","title":"Version 0.3.0","text":"","category":"section"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"Introduces a breaking change in the encoded type, which should allow easier composition with other Julia modules.","category":"page"},{"location":"#","page":"Paillier.jl","title":"Paillier.jl","text":"To migrate replace Encoding(Float32, publickey) with Encoding{Float32}(publickey).","category":"page"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"CurrentModule = Paillier","category":"page"},{"location":"encoding/#Encoding-1","page":"Encoding","title":"Encoding","text":"","category":"section"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"Paillier.jl allows encoding of Julia primitive numbers. The following example shows carrying out homomorphic operations on floating point numbers - in this case Float32.","category":"page"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"julia> keysize = 2048\njulia> publickey, privatekey = generate_paillier_keypair(keysize)\njulia> encoding = Encoding{Float32}(publickey)\njulia> a = Float32(π)\njulia> enc1 = encode_and_encrypt(a, encoding)\njulia> decrypt_and_decode(privatekey, enc1)\n3.1415927f0\njulia> enc1.exponent\n-6\njulia> b = 100\njulia> enc2 = encode_and_encrypt(b, encoding)\njulia> decrypt_and_decode(privatekey, enc1 + enc2)\n103.141594f0\njulia> decrypt_and_decode(privatekey, enc1 - 20.0)\n-16.858408f0","category":"page"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"Note the enc1.exponent is a public number which reveals size information about the encrypted value.","category":"page"},{"location":"encoding/#API-1","page":"Encoding","title":"API","text":"","category":"section"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"encode_and_encrypt\n\ndecrypt_and_decode","category":"page"},{"location":"encoding/#Paillier.encode_and_encrypt","page":"Encoding","title":"Paillier.encode_and_encrypt","text":"encode_and_encrypt(plaintext::Number, encoding::Encoding)\nencode_and_encrypt(plaintext::Number, encoding::Encoding, exponent::Int64)\n\nEncode the plaintext number using given encoding and encrypt using the PublicKey from the encoding.\n\n\n\n\n\nencode_and_encrypt(xs::Array{<:Number}, encoding::Encoding)\nencode_and_encrypt(xs::Array{<:Number}, encoding::Encoding, exponent::Int64)\n\nCreate an EncryptedArray of your plaintext numbers.\n\n\n\n\n\n","category":"function"},{"location":"encoding/#Paillier.decrypt_and_decode","page":"Encoding","title":"Paillier.decrypt_and_decode","text":"decrypt_and_decode(privatekey::PrivateKey, enc::EncryptedNumber)\n\nDecrypt an EncryptedNumber using the given PrivateKey and decode it using the EncryptedNumber's encoding.\n\n\n\n\n\n","category":"function"},{"location":"encoding/#Types-1","page":"Encoding","title":"Types","text":"","category":"section"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"Encoding\n\nEncoded\n\nEncryptedNumber","category":"page"},{"location":"encoding/#Paillier.Encoding","page":"Encoding","title":"Paillier.Encoding","text":"Encoding{::DataType}(::PublicKey)\nEncoding{::DataType,(::PublicKey, base::Int64)\n\nA datatype for describing a fixed point encoding scheme for Julia DataTypes.\n\nThe public key is included as the encoding is effected by the maximum representable integer which varies with the public_key.\n\nSetting a base value is optional - other Paillier implementations may use a  different base.\n\nExamples\n\nSpecifying the optional base for encoding a Float64:\n\njulia> encoding = Encoding{Float64}(public_key, 64)\n\n\n\n\n\n","category":"type"},{"location":"encoding/#Paillier.Encoded","page":"Encoding","title":"Paillier.Encoded","text":"A datatype for a plaintext encoded number. Returned by the encode methods.\n\nRepresents the Julia value as a BigInt.\n\n\n\n\n\n","category":"type"},{"location":"encoding/#Paillier.EncryptedNumber","page":"Encoding","title":"Paillier.EncryptedNumber","text":"EncryptedNumber(::Encrypted, ::Encoding, exponent::Int64)\nEncryptedNumber(::Encoded, ::PublicKey)\n\nDatatype for representing an Encrypted number with a known Encoding.\n\nExamples\n\npublic_key, priv = generate_paillier_keypair(128)\nencoding = Encoding{Float32}(publickey)\n\njulia> encoded_number = encode(23.4, encoding)\njulia> EncryptedNumber(encoded_number, public_key)\n\n\n\n\n\n","category":"type"},{"location":"encoding/#User-Defined-Encoding-1","page":"Encoding","title":"User Defined Encoding","text":"","category":"section"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"Say you wanted to carry out Partially Homomorphic operations on values with uncertainty using the fantastic Meaurements package.","category":"page"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"Do achieve this you need to define your Encoding type, and add methods to encode and decode the new Encoding type.","category":"page"},{"location":"encoding/#","page":"Encoding","title":"Encoding","text":"import Paillier\nusing Measurements\n\nkeysize = 2048\nbase = 64\n\nMyType = Measurement{Float16}\npublickey, privatekey = Paillier.generate_paillier_keypair(keysize)\nencoding = Paillier.Encoding{MyType}(publickey, base)\n\n# Support encoding any Measurement by encoding the value and error separately\n# This will create an EncodedArray\nfunction Paillier.encode(scalar::MyType, encoding::Paillier.Encoding{Measurement{T}}) where T\n    internal_encoding = Paillier.Encoding{T}(encoding.public_key, encoding.base)\n    encodings = Paillier.encode([scalar.val, scalar.err], internal_encoding)\n    # create a copy of the EncodedArray with our Measurement encoding type\n    Paillier.EncodedArray(encodings.plaintexts, encoding)\nend\n\nfunction Paillier.decode(encoded::Paillier.EncodedArray, exponent::Int64, encoding::Paillier.Encoding{Measurement{T}}) where T\n    internal_encoding = Paillier.Encoding{T}(encoding.public_key, encoding.base)\n    return measurement(\n        Paillier.decode(encoded.plaintexts[1].value, exponent, internal_encoding),\n        Paillier.decode(encoded.plaintexts[2].value, exponent, internal_encoding)\n    )\nend\n\n\"\"\"\nBecause we are end up with an array of encrypted numbers\nwe may want to override some of the broadcast/array functionality\n\"\"\"\n+(enc_a::Paillier.EncryptedArray, plaintext::Measurement) = enc_a + Paillier.encode(plaintext, enc_a.encoding)\n\n\na = Measurement{Float16}(2000 ± 10)\nb = Measurement{Float16}(100 ± 1)\n\nenc1 = Paillier.encode_and_encrypt(a, encoding)\nenc2 = Paillier.encode_and_encrypt(b, encoding)\n\nenc3 = enc1 + enc2\n\nc = Paillier.decrypt_and_decode(privatekey, enc3)\nprintln(\"Adding encrypted Measurement numbers: D(E($a) + E($b)) = $c\")\n\n# Dircetly use our previously defined encoding function\nencoded_b = Paillier.encode(b, enc3.encoding)\nd = Paillier.decrypt_and_decode(privatekey, enc3 + encoded_b)\nprintln(\"Adding encrypted number with encoded but unencrypted number (with uncertainty): D(E($c) + $b) = $d\")\n\n# Dircetly add a non encoded Measurement number\nd = Paillier.decrypt_and_decode(privatekey, enc3 + b)\nprintln(\"Adding encrypted number with Meaurement number: D(E$c) + $b) = $d\")\n\n# Subtraction\nenc4 = Paillier.decrypt_and_decode(privatekey, enc3 - Paillier.encode_and_encrypt(a, enc3.encoding))\nprintln(\"Subtract a constant (with uncertainty) from an encrypted number: D(E($c) - $a) = $enc4\")\n\n# Multiplication\nenc5 = Paillier.decrypt_and_decode(privatekey, 3*enc1)\nprintln(\"Scaling an encrypted Measurement number: 3 * $a = $enc5\")\n","category":"page"}]
}
