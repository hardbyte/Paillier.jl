var documenterSearchIndex = {"docs": [

{
    "location": "core/#",
    "page": "Core Cryptosystem",
    "title": "Core Cryptosystem",
    "category": "page",
    "text": "CurrentModule = Paillier"
},

{
    "location": "core/#Core-Cryptosystem-1",
    "page": "Core Cryptosystem",
    "title": "Core Cryptosystem",
    "category": "section",
    "text": ""
},

{
    "location": "core/#Paillier.Encrypted",
    "page": "Core Cryptosystem",
    "title": "Paillier.Encrypted",
    "category": "type",
    "text": "Encrypted(ciphertext, public_key)\nEncrypted(ciphertext, public_key, is_obfuscated::Bool)\n\nAn Encrypted is the Paillier.jl library\'s low level encrypted type. This simple object that includes the ciphertext, public_key and tracks whether obfuscation has occurred (assumed as false if not provided).\n\n\n\n\n\n"
},

{
    "location": "core/#Types-1",
    "page": "Core Cryptosystem",
    "title": "Types",
    "category": "section",
    "text": "Encrypted"
},

{
    "location": "core/#Paillier.encrypt",
    "page": "Core Cryptosystem",
    "title": "Paillier.encrypt",
    "category": "function",
    "text": "encrypt(public_key, message)\n\nEncrypt a message with a given public key and return an Encrypted. The message must be a positive integer under public_key.n - following Julia\'s Int64 type larger numbers will wrap around and not throw an error.\n\nSee decrypt if you\'d like your original message back.\n\n\n\n\n\n"
},

{
    "location": "core/#Paillier.decrypt",
    "page": "Core Cryptosystem",
    "title": "Paillier.decrypt",
    "category": "function",
    "text": "decrypt(private_key, ciphertext::Ciphertext)\ndecrypt(private_key, ciphertext::Encrypted)\n\nThe inverse of encrypt, uses the private_key to decrypt an encrypted message (ciphertext) to a positive integer less than public_key.n. The result is always a BigInt.\n\nExamples\n\njulia> publickey, privatekey = generate_paillier_keypair(128);\njulia> ciphertext = encrypt(publickey, 10);\njulia> decrypt(privatekey, ciphertext)\n10\n\n\n\n\n\n\n"
},

{
    "location": "core/#Paillier.encrypt_raw",
    "page": "Core Cryptosystem",
    "title": "Paillier.encrypt_raw",
    "category": "function",
    "text": "encrypt_raw(public_key, message)\n\nInternal version of encrypt that returns the raw Ciphertext - which is just a BigInt. Note this includes obfuscation so a directly encrypted unsigned integer is safe to share.\n\n\n\n\n\n"
},

{
    "location": "core/#Paillier.obfuscate",
    "page": "Core Cryptosystem",
    "title": "Paillier.obfuscate",
    "category": "function",
    "text": "obfuscate(encrypted)\n\nSalt the Encrypted with a new random number. Required before sharing ciphertexts with another party.\n\n\n\n\n\n"
},

{
    "location": "core/#Methods-1",
    "page": "Core Cryptosystem",
    "title": "Methods",
    "category": "section",
    "text": "encryptdecryptencrypt_rawobfuscate"
},

{
    "location": "encoding/#",
    "page": "Encoding Floats",
    "title": "Encoding Floats",
    "category": "page",
    "text": "CurrentModule = Paillier"
},

{
    "location": "encoding/#Encoding-Floats-1",
    "page": "Encoding Floats",
    "title": "Encoding Floats",
    "category": "section",
    "text": ""
},

{
    "location": "encoding/#Paillier.Encoding",
    "page": "Encoding Floats",
    "title": "Paillier.Encoding",
    "category": "type",
    "text": "Encoding(::DataType, ::PublicKey)\nEncoding(::DataType, ::PublicKey, base::Int64)\n\nA datatype for describing an encoding scheme.\n\nThe public key is included as the encoding is effected by the maximum representable integer which varies with the public_key. Although I could be convinced to change this.\n\nExamples\n\nSetting a base value is optional:\n\njulia> encoding = Encoding(Float64, public_key, 64)\n\nFull example showing homomorphic operations on floating point numbers:\n\njulia> keysize = 2048\njulia> publickey, privatekey = generate_paillier_keypair(keysize)\njulia> encoding = Encoding(Float32, publickey)\njulia> a = Float32(π)\njulia> enc1 = encode_and_encrypt(a, encoding)\njulia> decrypt_and_decode(privatekey, enc1)\n3.1415927f0\njulia> enc1.exponent\n-6\njulia> b = 100\njulia> enc2 = encode_and_encrypt(b, encoding)\njulia> decrypt_and_decode(privatekey, enc1 + enc2)\n103.141594f0\njulia> decrypt_and_decode(privatekey, enc1 - 20.0)\n-16.858408f0\n\n\n\n\n\n\n"
},

{
    "location": "encoding/#Types-1",
    "page": "Encoding Floats",
    "title": "Types",
    "category": "section",
    "text": "Encoding"
},

{
    "location": "#",
    "page": "Paillier.jl",
    "title": "Paillier.jl",
    "category": "page",
    "text": ""
},

{
    "location": "#Paillier.jl-1",
    "page": "Paillier.jl",
    "title": "Paillier.jl",
    "category": "section",
    "text": "Paillier.jl is divided into two layers: the core cryptosystem, and a higher level layer which can deal with floating point numbers."
},

]}
