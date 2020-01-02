import Paillier
using Measurements

"""
This example uses a custom Encoding and tries to pack a bunch of small numbers together
into one Paililer ciphertext.

THe idea is to pack a Big Int with lots of smaller numbers with some padding between them:

| 20 bytes | 20 bytes | 20 bytes | 20 bytes | 20 bytes | 20 bytes |
|  UInt16  |  UInt16  |  UInt16  |  UInt16  |  UInt16  |  UInt16  |

"""
keysize = 2048
padded_el_size = 20

PackableUInt16Type = Array{UInt16, 1}
publickey, privatekey = Paillier.generate_paillier_keypair(keysize)
encoding = Paillier.Encoding{PackableUInt16Type}(publickey)

# Support encoding an Array of UInt16 elements into a single cipchertext by encoding
# the values with some padding and recording the length of the vector as the public
# "exponent"
# Enhancements: We could pack as many ciphertexts as fit, then create an EncodedArray
function Paillier.encode(scalars::PackableUInt16Type, encoding::Paillier.Encoding{PackableUInt16Type})
    internal_encoding = Paillier.Encoding{BigInt}(encoding.public_key, encoding.base)

    # Packing method via BigInt bit shifting
    packed_bin = reduce(+, [BigInt(inputnumber)<<(padded_el_size*(i-1)) for (i, inputnumber) in enumerate(scalars)])
    packed = Paillier.encode(packed_bin, internal_encoding)

    # TODO could encode to multiple encoded arrays if too many plaintexts for one ciphertext.
    #encodings = Paillier.encode(packed_bin, internal_encoding)
    # create a copy of the EncodedArray with our Measurement encoding type
    #Paillier.EncodedArray(encodings.plaintexts, encoding)

    # create a copy of the Encoded with our custom encoding type
    # we abuse the encoding's public exponent value to store the length,
    # Although this shouldn't be necassary.
    Paillier.Encoded(encoding, packed.value, length(scalars))
end

function Paillier.decode(encoded::BigInt, exponent::Int64, encoding::Paillier.Encoding{PackableUInt16Type})
    num_elements = exponent
    # Probably the world worst way of calculating the number comprising 20 1's in binary
    mask = parse(BigInt, join(split(bitstring(BitArray(ones(Bool, 20))), " "), ""), base=2)
    return [UInt16((encoded & mask << (i*20)) >> (20*i)) for i in 0:(num_elements-1)]
end

function test_packed_encoding()
    a = Array{UInt16, 1}([1, 2, 734, 0x08])
    b = Array{UInt16, 1}([1, 2, 100, 0x22])

    println("Encrypting vector into a single ciphertext...", a)
    enca = Paillier.encode_and_encrypt(a, encoding)
    encb = Paillier.encode_and_encrypt(b, encoding)

    decrypted_a = Paillier.decrypt_and_decode(privatekey, enca)
    println("Decrypted packed numbers:", decrypted_a)

    println("Adding vector of encrypted numbers encoded inside single ciphertext")
    encc = enca + encb
    decrypted_c = Paillier.decrypt_and_decode(privatekey, encc)
    println("Decrypted packed numbers after adding: ", decrypted_c)
    println("Clear text version:                    ", a + b)
end

test_packed_encoding()
