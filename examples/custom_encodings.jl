import Paillier
using Measurements

"""
This example uses a custom Encoding.

"""
keysize = 2048
base = 64

MyType = Measurement{Float16}
publickey, privatekey = Paillier.generate_paillier_keypair(keysize)
encoding = Paillier.Encoding{MyType}(publickey, base)

# Support encoding any Measurement by encoding the value and error separately
# This will create an EncodedArray
function Paillier.encode(scalar::MyType, encoding::Paillier.Encoding{Measurement{T}}) where T
    internal_encoding = Paillier.Encoding{T}(encoding.public_key, encoding.base)
    encodings = Paillier.encode([scalar.val, scalar.err], internal_encoding)
    # create a copy of the EncodedArray with our Measurement encoding type
    Paillier.EncodedArray(encodings.plaintexts, encoding)
end

function Paillier.decode(encoded::Paillier.EncodedArray, exponent::Int64, encoding::Paillier.Encoding{Measurement{T}}) where T
    internal_encoding = Paillier.Encoding{T}(encoding.public_key, encoding.base)
    return measurement(
        Paillier.decode(encoded.plaintexts[1].value, exponent, internal_encoding),
        Paillier.decode(encoded.plaintexts[2].value, exponent, internal_encoding)
    )
end

a = Measurement{Float16}(2000 ± 10)
b = Measurement{Float16}(100 ± 1)

enc1 = Paillier.encode_and_encrypt(a, encoding)
enc2 = Paillier.encode_and_encrypt(b, encoding)

enc3 = enc1 + enc2

c = Paillier.decrypt_and_decode(privatekey, enc3)
println("Adding encrypted numbers (with uncertainty): $c")

# Dircetly use our previously defined encoding function
encoded_b = Paillier.encode(b, enc3.encoding)
d = Paillier.decrypt_and_decode(privatekey, enc3 + encoded_b)
println("Adding encrypted number with encoded but unencrypted number (with uncertainty): $c + $b = $d")

# Issue due to encoding a single number as an EncryptedArray...
# However broadcasting will add to both the value and the uncertainty
e = Paillier.decrypt_and_decode(privatekey, enc3 .+ 5)
println("Broadcast adding an encrypted number with an uncertain number: $c .+ 5 = $e")

# Subtraction
enc4 = Paillier.decrypt_and_decode(privatekey, enc3 - Paillier.encode_and_encrypt(a, enc3.encoding))
println("Subtract a constant (with uncertainty) from an encrypted number: $c - $a = $enc4")
println("Ideal (if we could propogate tags through the encryption): $c - $a = $(a+b-a)")

# TODO check against ideal. Can we override *(Encrypted, Encoding{Measurement}) to add uncertainty?
#enc5 = Paillier.decrypt_and_decode(privatekey, 3*enc1)
#println("Scaling an encrypted number: 3 * $a = $enc5")
