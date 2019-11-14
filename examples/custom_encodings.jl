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
function Paillier.encode(scalar::MyType, encoding::Paillier.Encoding{MyType})
    # HACK... ? Better to unwrap the T from "Measuement{T}"
    internal_encoding = Paillier.Encoding{Float16}(encoding.public_key, encoding.base)
    encodings = Paillier.encode([scalar.val, scalar.err], internal_encoding)
    # create a copy of the EncodedArray with our Measurement encoding type
    Paillier.EncodedArray(encodings.plaintexts, encoding)
end

function Paillier.decode(encoded::Paillier.EncodedArray, exponent::Int64, encoding::Paillier.Encoding{Measurement{Float16}})
    internal_encoding = Paillier.Encoding{Float16}(encoding.public_key, encoding.base)
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
println("Adding encrypted numbers: $a + $b = $c")

println("Ideal (if we could propogate tags through the encryption): $c - $a = $(a+b-a)")

enc4 = Paillier.decrypt_and_decode(privatekey, enc3 - a)
println("Subtract a constant (with uncertainty) from an encrypted number: $c - $a = $enc4")

#enc5 = Paillier.decrypt_and_decode(privatekey, 3*enc1)
#println("Scaling an encrypted number: 3 * $a = $enc5")
