using Paillier

"""
This example uses a custom Encoding.

"""
keysize = 2048
base = 64

publickey, privatekey = generate_paillier_keypair(keysize)
encoding = Encoding(Float16, publickey, base)

a = 2000.0
b = 100.0
enc1 = encode_and_encrypt(a, encoding)
enc2 = encode_and_encrypt(b, encoding)

enc3 = decrypt_and_decode(privatekey, enc1 + enc2)
println("Adding encrypted numbers: $a + $b = $enc3")

enc4 = decrypt_and_decode(privatekey, enc1 - 20.0)
println("Subtract a constant from an encrypted number: $a - 20.0 = $enc4")

enc5 = decrypt_and_decode(privatekey, 3*enc1)
println("Scaling an encrypted number: 3 * $a = $enc5")
