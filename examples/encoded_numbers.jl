using Paillier

"""
This example uses a custom Encoding.

"""
keysize = 2048
base = 16

publickey, privatekey = generate_paillier_keypair(keysize)
encoding = Encoding(Float16, publickey, base)

a = 2000
b = 100
enc1 = encode_and_encrypt(a, encoding)
enc2 = encode_and_encrypt(b, encoding)

@info "Decrypt $a: $(decrypt_and_decode(privatekey, enc1))"
@info decrypt_and_decode(privatekey, enc2)

enc3 = decrypt_and_decode(privatekey, enc1 + enc2)
@info enc3

enc4 = decrypt_and_decode(privatekey, enc1 - 20.0)
@info enc4

