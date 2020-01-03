import Paillier

keysize = 512
base = 64

publickey, privatekey = Paillier.generate_paillier_keypair(keysize)
encoding = Paillier.Encoding{Float16}(publickey, base)

T = Float16

a = ones(T, 16)
b = rand(T, 16)

enc1 = Paillier.encode_and_encrypt(a, encoding)
enc2 = Paillier.encode_and_encrypt(b, encoding)

out1 = Paillier.decrypt_and_decode(privatekey, enc1 + enc2)
println("Adding encrypted numbers: D(E(ones(16)) + E(rand(16)):\n$out1")

out2 = Paillier.decrypt_and_decode(privatekey, enc2 .- 1.0)
println("Subtract a constant from an encrypted vector: D(E(rand(16) .- 1.0)):\n$out2")

out3 = Paillier.decrypt_and_decode(privatekey, 2*(enc2 .- 0.5))
println("Scaling an encrypted vector:\nD(2 * E(rand(16) .- 0.5)):\n$out3")
