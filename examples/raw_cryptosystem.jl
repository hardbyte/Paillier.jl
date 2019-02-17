import Paillier

pub, priv = Paillier.generate_paillier_keypair(1024)
println(pub)
println(priv)

a = Paillier.encrypt(pub, 10)
b = Paillier.encrypt(pub, 50)
println("decrypt(a) = $(Paillier.decrypt(priv, a))")
println("decrypt(b) = $(Paillier.decrypt(priv, b))")

println("decrypt(a + 5) = $(Paillier.decrypt(priv, a + 5))")
# obfuscate before sharing an encrypted number
c = Paillier.obfuscate(2a + b);

println("decrypt(2a + b) = ", Paillier.decrypt(priv, c))
