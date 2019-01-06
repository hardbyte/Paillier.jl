using Paillier

pub, priv = generate_paillier_keypair(1024)
println(pub)
println(priv)

a = encrypt(pub, 10)
b = encrypt(pub, 50)
println("decrypt(a) = $(decrypt(priv, a))")
println("decrypt(b) = $(decrypt(priv, b))")

println("decrypt(a + 5) = $(decrypt(priv, a + 5))")
# obfuscate before sharing an encrypted number
c = obfuscate(2a + b);

println("decrypt(2a + b) = ", decrypt(priv, c))
