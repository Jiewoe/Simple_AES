from aes.AES import AES

ase = AES()
ase.init()
e = ase.encrypt(0x45C1)
d = ase.decrypt(e)

print(e)
print(d)
print(0x45C1)
print(0x09DB)