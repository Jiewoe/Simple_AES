from aes.AES import AES

ase = AES()
ase.extend_keys()
e = ase.encrypt(0x45C1)
d = ase.decrypt(e)

print(e)
print(d)
print(0x45C1)