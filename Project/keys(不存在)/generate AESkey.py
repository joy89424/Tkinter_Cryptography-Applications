from Crypto.Random import get_random_bytes

AESkey=get_random_bytes(16)

f=open("User.pem","wb")
f.write(AESkey)
f.close()
