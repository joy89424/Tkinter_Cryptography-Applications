from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES

f=open("password.bin","rb")
data=f.read()
f.close()

#RSA先
f1=open("SU_privateKey.pem","rb")
PrivateKey=f1.read()
f1.close()

RSAkey_pri=RSA.import_key(PrivateKey)
decrypt_cipher=PKCS1_OAEP.new(RSAkey_pri)
data1=decrypt_cipher.decrypt(data)

#AES後
nonce=data1.split(b" ")[0]
tag=data1.split(b" ")[1]
ciphertext=data1.split(b" ")[2]
print(nonce,tag,ciphertext,sep="\n")

f1=open("User.pem","rb")                             
AESkey=f1.read()
f1.close()

cipher=AES.new(AESkey,AES.MODE_EAX,nonce) 
data=cipher.decrypt_and_verify(ciphertext,tag)
print(data)

