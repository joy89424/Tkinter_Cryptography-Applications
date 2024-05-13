from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES

f=open("password.txt","r")
data=f.read().encode()
f.close()

#AES先
f=open("User.pem","rb")
AESkey=f.read()
f.close()

cipher=AES.new(AESkey,AES.MODE_EAX)
ciphertext,tag= cipher.encrypt_and_digest(data)

data1=cipher.nonce+b" "+tag+b" "+ciphertext
print(data1.split(b" "))

#RSA後
f1=open("SU_publicKey.pem","rb")
PublicKey=f1.read()
f1.close()

RSAkey_pub=RSA.import_key(PublicKey)
encrypt_cipher = PKCS1_OAEP.new(RSAkey_pub)
encrypt_data=encrypt_cipher.encrypt(data1)
data2=encrypt_data
print(data2)

#輸出
f=open("password.bin","wb")
f.write(data2)
f.close()

