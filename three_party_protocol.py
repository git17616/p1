
from charm.toolbox.pairinggroup import PairingGroup, G1, G2,GT, ZR, pair
from charm.toolbox.pairinggroup import GT
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
#from waters09 import Waters09FromID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
from eccp import ecc_encrypt
from eccp import ecc_decrypt
from aesed import aes_encrypt
from aesed import aes_decrypt
import json
from Cryptodome.Random import get_random_bytes
import hashlib
from hashlib import sha256



##################################################################################3General Values ///////////////////////////

# 1. Initialize pairing group
group = PairingGroup('SS512')                  

# 2. Fixed generator g in G2
g = group.hash("fixed generator", G1)             #############  g value
#print("g",g)

# 3. Fixed master secret alpha
alpha = group.hash("fixed-alpha value is storedfixe-alpha value is stored", ZR)             ############  alpha value 

#print("alpha",alpha)

########t11 =  group.hash("fixed alpha", ZR)              ############ time t1
#########t = g ** t11   




# 4. Public key = g^alpha
g_alpha = g ** alpha                              ############## g^apha
#print("g^alpha1",g_alpha)

# 5. Set up mpk and msk manually
mpk = {'g': g, 'g_alpha': g_alpha}               ############### to print  print("g:", mpk['g'])  print("g_alpha:", mpk['g_alpha']) 
msk = {'alpha': alpha}
 


# 6. Identity of user
id_p = "patient@example.com"
id_pr = "proxy@example.com"
id_TT = "TT@example.com"
id_D = "Doctor@example.com"



# 7. Hash identity to G1 (Q_id)
pk_idp = group.hash(id_p, G1)
pk_idpr = group.hash(id_pr, G1)
pk_idTT = group.hash(id_TT, G1)
pk_idD = group.hash(id_D, G1)
#print("pk_idD",pk_idD)

# 8. Private key = Q_id^alpha (in G1), same as ibe.extract
sk_idp = pk_idp ** alpha
sk_idpr = pk_idpr ** alpha
sk_idTT = pk_idTT ** alpha
sk_idD = pk_idD ** alpha



# Patient data and key and encryption
md = b"aes medical data This is my medical data1"    #  patient message                  
   ###  key  Make sure the key is 16, 24, or 32 bytes long for AES-128, 192, or 256   
print("Original medical data=================",md) 
print(type(md))


# key (16 bytes → AES-128)
key = get_random_bytes(32)
# create cipher
cipher = AES.new(key, AES.MODE_EAX)

# encrypt
ciphertext, tag = cipher.encrypt_and_digest(md)

print("Ciphertext:", ciphertext)
cipher_dec = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
plaintext = cipher_dec.decrypt(ciphertext)

print("Decrypted:", plaintext)

################################################################################################NON EMERGENCY***********************

##############################################################   Patient private keys

hthumb = group.hash("hthumb-constant", ZR)
combined = sha256(group.serialize(hthumb) + id_p.encode()).digest()
alpha_bytes = group.serialize(alpha)
y = group.hash(alpha_bytes + combined, ZR)

##############################################################   patient keys 




##############################################################  Patient tconstant values derived

lamda = group.random(GT)
row = group.random(GT)
print("lamda",lamda)
################## to find v1 =hash(lamda || m)

lambda_bytes = group.serialize(lamda)
v1= group.hash(md + lambda_bytes , ZR)
################## to find r1 =hash(row || key)

row_bytes = group.serialize(row)       
r1= group.hash(key + row_bytes , ZR)
############################################################## patient tconstant values derived




#################################################################### Patient to Proxy(CIPHER)


#####C1,C2,C3


C1 = g ** y
C2 = g ** v1
C3 = lamda * pair (g ** alpha, (pk_idp ** y) * (pk_idpr ** (v1 * hthumb)))

#check1 = C3 /((pair (g ** alpha, (pk_idp ** y))) * pair (g ** alpha, (pk_idpr ** (v1 * hthumb))))

#print("lamda check",check1)

###################  C4 =Hash(lamda) xor c

h = hashlib.sha256(lambda_bytes).digest()
h_full = (h * (len(ciphertext)//len(h) + 1))[:len(ciphertext)]
C4 = bytes(x ^ y for x, y in zip(ciphertext, h_full))
print(type(C4))

###recover step 
'''
result = bytes(x ^ y for x, y in zip(C4, h_full))
print("Recovered Ciphertext:", result)
'''
############################### C5 =0
C5 = group.init(ZR, 0)


###############################  H(id_dr|| C1,C2,C3,C4,C5)^v1 ------------------NOT USED 

id_pr = "proxy@example.com".encode()
data = id_pr \
     + group.serialize(C1) \
     + group.serialize(C2) \
     + group.serialize(C3) \
     + C4 \
     + group.serialize(C5)

H = group.hash(data, G1)

# Step 3: exponentiate
S1= H ** v1

print("Result:", S1)     

#########################################################################Patient Sends CT1 = (S1,C1,C2,C3,C4,C5) to Proxy

################################################################################Patient to TT(KEY) //////////////////////////

################### C1kp,C2kp,C3kp


C1kp = g ** y
C2kp = g ** r1
C3kp = row * pair (g ** alpha, (pk_idp ** y) * (pk_idTT ** (r1 * hthumb)))

###################  C4 =Hash(row ) xor key

hashrow = hashlib.sha256(row_bytes).digest()
hrow_full = (hashrow * (len(key)//len(hashrow) + 1))[:len(key)]
C4kp = bytes(x ^ y for x, y in zip(key, hrow_full))
print(type(C4kp))

####################check
resultx = bytes(x ^ y for x, y in zip(C4kp, hrow_full))
print("Recovered Ciphertext:", resultx)

print(key)
########################

############################### C5kp =0
C5kp = group.init(ZR, 1)
###############################  S2 = H(id_TT|| C1kp,C2kp,C3kp,C4kp,C5kp)^r1--------------NOT USED

id_TT = "TT@example.com".encode()
data = id_TT \
     + group.serialize(C1kp) \
     + group.serialize(C2kp) \
     + group.serialize(C3kp) \
     + C4kp \
     + group.serialize(C5kp)

H2 = group.hash(data, G1)

# Step 3: exponentiate
S2= H2 ** r1

print("Result:", S2)     

############################################################### Patient Sends CT2 = (S2,C1kp,C2kp,C3kp,C4kp,C5kp) to TT




#############################################################################        EMERGENCY***********************


################################################################# TT party when it receives request
yD = group.random(ZR)
r = group.random(ZR)  
N = group.random(ZR) 
A = group.random(GT) 
HashA = group.hash(A, G1)
R1 = C1
R2 = g ** r
R3 = pair(g **(alpha * yD), pk_idD ** r) * A
R4 = pair (g ** y, sk_idp * HashA)
R5 = group.init(ZR, 1)

id_D = "Doctor@example.com".encode()
data1 = id_D  \
     + group.serialize(R1)  \
     + group.serialize(R2) \
     + group.serialize(R3) \
     + group.serialize(R4) \
     + group.serialize(R5)

H1 = group.hash(data1, G1)

# Step 3: exponentiate
SR1= H1 **(r * hthumb) 

#####################################################################TT sends (SR1,R1,R2,R3,R4,R5) to Proxy


########################################################################## Proxy receives (SR1,R1,R2,R3,R4,R5)///////////////////////
###### verify the integrity

id_D = "Doctor@example.com".encode()
data1p = id_D  \
     + group.serialize(R1)  \
     + group.serialize(R2) \
     + group.serialize(R3) \
     + group.serialize(R4) \
     + group.serialize(R5)

H1p = group.hash(data1, G1)

# Step 3: exponentiate
SR1p= H1 **(hthumb)

check1p = pair (g,SR1)
check2p = pair (R2,SR1p)
if check1p == check2p:
    print("key verified by Proxy")


N= group.random(GT)
#HashN = group.hash(A, G1)

k_full = hashlib.shake_256(group.serialize(N)).digest(len(C4))
C4new = bytes(x ^ y for x, y in zip(C4, k_full))


#### Decryption
'''
k_full1 = hashlib.shake_256(group.serialize(N)).digest(len(C4new))
resultci = bytes(x ^ y for x, y in zip(C4new, k_full1))

#print("C4",C4)

#print("resultci",resultci)
'''
##################

C3new = C3/ (R4 *pair (C2 , (sk_idpr ** (hthumb))))
print(C3new)




#################S1NEW
N_bytes = group.serialize(N)
digest = hashlib.sha256(N_bytes).digest()

N_zr = group.hash(digest, ZR)
id_D = "Doctor@example.com".encode()
data11 = id_D  \
     + group.serialize(C1)  \
     + group.serialize(C2) \
     + group.serialize(C3new) \
     + C4new \
     + group.serialize(C5) \
     + group.serialize(R2) \
     + group.serialize(R3)

H11 = group.hash(data11, G1)

# Step 3: exponentiate
S1new= H11 **(N_zr) 


####################################################################Prxy sends to doctor sends (S1new,C1,C2,C3new,C4new,C5,(R2,R3))






##################################################################### TT preparing REKEY and key cipher/////////////////////////
########## TT party when it receives request

rdash = group.random(ZR)  
B = group.random(GT) 
HashB = group.hash(B, G1)
R1dash = C1kp
R2dash = g ** rdash
R3dash = pair(g **(alpha * yD), pk_idD ** rdash) * B
R4dash = pair (g ** y, sk_idp * HashB)
R5dash = group.init(ZR, 1)

#C3kp = row * pair (g ** alpha, (pk_idp ** y) * (pk_idTT ** (r1 * hthumb)))
C3kpnew = C3kp/ (R4dash * pair (C2kp , (sk_idTT ** (hthumb))))
#C3kpnew = C3kp/ (R4dash * pair (g ** alpha , (pk_idTT ** (r1 * hthumb))))
print("C3kpnew",C3kpnew )

id_D = "Doctor@example.com".encode()
datap33 = id_D  \
     + group.serialize(C1kp)  \
     + group.serialize(C2kp) \
     + group.serialize(C3kpnew) \
     + C4kp \
     + group.serialize(C5kp) \
     + group.serialize(R2dash) \
     + group.serialize(R3dash)

Hp33 = group.hash(datap33, G1)

# Step 3: exponentiate
S2new= Hp33 **(hthumb) 


########################################################################TT sends to doctor sends (S2new,C1kp,C2kp,C3kpnew,C4kp,C5kp,R2dash,R3dash)


######################################################################## Doctor Decryption////////////////////////////////

############################## Doctor to get Cipher receives (S1new,C1,C2,C3new,C4new,C5,(R2,R3))

############ verify

N_bytes1 = group.serialize(N)
digest1 = hashlib.sha256(N_bytes1).digest()
N_zr1 = group.hash(digest1, ZR)
id_D = "Doctor@example.com".encode()
datap1 = id_D  \
     + group.serialize(C1)  \
     + group.serialize(C2) \
     + group.serialize(C3new) \
     + C4new \
     + group.serialize(C5) \
     + group.serialize(R2) \
     + group.serialize(R3)

Hp1 = group.hash(datap1, G1)

# Step 3: exponentiate
S1newp= Hp1 **(N_zr1) 


if S1newp== S1new:
    print("Doctot verified the cipher received")






#R3 = pair(g **(alpha * yD), pk_idD ** r) * A

Anew = R3 /pair(R2 ** yD, sk_idD)   ######## first finds A 
#print("Anew",Anew)
HashAnew = group.hash(Anew, G1)     #######finds the hash of A
lamdanew = C3new * pair(C1,HashAnew)   #########finds the lamda'
#print("lamdanew",lamdanew)



k_full1 = hashlib.shake_256(group.serialize(N)).digest(len(C4new))  ####### finds  k_full1= Hash N
resultci = bytes(x ^ y for x, y in zip(C4new, k_full1))     ########## resultci =C4' xor hash N

print("C4",C4)

print("resultci",resultci)
lambdanew_bytes = group.serialize(lamdanew)
h1 = hashlib.sha256(lambdanew_bytes).digest()     ###########hash of lamda
h_full22 = (h1 * (len(resultci)//len(h1) + 1))[:len(resultci)] 
Ciphernew = bytes(x ^ y for x, y in zip(resultci, h_full22))   ########### c' = resultci xor hash lamda
print("Ciphernew",Ciphernew)

##################################################



###############################Doctor to get key

############verify
id_D = "Doctor@example.com".encode()
datap34 = id_D  \
     + group.serialize(C1kp)  \
     + group.serialize(C2kp) \
     + group.serialize(C3kpnew) \
     + C4kp \
     + group.serialize(C5kp) \
     + group.serialize(R2dash) \
     + group.serialize(R3dash)

Hp34 = group.hash(datap34, G1)

# Step 3: exponentiate
S2new34= Hp34 **(hthumb) 


if S2new34== S2new:
    print("Doctot verified the key cipher")




Bnew = R3dash /pair(R2dash ** yD, sk_idD)   ######## first finds A 
print("Bnew",Bnew)
print("B",B)
HashBnew = group.hash(Bnew, G1)     #######finds the hash of A
rownew = C3kpnew * pair(C1kp,HashBnew)   #########finds the lamda'
print("rownew",rownew)
print("row",row)

rownew_bytes = group.serialize(row)

hashrow = hashlib.sha256(rownew_bytes).digest()
hrow_full = (hashrow * (len(C4kp)//len(hashrow) + 1))[:len(C4kp)]
keynew = bytes(x ^ y for x, y in zip(C4kp,hrow_full))

print(keynew)
##############################



########################### final decryption

################### decryption with key
cipher_dec1 = AES.new(keynew, AES.MODE_EAX, nonce=cipher.nonce)
Ciphernewmd= cipher_dec1.decrypt(Ciphernew)
print("patient medical data ===================",Ciphernewmd)



