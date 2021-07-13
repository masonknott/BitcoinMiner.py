from Crypto.PublicKey import RSA
from hashlib import sha512, sha256
import random
import itertools

def generateRSAKeys(numBits):
    keyPair = RSA.generate(numBits)

    return keyPair

def digitalSignRSA(msg, keyPairRSA):

    hashValue = int.from_bytes(sha256(msg).digest(), byteorder='big')
    
    signature = pow(hashValue, keyPair.d, keyPair.n)
    
    return(hashValue, signature)


def checkOneNonce(numZerosNeeded, nonce):

    # Note that hash function sha256 accepts input of type byte.
    # so we convert random number nonce to a byte array nByte
    #convert the random integer to a byte array
    nByte = bytes(str(nonce), 'utf-8')

    # compute the hash of the nonce
    hash = int.from_bytes(sha256(nByte).digest(), byteorder='big')

    # convert the hash value to binary number and extract the needed LSBs.
    hashBin = bin(hash) 
    hashLSB = int(hashBin[-numZerosNeeded:]) 
  #  validity = (hashLSB == 0)


    while True:
        validity = (hashLSB == 0)
        if nonce != validity:
         nonce = random.randint(0, 1000000)
         if nonce == validity:
             validity = True
             break
             
    return(validity)


numBits = 1024
keyPair = generateRSAKeys(numBits)
print("Public key:  n={", hex(keyPair.n), "}, e={", hex(keyPair.e), "})")
print('  ')
print("Private key: n={", hex(keyPair.n), "}, d={", hex(keyPair.d), "})")
print('  ')



numZerosNeeded = 5
nonce = random.randint(0,1000000)


msg = bytes('A message for signing', 'utf-8')
(hashValue, signature) = digitalSignRSA(msg, keyPair)
print("Hash value of message:", hashValue)
print("Signature:", hex(signature))
print('  ')

validity = checkOneNonce(numZerosNeeded, nonce)
print('The validity of this nonce ',nonce, ' is:', validity)
print('================================================================  ')




