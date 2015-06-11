from basic import *
from random import randint

def pad(s,blocklength):
    num=blocklength-(len(s)%blocklength)
    if len(s)%blocklength==0:
        return s
    else:
        return s + "".join([chr(num)]*(num))

def encryptCBCAES(k,s,iv):
    ctext=""
    blocks=splitblocks(s,16)
    for block in blocks:
        t=xorstrings(block,iv)
        temp=encryptECBAES(k,t)
        ctext+=temp
        iv=temp
    return ctext

def decryptCBCAES(k,s,iv):
    plaintext=""
    blocks=splitblocks(s,16)
    for block in blocks:
        temp=decryptECBAES(k,block)
        plaintext+=xorstrings(temp,iv)
        iv=block
    return plaintext

def randomkey(keysize):
    return "".join([chr(randint(0,255)) for x in xrange(keysize)])

def randomencrypt(s):
    key=randomkey(16)
    cbefore=randint(5,10)
    cafter=randint(5,10)
    news=randomkey(cbefore)+s+randomkey(cafter)
    news=pad(news,16)
    x=randint(0,1)
    if x==0:
        out=encryptECBAES(key,news)
        print "Chose ECB"
    else:
        out=encryptCBCAES(key,news , randomkey(16))
        print "Chose CBC"
    return out

def ECBorCBCoracle(blackbox):
    lenblock=16
    samecount=0
    c=blackbox("".join([chr(0)]*128))
    for i in xrange(len(c)/lenblock):
           for j in xrange(i+1,(len(c)/lenblock)):
                if c[i*lenblock:(i+1)*lenblock] == c[j*lenblock:(j+1)*lenblock]:
                    samecount+=1
    if samecount>0:
        return "ECB"
    else:
        return "CBC"

def findblocksize(blackbox,key, limit):
    prevval=""
    for bs in xrange(2,limit):
        ct=blackbox(key,"A"*bs)
        if ct[:bs-1]==prevval:
            return bs-1
        else:
            prevval=ct[:bs]
    return None

def unpad(s):
    n=s[-1:]
    i=ord(n)
    if all(map(lambda x: x==n, s[-i:])):
        return s[:-i]
    else:
        return s
    
def repeatECB(key,s):
    appends=b642ascii("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    s=s+appends
    s=pad(s,16)
    out=encryptECBAES(key,s)
    return out

def padoracle(blackbox,blocksize,totalbytes,key):
    outs=[]
    knownletters=[]
    for b in xrange(totalbytes/blocksize):
        o=""
        for byte in xrange(1,blocksize+1):
            onebyteshort=blackbox(key, "A"*((blocksize-byte)))
            d=createdict(blackbox,key,blocksize,curblock=b,byte=byte,knownletters=knownletters)
            #print d
            try: #TODO: Hack for last byte
                knownletters.append(d[onebyteshort[b*blocksize:(b+1)*blocksize]])
                o+=d[onebyteshort[b*blocksize:(b+1)*blocksize]]
            except:
                pass
           # print o, b
        outs.append(o)
       #print outs,b
    return "".join(outs)

def createdict(blackbox, key,blocksize,curblock=0,byte=1,knownletters=[], offset=0):
    d={}
    z=curblock*blocksize
    for a in xrange(0,128):
        d[blackbox(key,("A"*((blocksize-byte)))+"".join(knownletters)+chr(a))[z:z+blocksize]]=chr(a)
    #print ("A"*((blocksize-byte)))+"".join(knownletters)+chr(a)
    return d

def newECBorCBCoracle(key,lenblock,blackbox):
    samecount=0
    c=blackbox(key,"".join([chr(0)]*128))
    for i in xrange(len(c)/lenblock):
           for j in xrange(i+1,(len(c)/lenblock)):
                if c[i*lenblock:(i+1)*lenblock] == c[j*lenblock:(j+1)*lenblock]:
                    samecount+=1
    if samecount>0:
        return "ECB"
    else:
        return "CBC"

#Q13
#foo=bar&baz=qux&zap=zazzle
def parse2dict(s):
    d={}
    s=s.split("&")
    for item in s:
        t=item.split("=")
        d[t[0]]=t[1]
    return d

#6,X,5,10 - 3 blocks
def profile_for(key,email):
    #global uid
    uid=1
    email=email.strip("&=")
    email=email.replace("&","")
    email=email.replace("=","")
    s="email="+str(email)+"&uid="+str(uid)+"&role=user"
    n=16
    line =s
    #print [line[i:i+n] for i in range(0, len(line), n)]
    news=pad(s,16)
    out=encryptECBAES(key,news)
    #uid+=1
    return out

def create_profile(key,ct):
    out=decryptECBAES(key,ct)
    out=unpad(out)
    #print(out)
    #print ':'.join(x.encode('hex') for x in out)
    d=parse2dict(out)
    return d

#Q14
def myoracle(key,attack):
    global rprefix
    return encryptECBAES(key,pad(rprefix+attack+"decryptme",16))

import numpy as np

def wherearewe(blackbox, key):
    #return offset to block
    pastblocks=np.zeros(16)
    blocksnoinput = splitblocks(blackbox(key,""), 16)
    blocksonebyte=splitblocks(blackbox(key,"A"), 16)
    #numsameorig=np.sum(np.array(blocksnoinput)==np.array(blocksonebyte))
    numsameorig=len(set(blocksnoinput).intersection(set(blocksonebyte)))
    for b in xrange(1,18):
        blocks = splitblocks(blackbox(key,"A"*b), 16)
        #numsame=np.sum(np.array(blocksnoinput)==np.array(blocks))
        numsame=len(set(blocks).intersection(set(pastblocks)))
        if numsame>numsameorig:
            return ((b-1)%16, np.max(np.where(np.array(blocks[:len(pastblocks)])==np.array(pastblocks)) ))
        pastblocks=blocks
    return None


def newcreatedict(blackbox, key,blocksize,curblock=0,byte=1,knownletters=[], offset=0):
    d={}
    z=(curblock*blocksize)
    #print z, z+blocksize, byte
    #print ascii2hex(blackbox(key,("A"*((blocksize-1)+offset))+"&"))
    #print ':'.join(x.encode('hex') for x in blackbox(key,("A"*((blocksize-2)+offset))+"=u")[16:32])
    for a in xrange(0,128):
        #print ("A"*((blocksize-byte)))+"".join(knownletters)+chr(a)
        d[blackbox(key,("A"*((blocksize-byte)+offset))+"".join(knownletters)+chr(a))[z:z+blocksize]]=chr(a)
    #print ("A"*((blocksize-byte)))+"".join(knownletters)+chr(a)
    return d


def newpadoracle(blackbox,blocksize,totalbytes,key, offset=0, ourblock=0):
    outs=[]
    knownletters=[]
    for b in xrange((ourblock+1),(totalbytes/blocksize)+1):
        o=""
        for byte in xrange(1,blocksize+1):
            #print b,byte,offset,blocksize,((blocksize-byte)+offset)
            #print b*blocksize, (b+1)*blocksize
            #print blackbox(key, "A"*((blocksize-1)+offset))
            #print ':'.join(x.encode('hex') for x in blackbox(key, "A"*((blocksize-2)+offset)+"=")[16:32])

            onebyteshort=blackbox(key, "A"*((blocksize-byte)+offset))
            d=newcreatedict(blackbox,key,blocksize,curblock=b,byte=byte,knownletters=knownletters, offset=offset)
            #print d
            #print d
            try: #TODO: Hack for last byte
                knownletters.append(d[onebyteshort[b*blocksize:(b+1)*blocksize]])
                o+=d[onebyteshort[b*blocksize:(b+1)*blocksize]]
                #print o
            except Exception as e:
                #print e
                pass
           # print o, b
        outs.append(o)
       #print outs,b
    return "".join(outs)

#Q15

class MyException(Exception):
    pass

def unpad2(s):
    n=s[-1:]
    i=ord(n)
    if all(map(lambda x: x==n, s[-i:])):
        return s[:-i]
    else:
        raise MyException("Bad Padding!")

#Q16
import string
def f1(s,key,iv):
    s=s.replace("=","")
    s=s.replace("&","")
    s=s.replace(";","")
    news = pad("comment1=cooking%20MCs;userdata=" + s + ";comment2=%20like%20a%20pound%20of%20bacon", 16)
    return encryptCBCAES(key,news, iv)

def f2(s,key,iv):
    s=decryptCBCAES(key,s,iv)
    #print s
    #print [s[i:i+16] for i in range(0, len(s), 16)]
    if string.find(s,";admin=true;")!=-1:
        return (True,s)
    else:
        return (False,s)


if __name__=='__main__':
    #Q9
    print "Q9"
    print ascii2hexstring(pad("YELLOW SUBMARINE",20))
    #Q10
    print "Q10"
    ct=""
    f=open("blockcrypto/10.txt","r")
    for line in f:
        ct+=line.strip()
    f.close()
    ct=b642ascii(ct)
    #print decryptCBCAES("YELLOW SUBMARINE", ct, "".join([chr(0)]*16))
    #Q11
    print "Q11"
    print ECBorCBCoracle(randomencrypt)
    #Q12
    print "Q12"
    globalkey=randomkey(16)
    blocksize=findblocksize(repeatECB, globalkey,256)
    print "Blocksize: " + str(blocksize)
    print newECBorCBCoracle(globalkey,16,repeatECB)
    hiddenlength= len(repeatECB(globalkey,""))
    out=padoracle(repeatECB,blocksize,hiddenlength,globalkey)
    print unpad(out)==b642ascii("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    #Q13
    print "Q13"
    #assuming we know plain-text form apriori
    globalkey=randomkey(16)
    uid=1
    ct1=profile_for(globalkey,"AAA@AA.COMadmin"+("\x0B"*11))
    ct2=profile_for(globalkey,"AAAAAAAA@A.COM")
    ct3=ct2
    ct4=ct2[:32]+ct1[16:32]
    print create_profile(globalkey,ct4)
    #Q14
    print "Q14"
    globalkey=randomkey(16)
    import random
    rcount=random.randint(1,64)
    rprefix=randomkey(rcount)
    (offset,ourblock) =wherearewe(myoracle,globalkey)
    lengthprefix = (ourblock)*16 + (16-offset)
    print "Prefix length: " + str(lengthprefix)
    print "Message: "
    print unpad(newpadoracle(myoracle, 16,len(myoracle(globalkey,"")), globalkey, offset=offset, ourblock=ourblock ))
    #Q15
    print "Q15"
    print unpad2("ICE ICE BABY\x04\x04\x04\x04")
    try:
        print unpad2("ICE ICE BABY\x05\x05\x05\x05")
    except Exception as e:
        print e

    try:
        print unpad2("ICE ICE BABY\x01\x02\x03\x04")
    except Exception as e:
        print e

    #Q16
    print "Q16"
    globalkey=randomkey(16)
    iv = randomkey(16)
    test=f1("AadminAtrue", globalkey, iv)
    test=test[:16]+chr(ord("A")^ord(";")^ord(test[16])) + test[17:]
    test=test[:16+6] + chr(ord("A")^ord("=")^ord(test[16+6])) + test[16+7:]
    print f2(test,globalkey,iv)
