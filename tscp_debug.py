#!/usr/bin/env micropython

# Alice is client, Bob is server.
# Alice intiate connection to Bob
# TLS1.3 style 1 turn-around session-key negotiation

import urandom as ran
from utime import ticks_ms
from CryptoXo import Crypt
try:
   from cryptolib import aes
except:
   aes=None
from binascii import hexlify as hexy, unhexlify as unhexy
from hashlib import sha256 as sha
# from hashlib import sha1 as sha # stm32 does not have sha1
import gc

ran.seed(ticks_ms())
rn=ran.getrandbits
gc.enable()


org="KAKI5-1-0-A"

class MDH():
   def __init__(my):
      my.G,my.Q,my.L,my.err=138831,29,24,'' # KAKI5-1-0-A (Org code)

   def get_P(my):
      p=0; 
      while p<101: p+=rn(4)
      pq=p**my.Q
      if len(str(pq))<my.L:
         pq+=(10*(my.L-1))
      P=int(str(pq)[:my.L])
      if P%my.G==0: #if 0 then both Ka and Kb will be 0
         P+=1
      return (p,P)

   def alice(my):  # protocol intiator 
      a=0 # Alice private key
      p,P=0,0
      cln_enc=cln_dec=None
      cln_id=srv_id=''
      def A(cs="oXo|AES"): # Alace hello request
         nonlocal a,p,P,cln_id
         rn=ran.getrandbits
         a_ses_id="C-%d-%d-%d"%(rn(4),rn(4),rn(6))
         cln_id=a_ses_id
         p,P=MDH.get_P(my)
         a=0; 
         while a<71: a+=rn(4)
         x=(my.G**a)%P # Alice public
         hs=b"Hello:%s:%s:%s:%d:%d"%(org,a_ses_id,cs,p,x) # handshake message
         del x
         gc.collect()
         print(hs)
         return hs
      def B(hs): # Bob hello reply
         nonlocal a,p,P,cln_enc,cln_dec,cln_id,srv_id
         srv_cs,srv_enc_ids,srv_y=hs.decode().split(':')[1:]
         # Secret key for Alice
         ka = ((int(srv_y))**a)%P  # (((G**b)%P)**a)%P --> (G**(b*a))%P
         cln_enc=crypt[srv_cs](ka, 'enc')
         cln_dec=crypt[srv_cs](ka, 'dec')
         del ka,P
         gc.collect()
         #decrypt srv_enc_id compare to srv_id to authenticate
         esids=unhexy(srv_enc_ids.encode())
         my_id, srv_id=cln_dec(esids).split(':')
         #print('Session ok?', my_id==cln_id, cln_id)
      def put(data):
         nonlocal cln_id,srv_id
         # Alice send - "from_id:to_id:data"
         a_dat="%s:%s:%s"%(cln_id,srv_id,data)
         h=sha();h.update(a_dat)
         dat=cln_enc(a_dat)
         msg=hexy(dat)+b':'+hexy(h.digest())
         print(msg)
         return msg
      def get(msg):
         try:
            print('SRV msg: %s'%msg)
            dat,dat_hash=msg.decode().split(':')
            print('Raw Data:%s'%dat)
            print('Hash: %s'%dat_hash)
            srv_dat=cln_dec(unhexy(dat))
            frm_id,to_id,get_dat=srv_dat.split(':')
            print('SRV data: %s:%s:%s'%(frm_id,to_id,get_dat))
            h=sha();h.update("%s:%s:%s"%(frm_id,to_id,get_dat))
            hv=h.digest()
            print('It hash: %s'%hexy(hv))
         except Exception as e:
            my.err=str(e)
            ok='!X'
            get_dat=''
         else:
            print('Alice:')
            print('   Client node authenticates?', cln_id==to_id, cln_id)
            print('   Server node authenticates?', srv_id==frm_id, srv_id)
            print('   Data hash ok?', hexy(hv)==dat_hash.encode())
            if cln_id!=to_id: ok='!C'
            elif srv_id!=frm_id: ok='!S'
            elif hexy(hv)!=dat_hash.encode(): ok='!H'
            else: ok='ok'
         return (ok,get_dat)
      return (A,B,put,get)

   def bob(my):  # protocol reply 
      b=0 # Bob private key
      srv_enc=srv_dec=None
      cln_id=srv_id=''
      def B(hs): # Bob hello reply
         nonlocal b,srv_enc,srv_dec,cln_id,srv_id
         rn=ran.getrandbits
         b_ses_id="S-%d-%d-%d"%(rn(4),rn(4),rn(6))
         b=int(str(rn(4))+str(rn(3)))
         while b<37: b+=rn(6)
         org_id,cln_id,cln_cs,cln_p,cln_x=hs.decode().split(':')[1:]
         pq=(int(cln_p))**my.Q
         if len(str(pq))<my.L:
            pq+=(13**(my.L-1))
         P=int(str(pq)[:my.L])
         del pq
         gc.collect()
         if P%my.G==0: #if 0 then both Ka and Kb will be 0
            P+=1
         # gets the generated key
         y = (my.G**b)%P
         kb = ((int(cln_x))**b)%P  # (((G**a)%P)**b)%P --> (G**(a*b))%P

         # cs='oXo' 
         csa=cln_cs.split('|')
         if 'AES' in csa:cs='AES'
         else: cs='oXo'
         # decrypt b_ses_id
         srv_enc=crypt[cs](kb, 'enc')
         srv_dec=crypt[cs](kb, 'dec')
         del kb,P
         gc.collect()
         srv_id=b_ses_id
         srv_enc_ids=srv_enc('%s:%s'%(cln_id,b_ses_id))
         hs=b"Hey:%s:%s:%d"%(cs,hexy(srv_enc_ids).decode(),y)
         del y
         gc.collect()
         print(hs)
         return hs
      def get(msg): # Bob get encrypted form Alice
         #nonlocal srv_dec,srv_id,cln_id
         try:
            dat,dat_hash=msg.decode().split(':')
            cln_dat=srv_dec(unhexy(dat))
            frm_id,to_id,get_dat=cln_dat.split(':')
            h=sha();h.update("%s:%s:%s"%(frm_id,to_id,get_dat))
            hv=h.digest()
         except Exception as e:
            my.err=str(e)
            ok='!X'
            get_dat=''
         else:
            print('Bob:')
            print('   Client node authenticates?', cln_id==frm_id, cln_id)
            print('   Server node authenticates?', srv_id==to_id, srv_id)
            print('   Data hash ok?', hexy(hv)==dat_hash.encode())
            if cln_id!=frm_id: ok='!C'
            elif srv_id!=to_id: ok='!S'
            elif hexy(hv)!=dat_hash.encode(): ok='!H'
            else: ok='ok'
         return (ok,get_dat)
      def put(msg): # Bob send encrypted to Alice
         nonlocal srv_enc,srv_id,cln_id
         b_dat="%s:%s:%s"%(srv_id,cln_id,msg)
         h=sha();h.update(b_dat)
         dat=srv_enc(b_dat)
         msg=hexy(dat)+b':'+hexy(h.digest())
         return msg

      return (B,get,put)

#----------------------------------------------------------

def oXo(k, mode=None):
   cry=Crypt(str(k))
   if mode=='enc':
      def encrypt(data):
          return cry.encrypt(data.encode())
      return encrypt
   elif mode=='dec':
      def decrypt(cip):
          return cry.decrypt(cip).decode()
      return decrypt
   else:
      return None

def AES(k, mode=None):
   ks=str(k)
   if len(ks)<32:
      ks=(ks*(int(32/len(ks))+1))[:32]
   else:
      ks=ks[:32]
   cry=aes(ks.encode(), 1)
   if mode=='enc':
      def encrypt(data):
          data=data+'\0'*(16-(len(data)%16)) # len(M)%16==0 is a MUST
          return cry.encrypt(data)
      return encrypt
   elif mode=='dec':
      def decrypt(cip):
          data=cry.decrypt(cip).decode()
          return data.replace('\0', '')
      return decrypt
   else:
      return None

if aes != None:
   crypt={'oXo': oXo, 'AES': AES}
else:
   crypt={'oXo': oXo, 'AES': None}

def Cln():
   return MDH().alice()

def Srv():
   return MDH().bob()

