
from tscp import Cln, Srv
import gc

srv_hs,srv_get,srv_put=Srv()  # one per channel/client

def test(msg):
   cln_hs,sesi,cln_put,cln_get=Cln() # new session each time
   # handskake
   h0=cln_hs('oXo')  # 'oXo', 'AES', 'oXo|AES'==default
   h1=srv_hs(h0)
   sesi(h1) # Hello exchange done, client calculates session ids and secret-key
   # Message exchange
   amsg=cln_put(msg)    # Alice send to Bob
   ok, amsg=srv_get(amsg)   # Bob get Alice message
   if ok:
      bmsg=amsg.upper() # Bob process the message form Alice
      bmsg=srv_put(bmsg)   # Bob send reply to Alice
      ok, msg=cln_get(bmsg)    # Alice get Bob reply
   del cln_hs,sesi,cln_put,cln_get
   gc.collect()
   return msg        # Alice process the reply form Bob

C=0
err=0
while C<2:
   print(C,'----------------------------------')
   msg0="This is the start of a beautiful day!"
   print(msg0)
   msg1=test(msg0)
   ok=msg0.upper()==msg1
   if ok:
      print(msg1)
   else:
      print(msg1, '!!')
      err+=1
   C+=1
print('# error:', err, 'in', C, 'tests')

