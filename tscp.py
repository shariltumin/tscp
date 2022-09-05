X=b'%s:%s:%s'
W='%s:%s:%s'
R=Exception
U='oXo'
P='dec'
O='enc'
K='AES'
J=''
I=len
G=':'
D=int
B=None
A=str
import urandom as S
from utime import ticks_ms as L
from CryptoXo import Crypt
try:from cryptolib import aes as E
except:E=B
from binascii import hexlify as T,unhexlify as N
import gc as F
S.seed(L())
F.enable()
V='KAKI5-1-0-A'
def csum(m):
	D=I(m);B=0;E=17+D+m[0];F=0;C=1954**7
	for G in m:F+=1;B+=E*(G*F);E=G
	if B<C:B=(C+D)//B*1954
	return A(B%C).encode()
class C:
	def __init__(A):A.G,A.Q,A.L,A.M,A.err=11,73,32,3,J
	def alice(C):
		H=0;E=0;Q=M=B;K=L=J
		def U(cs='oXo|AES'):
			nonlocal H,E,K;B=S.getrandbits;L='C-%d-%d-%d'%(B(4),B(4),B(6));K=L;G=D(A(B(4))+A(B(8)))
			while G<70:G+=B(8)
			J=G**C.Q
			if I(A(J))<C.L:J+=13*(C.L-1)
			E=D(A(J)[:C.L]);del J;F.collect()
			if E%C.G==0:E+=1
			H=D(A(B(4))+A(B(3)))
			while H<29:H+=B(6)
			M=C.G**H%E;N=b'Hello:%s:%s:%s:%d:%d'%(V,L,cs,G+C.M**2,M*C.M);del M;F.collect();return N
		def Y(hs):nonlocal H,E,Q,M,K,L;B,I,J=hs.decode().split(G)[1:];A=(D(J)//C.M)**H%E;Q=crypto[B](A,O);M=crypto[B](A,P);del A,E;F.collect();R=N(I.encode());S,L=M(R).split(G)
		def Z(data):nonlocal K,L;A=W%(K,L,data);B=csum(A.encode());C=Q(A);D=T(C)+b':'+B;return D
		def a(msg):
			try:H,I=msg.decode().split(G);O=M(N(H));E,F,D=O.split(G);P=csum(X%(E,F,D))
			except R as Q:C.err=A(Q);B='!X';D=J
			else:
				if K!=F:B='!C'
				elif L!=E:B='!S'
				elif P!=I.encode():B='!H'
				else:B='ok'
			return B,D
		return U,Y,Z,a
	def bob(C):
		E=0;L=V=B;H=M=J
		def Q(hs):
			nonlocal E,L,V,H,M;J=S.getrandbits;X='S-%d-%d-%d'%(J(4),J(4),J(6));E=D(A(J(4))+A(J(3)))
			while E<37:E+=J(6)
			e,H,Z,a,b=hs.decode().split(G)[1:];Q=(D(a)-C.M**2)**C.Q
			if I(A(Q))<C.L:Q+=13**(C.L-1)
			N=D(A(Q)[:C.L]);del Q;F.collect()
			if N%C.G==0:N+=1
			Y=C.G**E%N;W=(D(b)//C.M)**E%N;R=U;c=Z.split('|')
			if K in c:
				if crypto[K]!=B:R=K
			L=crypto[R](W,O);V=crypto[R](W,P);del W,N;F.collect();M=X;d=L('%s:%s'%(H,X));hs=b'Hey:%s:%s:%d'%(R,T(d).decode(),Y*C.M);del Y;F.collect();return hs
		def Y(msg):
			try:I,K=msg.decode().split(G);L=V(N(I));E,F,D=L.split(G);O=csum(X%(E,F,D))
			except R as P:C.err=A(P);B='!X';D=J
			else:
				if H!=E:B='!C'
				elif M!=F:B='!S'
				elif O!=K.encode():B='!H'
				else:B='ok'
			return B,D
		def Z(msg):A=msg;nonlocal L,M,H;B=W%(M,H,A);C=csum(B.encode());D=L(B);A=T(D)+b':'+C;return A
		return Q,Y,Z
def H(k,mode=B):
	C=Crypt(A(k))
	if mode==O:
		def D(data):
			A=data
			if type(A)==type('str'):A=A.encode()
			return C.encrypt(A)
		return D
	elif mode==P:
		def E(cip):return C.decrypt(cip).decode()
		return E
	else:return B
def M(k,mode=B):
	G='\x00';C=A(k)
	if I(C)<32:C=(C*(D(32/I(C))+1))[:32]
	else:C=C[:32]
	F=E(C.encode(),1)
	if mode==O:
		def H(data):A=data;A=A+G*(16-I(A)%16);return F.encrypt(A)
		return H
	elif mode==P:
		def K(cip):A=F.decrypt(cip).decode();return A.replace(G,J)
		return K
	else:return B
crypto={}
if E!=B:crypto={U:H,K:M}
else:crypto={U:H,K:B}
def Cln():return C().alice()
def Srv():return C().bob()