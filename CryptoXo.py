R='wb'
Q='rb'
P='None source or target file'
O=' get '
N=b'123'
L='Wrong type, need '
K='Empty data'
M='X'
I=isinstance
J=True
G=''
F=open
E=type
C=str
H=bytes
B=ValueError
D=len

def csum(m): # msg must be bytes array i.e b'123abc'
    m=b"%s"%m;l=len(m);s=0;v=13+l+m[0];i=0;d=1954**13;
    for c in m:i+=1;s+=v*(c*i);v=c
    if s<d:s=((d+l)//s)*1954
    return str(s%d).encode()

def S(F,mode,data):
        def S(C,D):return H([A^B for(A,B)in zip(C,D)])
	I=data;B=F.Z;X=F.X;E=0;N=D(I);K=H()
	while J:
		G=D(B)
		if E+G>N:C=I[E:]
		else:C=I[E:E+G]
		if C:
			L=S(C,B[:D(C)]);K+=L
			if mode==M:B=csum(X+B+C)
			else:B=csum(X+B+L)
		if D(C)<G:break
		else:E+=G
	return K
class Crypt:
	def __init__(B,X=G,blk=80):
		if X:B.X=csum(X)
		else:B.X=csum('Tgsf2kjf&MOtgeHs#34kk')
		B.Y=csum('gsfT5#dskiTRa12@7sDQa');
                B.Z=csum(B.X+B.Y)
	def key(B,X=G,Y=G):
		if X and Y: B.X=csum(X);B.Y=csum(Y);B.Z=csum(B.X+B.Y)
	def encrypt(D,A):
                if type(A)==type('str'):A=A.encode()
		if not A:raise B(K)
		if not I(A,H):raise B(L+C(E(N))+O+C(E(A)))
		return S(D,M,A)
	def decrypt(D,A):
		if not A:raise B(K)
		if not I(A,H):raise B(L+C(E(N))+O+C(E(A)))
		return S(D,'Y',A)
	def encrypt_file(I,source,target,blk=80):
		C=target;A=source
		if not(A and C):raise B(P)
		E=F(A,Q);G=F(C,R)
		while J:
			H=E.read(blk);G.write(I.encrypt(H))
			if D(H)<blk:break
		G.close();E.close()
	def decrypt_file(I,source,target,blk=80):
		C=target;A=source
		if not(A and C):raise B(P)
		E=F(A,Q);G=F(C,R)
		while J:
			H=E.read(blk);G.write(I.decrypt(H))
			if D(H)<blk:break
		G.close();E.close()
