def ROTL8(v,n):
    return (((v<<n)&0xff) | ((v>>(8-n))&0xff))
def ROTL16(v,n):
    return (((v<<n)&0xffff) | ((v>>(16-n))&0xffff))
def ROTL32(v,n):
    return (((v<<n)&0xffffffff) | ((v>>(32-n))&0xffffffff))
def ROTL64(v,n):
    return (((v<<n)&0xffffffffffffffff) | ((v>>(64-n))&0xffffffffffffffff)) 
def ROTR8(v,n):
    return ROTL(V,8-n)
def ROTR16(v,n):
    return ROTL(V,16-n)
def ROTR32(v,n):
    return ROTL(V,32-n)
def ROTR64(v,n):
    return ROTL(V,64-n)
def SWAP32(v):
    return ((ROTL32(v,8)&0x00ff00ff) | (ROTL32(v,24)&0xff00ff00));
class Rabbit_state(object):
    def __init__(self):
        self.x=[0]*8
        self.c=[0]*8
        self.carry=0

class Rabbit_ctx(object):
    def __init__(self):
        self.m=Rabbit_state()
        self.w=Rabbit_state()

