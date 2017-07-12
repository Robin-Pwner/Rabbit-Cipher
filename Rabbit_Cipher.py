from Rabbit_Util import *


class Rabbit(object):
    def __init__(self,key,iv):
        self.ctx=Rabbit_ctx();
        self.set_key(key);
        if(len(iv)):
          self.set_iv(iv);
        
    def g_func(self,x):
        x=x&0xffffffff
        x=(x*x)&0xffffffffffffffff
        result=(x>>32)^(x&0xffffffff)
        return result
    def set_key(self,key):
        #generate four subkeys
        key0=int(key[0:4][::-1].encode("hex"),16)
        key1=int(key[4:8][::-1].encode("hex"),16)
        key2=int(key[8:12][::-1].encode("hex"),16)
        key3=int(key[12:16][::-1].encode("hex"),16)
        s=self.ctx.m
        #generate initial state variables
        s.x[0]=key0
        s.x[2]=key1
        s.x[4]=key2
        s.x[6]=key3
        s.x[1]=((key3<<16)&0xffffffff)|((key2>>16)&0xffff)
        s.x[3]=((key0<<16)&0xffffffff)|((key3>>16)&0xffff)
        s.x[5]=((key1<<16)&0xffffffff)|((key0>>16)&0xffff)
        s.x[7]=((key2<<16)&0xffffffff)|((key1>>16)&0xffff)
        #generate initial counter values
        s.c[0]=ROTL32(key2,16)
        s.c[2]=ROTL32(key3,16)
        s.c[4]=ROTL32(key0,16)
        s.c[6]=ROTL32(key1,16)
        s.c[1]=(key0&0xffff0000) | (key1&0xffff)
        s.c[3]=(key1&0xffff0000) | (key2&0xffff)
        s.c[5]=(key2&0xffff0000) | (key3&0xffff)
        s.c[7]=(key3&0xffff0000) | (key0&0xffff)
        s.carry=0

          #Iterate system four times
        for i in range(4):
            self.next_state(self.ctx.m);
           
        for i in range(8):
        #modify the counters
            self.ctx.m.c[i]^=self.ctx.m.x[(i+4)&7]
        #Copy master instance to work instance
        self.ctx.w=self.copy_state(self.ctx.m)
        
    def copy_state(self,state):
        n=Rabbit_state()
        n.carry=state.carry
        
        for i,j in enumerate(state.x):
            n.x[i]=j
        for i,j in enumerate(state.c):
            n.c[i]=j
        return n
    def set_iv(self,iv):
        #generate four subvectors
        v=[0]*4
        v[0]=int(iv[0:4][::-1].encode("hex"),16)
        v[2]=int(iv[4:8][::-1].encode("hex"),16)
        v[1]=(v[0]>>16) |(v[2]&0xffff0000)
        v[3]=((v[2]<<16) |(v[0]&0x0000ffff))&0xffffffff
        #Modify work's counter values
        for i in  range(8):
            self.ctx.w.c[i]=self.ctx.m.c[i]^v[i&3]
        #Copy state variables but not carry flag
        tmp=[]
        
        for cc in self.ctx.m.x:
            tmp+=[cc]
        self.ctx.w.x=tmp   
       
        #Iterate system four times
        for i in range(4):
            self.next_state(self.ctx.w);
        

 
    def next_state(self,state):
        g=[0]*8
        x=[0x4D34D34D, 0xD34D34D3, 0x34D34D34]
        #calculate new counter values
        for i in range(8):
            tmp=state.c[i]
            state.c[i]=(state.c[i]+x[i%3]+state.carry)&0xffffffff
            state.carry=(state.c[i]<tmp)
        #calculate the g-values
        for i in range(8):
            g[i]=self.g_func(state.x[i]+state.c[i])
        #calculate new state values
        
        j=7
        i=0
        while(i <8):
            state.x[i]=(g[i] + ROTL32(g[j], 16) + ROTL32(g[j-1], 16))&0xffffffff
            i+=1
            j+=1
            state.x[i]=(g[i] + ROTL32(g[j & 7], 8) + g[j-1])&0xffffffff
            i+=1
            j+=1
            j&=7
        
    def crypt(self,msg):
        plain=""
        l=len(msg)
        c=self.ctx
        x=[0]*4
        start=0
        while(True):
            self.next_state(c.w)
            for i in range(4):
                x[i]=c.w.x[i<<1]
            x[0]^=(c.w.x[5]>>16)^(c.w.x[3]<<16)
            x[1]^=(c.w.x[7]>>16)^(c.w.x[5]<<16)
            x[2]^=(c.w.x[1]>>16)^(c.w.x[7]<<16)
            x[3]^=(c.w.x[3]>>16)^(c.w.x[1]<<16)
            b=[0]*16
            for i,j in enumerate(x):
                for z in range(4):
                    b[z+4*i]=0xff&(j>>(8*z))
            for i in range(16):
                plain+=chr(ord(msg[start])^b[i])
                start+=1
                if(start==l):
                  return plain
                  
                  
                  
                  
def st(b):
    a=""
    for x in b:
      a+=chr(x)
    return a  
def check(key,iv,out):
    msg="\x00"*48    
    cipher=Rabbit(key,iv)

    data=cipher.crypt(msg)
    assert data==out    
if __name__ == "__main__":
    #some test samples    
    key1  = [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ];

    key2  = [ 0xAC, 0xC3, 0x51, 0xDC, 0xF1, 0x62, 0xFC, 0x3B, 
                         0xFE, 0x36, 0x3D, 0x2E, 0x29, 0x13, 0x28, 0x91 ];

    key3  = [ 0x43, 0x00, 0x9B, 0xC0, 0x01, 0xAB, 0xE9, 0xE9,
                         0x33, 0xC7, 0xE0, 0x87, 0x15, 0x74, 0x95, 0x83 ];

    iv1    = [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ];

    iv2    = [ 0x59, 0x7E, 0x26, 0xC1, 0x75, 0xF5, 0x73, 0xC3 ];

    iv3    = [ 0x27, 0x17, 0xF4, 0xD2, 0x1A, 0x56, 0xEB, 0xA6 ];

    out1  = [ 0x02, 0xF7, 0x4A, 0x1C, 0x26, 0x45, 0x6B, 0xF5, 
                         0xEC, 0xD6, 0xA5, 0x36, 0xF0, 0x54, 0x57, 0xB1,
                         0xA7, 0x8A, 0xC6, 0x89, 0x47, 0x6C, 0x69, 0x7B,
                         0x39, 0x0C, 0x9C, 0xC5, 0x15, 0xD8, 0xE8, 0x88, 
                         0x96, 0xD6, 0x73, 0x16, 0x88, 0xD1, 0x68, 0xDA,
                         0x51, 0xD4, 0x0C, 0x70, 0xC3, 0xA1, 0x16, 0xF4 ];

    out2  = [ 0x9C, 0x51, 0xE2, 0x87, 0x84, 0xC3, 0x7F, 0xE9, 
                         0xA1, 0x27, 0xF6, 0x3E, 0xC8, 0xF3, 0x2D, 0x3D, 
                         0x19, 0xFC, 0x54, 0x85, 0xAA, 0x53, 0xBF, 0x96, 
                         0x88, 0x5B, 0x40, 0xF4, 0x61, 0xCD, 0x76, 0xF5, 
                         0x5E, 0x4C, 0x4D, 0x20, 0x20, 0x3B, 0xE5, 0x8A, 
                         0x50, 0x43, 0xDB, 0xFB, 0x73, 0x74, 0x54, 0xE5 ];

    out3  = [ 0x9B, 0x60, 0xD0, 0x02, 0xFD, 0x5C, 0xEB, 0x32, 
                         0xAC, 0xCD, 0x41, 0xA0, 0xCD, 0x0D, 0xB1, 0x0C, 
                         0xAD, 0x3E, 0xFF, 0x4C, 0x11, 0x92, 0x70, 0x7B, 
                         0x5A, 0x01, 0x17, 0x0F, 0xCA, 0x9F, 0xFC, 0x95, 
                         0x28, 0x74, 0x94, 0x3A, 0xAD, 0x47, 0x41, 0x92, 
                         0x3F, 0x7F, 0xFC, 0x8B, 0xDE, 0xE5, 0x49, 0x96 ];

    out4  = [ 0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C, 
                         0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7, 0xC6, 
                         0x8D, 0x4A, 0xDC, 0x70, 0x32, 0x29, 0x8F, 0x7B, 
                         0xD4, 0xEF, 0xF5, 0x04, 0xAC, 0xA6, 0x29, 0x5F, 
                         0x66, 0x8F, 0xBF, 0x47, 0x8A, 0xDB, 0x2B, 0xE5, 
                         0x1E, 0x6C, 0xDE, 0x29, 0x2B, 0x82, 0xDE, 0x2A ];

    out5  = [ 0x6D, 0x7D, 0x01, 0x22, 0x92, 0xCC, 0xDC, 0xE0, 
                         0xE2, 0x12, 0x00, 0x58, 0xB9, 0x4E, 0xCD, 0x1F, 
                         0x2E, 0x6F, 0x93, 0xED, 0xFF, 0x99, 0x24, 0x7B, 
                         0x01, 0x25, 0x21, 0xD1, 0x10, 0x4E, 0x5F, 0xA7, 
                         0xA7, 0x9B, 0x02, 0x12, 0xD0, 0xBD, 0x56, 0x23, 
                         0x39, 0x38, 0xE7, 0x93, 0xC3, 0x12, 0xC1, 0xEB ];

    out6 = [ 0x4D, 0x10, 0x51, 0xA1, 0x23, 0xAF, 0xB6, 0x70, 
                         0xBF, 0x8D, 0x85, 0x05, 0xC8, 0xD8, 0x5A, 0x44, 
                         0x03, 0x5B, 0xC3, 0xAC, 0xC6, 0x67, 0xAE, 0xAE, 
                         0x5B, 0x2C, 0xF4, 0x47, 0x79, 0xF2, 0xC8, 0x96, 
                         0xCB, 0x51, 0x15, 0xF0, 0x34, 0xF0, 0x3D, 0x31, 
                         0x17, 0x1C, 0xA7, 0x5F, 0x89, 0xFC, 0xCB, 0x9F ];
   
    check(st(key1), "",st(out1));
    check(st(key2), "",st(out2));
    check(st(key3), "",st(out3));
  
    check(st(key1), st(iv1), st(out4));
    check(st(key1), st(iv2), st(out5));
    check(st(key1), st(iv3), st(out6));

    print "pass all tests"