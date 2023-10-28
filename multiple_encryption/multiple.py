from aes.AES import AES
import threading
class multiple():
    def __init__(self):
        self.__total_key=[] #用于存储所有的密钥
        self.__find_keys=[] #用于存储找到的共同密钥
    
    #双重加密,输入为密钥和明文，密钥前面加0b这种为二进制或者直接十进制数
    def two_encrypt(self,key,p_text):
        #第一轮加密：
        A=AES()
        key=format(key,'032b')
        key=int(key)
        key1=int(str(key//10000000000000000),2)
        key2=int(str(key%10000000000000000),2)
        A.set_key(key1)
        c1=A.encrypt(p_text)
        #第二轮加密：
        A.set_key(key2)
        c2=A.encrypt(c1)
        return c2
    
    #二重解密
    def two_decrypt(self,key,c_text):
        #第一轮解密：
        A=AES()
        key=format(key,'032b')
        key=int(key)
        key1=int(str(key//10000000000000000),2)
        key2=int(str(key%10000000000000000),2)
        A.set_key(key2)
        p1=A.decrypt(c_text)
        #第二轮解密：
        A=AES()
        A.set_key(key1)
        p2=A.decrypt(p1)
        return p2
    
    #对密文暴力破解，输入明文
    def try_ck(self,c_text):
        c=[]
        for i in range(65536):
            ae = AES()
            ae.set_key(i)
            li = ae.decrypt(c_text)
            f=[li,i]
            c.append(f)
        return c
    
    #对明文暴力破解
    def try_pk(self,p_text,i):
        ae = AES()
        ae.set_key(i)
        lis =ae.encrypt(p_text)
        return lis

    #中间相遇攻击求其中一对明密文对，输入为整数的明密文对
    def find_onegroup(self,p_text,c_text):
        c1=self.try_ck(c_text)
        for i in range(65536):
            c2=self.try_pk(p_text,i)
            for j in c1:
                if j[0]==c2:
                    key=[i,j[1]]
                    self.__total_key.append(key)


    #多个明密文对取共通的密钥,pc_group由明密文对组成，先是明文再是密文，都为整数
    #得到的共同密钥存储在self.__find_keys之中的，对他输出得到结果
    def find_mid(self,pc_group):
        n=len(pc_group)
        t_list=[]
        for i in range(n):#利用循环创建n个线程
            t=threading.Thread(target=self.find_onegroup,args=(pc_group[i][0],pc_group[i][1] ,))
            t_list.append(t)
        #线程开始
        for t in t_list:
            t.start()
        #等所有线程完毕后再进行共同密钥的查找
        for t in t_list:
            t.join()
        for i in self.__total_key:
            if self.__total_key.count(i)==n:
                if i not in self.__find_keys:
                    self.__find_keys.append(i)
        num=len(self.__find_keys)
        if num==0:print("未找到密钥")
        else:
            print("找到",num,"对密钥，为:")
            for i in self.__find_keys:
                print(format(i[0],'016b'),format(i[1],'016b'))


    #三重加密方案2，采取的加密解密加密的方案进行三重加密，输入48bit的密钥和16位的明文
    def three_two_encrypt(self,key,p_text):
        key=format(key,'048b')
        key=int(key)
        key1=int(str(key//10000000000000000//10000000000000000),2)
        key2=int(str(key//10000000000000000%10000000000000000),2)
        key3=int(str(key%10000000000000000),2)
        #第一轮加密：
        A=AES()
        A.set_key(key1)
        c1=A.encrypt(p_text)
        #第二轮加密：
        A.set_key(key2)
        c2=A.decrypt(c1)
        #第三轮加密：
        A.set_key(key3)
        c3=A.encrypt(c2)
        return c3
    
    #三重解密方案2
    def three_two_decrypt(self,key,p_text):
        key=format(key,'048b')
        key=int(key)
        key1=int(str(key//10000000000000000//10000000000000000),2)
        key2=int(str(key//10000000000000000%10000000000000000),2)
        key3=int(str(key%10000000000000000),2)
        #第一轮加密：
        A=AES()
        A.set_key(key3)
        p1=A.decrypt(p_text)
        #第二轮加密：
        A.set_key(key2)
        p2=A.encrypt(p1)
        #第三轮加密：
        A.set_key(key1)
        p3=A.decrypt(p2)
        return p3
    
#输入测试的样例：
if __name__=='__main__':
    m=multiple()
    #二重加密
    c=m.two_encrypt(0b00000000111100001010110000101010,0b0)
    print(format(c,'016b'))
    #二重解密
    p=m.two_decrypt(0b00000000111100001010110000101010,0b1)
    print(format(p,'016b'))
    #三重加密：
    c3=m.three_two_encrypt(0b0,0b1111111100000000)
    #三重解密
    p3=m.three_two_decrypt(0b0,0b1101000101000011)
    print(format(c3,'016b'))
    print(format(p3,'016b'))
    #多重加密，pc_group是明密文对
    pc_group=[[0b0000111100001111,0b1110010001011110],[0b1111111100000000,0b0010010001010010],[0b1100110011001101,0b1010101100100010]]
    m.find_mid(pc_group)

