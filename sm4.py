import random

s = [['D6','90','E9','FE','CC','E1','3D','B7','16','B6','14','C2','28','FB','2C','05'],
     ['2B','67','9A','76','2A','BE','04','C3','AA','44','13','26','49','86','06','99'],
     ['9C','42','50','F4','91','EF','98','7A','33','54','0B','43','ED','CF','AC','62'],
     ['E4','B3','1C','A9','C9','08','E8','95','80','DF','94','FA','75','8F','3F','A6'],
     ['47','07','A7','FC','F3','73','17','BA','83','59','3C','19','E6','85','4F','A8'],
     ['68','6B','81','B2','71','64','DA','8B','F8','EB','0F','4B','70','56','9D','35'],
     ['1E','24','0E','5E','63','58','D1','A2','25','22','7C','3B','01','21','78','87'],
     ['D4','00','46','57','9F','D3','27','52','4C','36','02','E7','A0','C4','C8','9E'],
     ['EA','BF','8A','D2','40','C7','38','B5','A3','F7','F2','CE','F9','61','15','A1'],
     ['E0','AE','5D','A4','9B','34','1A','55','AD','93','32','30','F5','8C','B1','E3'],
     ['1D','F6','E2','2E','82','66','CA','60','C0','29','23','AB','0D','53','4E','6F'],
     ['D5','DB','37','45','DE','FD','8E','2F','03','FF','6A','72','6D','6C','5B','51'],
     ['8D','1B','AF','92','BB','DD','BC','7F','11','D9','5C','41','1F','10','5A','D8'],
     ['0A','C1','31','88','A5','CD','7B','BD','2D','74','D0','12','B8','E5','B4','B0'],
     ['89','69','97','4A','0C','96','77','7E','65','B9','F1','09','C5','6E','C6','84'],
     ['18','F0','7D','EC','3A','DC','4D','20','79','EE','5F','3E','D7','CB','39','48']]

FK = ['A3B1BAC6','56AA3350','677D9197','B27022DC']

CK = ['00070E15','1C232A31','383F464D','545B6269','70777E85','8C939AA1','A8AFB6BD','C4CBD2D9','E0E7EEF5','FC030A11','181F262D',
       '343B4249','50575E65','6C737A81','888F969D','A4ABB2B9','C0C7CED5','DCE3EAF1','F8FF060D','141B2229','30373E45','4C535A61',
       '686F767D','848B9299','A0A7AEB5','BCC3CAD1','D8DFE6ED','F4FB0209','10171E25','2C333A41','484F565D','646B7279']

def char_to_bit(plaintext): #将明文消息转换为01bit串
    bits = ''
    for letter in plaintext:
        temp = bin(ord(letter))[2:]
        for i in range(8-len(temp)):
            temp = '0' + temp
        bits += temp
    return bits

def bit_to_char(result):   #将解密出来的01串转化为字符
    plaintext = ''
    for i in range(len(result)//8):
        plaintext += chr(int(result[i*8:(i+1)*8],2))
    return plaintext

def key_group(key):  #密钥扩展第一步，MKi异或FKi
    MY = []
    K = []
    newFK = []
    for i in range(4):
        MY.append(key[32*i:(i+1)*32])
    for each in FK:
        temp = bin(int(each,16))[2:]
        for j in range(32-len(temp)):
            temp = '0'+temp
        newFK.append(temp)
    for i in range(4):
        K.append(xor(newFK[i],MY[i]))
    return K

def key_L(word):  #密钥扩展第二步L'
    word1 = word[13:]+word[:13]
    word2 = word[23:]+word[:23]
    result = xor(xor(word,word1),word2)
    return result

def key_extend(K): #密钥扩展第二步
    rk = []   
    newCK = []
    for each in CK:
        temp = bin(int(each,16))[2:]
        for j in range(32-len(temp)):
            temp = '0'+temp
        newCK.append(temp)
    for i in range(32):
        rk.append(xor(K[i],key_L(S_replace(xor(xor(xor(K[i+1],K[i+2]),K[i+3]),newCK[i])))))
        K.append(rk[i])
    return rk

def group(bits):
    arr = []
    result = []
    temp = []
    count = 0
    for i in range(len(bits)//32):   #按字进行划分
        newbits = bits[32*i:(i+1)*32]
        arr.append(newbits)
    if bits[32*(i+1):]:  #不足32bit的原样加入                                                     
        arr.append(bits[32*(i+1):])
    for word in arr:
        temp.append(word)
        count += 1
        if count % 4 == 0:  #四个字为单位加入result
            result.append(temp)
            temp = []
        elif count == len(arr):  
            result.append(temp)
    return result

def fill(arr):  #填充
    count = len(arr[-1][-1])
    time = (128 - ((len(arr[-1])-1)*32+count))//8
    if time == 0:
        arr.append([])
        a = bin(16)[2:]
        for j in range(8-len(a)):
            a = '0'+a
        for i in range(4):
            arr[-1].append(a*4)
    else:
        count = (32 - count) // 8
        a = bin(int(time))[2:]
        for j in range(8 - len(a)):
            a = '0' + a
        for i in range(count):
            arr[-1][-1] += a
        time = (time - count)//4
        for k in range(time):
            arr[-1].append(a*4)
    return arr

def S_replace(word):   #S盒替换，以字为单位
    hex_str = ''
    newhex = ''
    newbits = ''
    for i in range(8):
        hex_str += hex(int(word[i*4:(i+1)*4],2))[2:]
    for j in range(4):
        line = int(hex_str[j*2:(j+1)*2][0],16)
        clum = int(hex_str[j*2:(j+1)*2][1],16)
        newhex += s[line][clum]   
    for k in newhex:
        temp = bin(int(k,16))[2:]
        for m in range(4-len(temp)):
            temp = '0'+temp
        newbits += temp
    return newbits

def xor(a,b):  #逐比特异或
    result = ''
    if len(a) == len(b):
        for i in range(32):
            if a[i] == b[i]:
                result += '0'
            else:
                result += '1'
        return result
    else:
        print('The length don\'match\n')
        return None

def L(word):    #L变换
    word1 = word[2:]+word[:2]
    word2 = word[10:]+word[:10]
    word3 = word[18:]+word[:18]
    word4 = word[24:]+word[:24]
    str = xor(xor(xor(xor(word,word1),word2),word3),word4)
    return str

def ring(arr,key):  #轮函数
    x = arr[1]
    for i in range(2,len(arr)):
        x = xor(x,arr[i])
    x = xor(x,key)
    x = L(S_replace(x))
    x = xor(arr[0],x)
    return x

def encryption(word,key):  #加密函数
    result = word
    for i in range(32):
        x = ring(result,key[i])
        word.append(x)
        result = [word[i+1],word[i+2],word[i+3],word[i+4]]
        if i < 9:
            print('Round {}:'.format('0'+str(i+1)),hex(int(x,2)))
        else:
            print('Round {}:'.format(i+1),hex(int(x,2)))

    return word[-1]+word[-2]+word[-3]+word[-4]

def decryption(word1,key):  #解密
    result = word1
    for i in range(32):
        x = ring(result,key[-(i+1)])
        word1.append(x)
        result = [word1[i+1],word1[i+2],word1[i+3],word1[i+4]]
        if i < 9:
            print('Round {}:'.format('0'+str(i+1)),hex(int(x,2)))
        else:
            print('Round {}:'.format(i+1),hex(int(x,2)))
    return word1[-1] + word1[-2] + word1[-3] + word1[-4]

def main():    
    plaintext = input('请输入明文消息：\n')
    key = input('请输入密钥：\n')
    key = bin(int(key,16))[2:]
    for i in range(128 - len(key)):
        key = '0' + key
    print('加密过程：\n')
    key = key_extend(key_group(key))
    encry_result = ''
    decry_result = ''
    plain_bits = char_to_bit(plaintext) #将明文消息转换为01bit串
    encry_group = group(plain_bits)
    encry_group = fill(encry_group)
    for word in encry_group:
        encry_result += encryption(word,key)
    print('The cyphertext is:\n'+hex(int(encry_result,2))[2:]+'\n')
    print('解密过程：\n')
    decry_group = group(encry_result)
    for word1 in decry_group:
        decry_result += decryption(word1,key)
    print('The plaintext is:\n'+bit_to_char(decry_result))

if __name__ == '__main__':

    main()
