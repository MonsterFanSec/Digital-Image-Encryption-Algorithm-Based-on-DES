#encoding=utf-8
'''
2组内加密:
	说明:本代码旨在将得到的分组后的数据进行DES加密的处理，这里可以选用
	二重DES或三重DES加密算法，以提升加密的安全性
'''
import random
import os
# 密钥置换选择 1
key_table1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3]
# 密钥置换选择 2
key_table2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
# 初始置换 IP
IP = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8,  0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]
# 逆初始置换
IP_1 = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]
# 选择扩展运算 E
E = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]
# 置换运算 P
P = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]
# S盒
sbox = [
# S1
[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
# S2
[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
# S3
[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

# S4
[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

# S5
[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

# S6
[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

# S7
[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

# S8
[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

#循环左移位数
l=[1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

#检测64位密钥的奇偶校验是否通过
def check_key(key_bin):
	for i in range(0,64,8):
		xor=int(key_bin[i])^int(key_bin[i+1])^int(key_bin[i+2])^int(key_bin[i+3])^int(key_bin[i+4])^int(key_bin[i+5])^int(key_bin[i+6])
		if xor!=int(key_bin[i+7]):
			return False
	return True

#密钥置换选择1
def key_ds1(key):
	s=''
	for i in key_table1:
		s+=key[i]
	return s
#密钥置换选择2
def key_ds2(key):
    s=''
    for i in key_table2:
        s+=key[i]
    return s
#密钥循环左移
def key_move(key,r):
    s=key
    for i in range(l[r]):
    	s=s[1:]+s[:1]
    return s
#扩展置换E
def extend_E(R):
	r=''
	for i in E:
		r+=R[i]
	return r
#代换选择S盒
def alter_s(t):
	j=0
	res=''
	for i in range(0,48,6):
		c=int(t[i+1:i+5],2)
		r=int(t[i]+t[i+5],2)
		res+='{:04b}'.format((sbox[j][r*16+c]))
		j+=1
	# print(res)
	return res
#P置换
def p_repl(s):
	p=''
	for i in P:
		p+=s[i]
	return p

#通过64位密钥获取全部的子密钥   
def get_subkey(key_bin):
	#首先进行key_bin的奇偶校验检查
	if check_key(key_bin)==False:
		print('密钥奇偶校验不通过！')
		return 
	#print('密钥奇偶校验通过！')
	key=[]
	#密钥置换选择1
	key1_res=key_ds1(key_bin)
	L=key1_res[:28]
	R=key1_res[28:]
	for i in range(16):
		#循环左移
		L=key_move(L,i)
		R=key_move(R,i)
		#密钥置换选择2
		key.append(key_ds2(L+R))
	return key


#DES加密基本函数，输入64位明文和密钥
def DES(M,key):
	#首先将明文进行初始置换IP
	m=''
	for i in IP:
		m+=M[i]
	L=[]
	R=[]
	# print('m=',m)
	L.append(m[:32])
	R.append(m[32:])
	#16轮feistel结构
	for i in range(16):
		L.append(R[i])
		#将R进行扩展置换E
		R_extend=extend_E(R[i])
		#优化算法
		# t=''
		# for j in range(48):
		# 	#print(R_extend[j],key[i][j])
		# 	t+=str(int(R_extend[j])^int(key[i][j]))
		t='{:048b}'.format(int(R_extend,2)^int(key[i],2))
		#代换选择S盒
		s=alter_s(t)
		#P置换
		p=p_repl(s)
		#优化算法
		# r=''
		# for j in range(32):
		# 	r+=str(int(p[j])^int(L[i][j]))
		r='{:032b}'.format(int(p,2)^int(L[i],2))
		R.append(r)
		# print('l+r',L[i] + R[i])
	#左右交换
	c=R[16]+L[16]
	#逆初始置换
	cipher=''
	for i in IP_1:
		cipher+=c[i]
	return cipher

#随机生成满足奇偶校验的64位密钥
def get_rand_key(p):
	key_seed=os.urandom(8)	#随机获取8个字符
	KEY_bin_str=''
	for i in key_seed:
		binstr='{:07b}'.format(i)	#将每个字符转成7位二进制，第8位用于表示奇偶校验位
		xor=int(binstr[0])^int(binstr[1])^int(binstr[2])^int(binstr[3])^int(binstr[4])^int(binstr[5])^int(binstr[6])
		for i in range(7):
			KEY_bin_str+=str(binstr[i])
		KEY_bin_str+=str(xor)
		# print(binstr[0],binstr[1],binstr[2],binstr[3],binstr[4],binstr[5],binstr[6],sep=' ^ ',end=' = ')
		# print(xor)
	#print('随机生成的密钥',p,'为: ',KEY_bin_str,'  ',len(KEY_bin_str),'位')
	#print(len(KEY_bin_str))		
	return KEY_bin_str

#DES加密函数	
def DES_encrypt(message_bin_data,sub_key,i):
	#print(sub_key[0])
	print('正在利用密钥',i,'对数据进行DES加密')
	ciphertext=DES(message_bin_data,sub_key)
	print('加密后得到的二进制流为：',ciphertext,'   ',len(ciphertext),'位')
	return ciphertext

#DES解密函数
def DES_decrypt(ciphertext,key,i):
	print('正在利用密钥',i,'对数据进行DES解密')
	plainbin=DES(ciphertext,key)
	print('解密后得到的二进制流为：',plainbin,'   ',len(plainbin),'位')
	return plainbin

#进行二重DES加密
def DES_2_encrypt(s,sub_key1,sub_key2):
	# print("***   开始进行二重DES加密   ***")
	#print("***   正在随机生成DES密钥   ***")
	print("***   正在进行二重DES加密   ***")
	ciphertext=DES_encrypt(s,sub_key1,1)
	ciphertext=DES_encrypt(ciphertext,sub_key2,2)
	return ciphertext
def DES_2_decrypt(ciphertext,sub_key1,sub_key2):
	print("***   正在进行二重DES解密   ***")
	sub_key1=sub_key1[::-1]
	sub_key2=sub_key2[::-1]
	ciphertext=DES_decrypt(ciphertext,sub_key2,2)
	plaintext=DES_decrypt(ciphertext,sub_key1,1)
	return plaintext

#三重DES加密
def DES_3_encrypt(s,sub_key1,sub_key2,sub_key3):
	sub_key2=sub_key2[::-1]	#解密密钥
	print("***   正在进行三重DES加密   ***")
	ciphertext=DES_encrypt(s,sub_key1,1)
	ciphertext=DES_decrypt(ciphertext,sub_key2,2)
	ciphertext=DES_encrypt(ciphertext,sub_key3,3)
	print("***   三重DES加密成功   ***")
	return ciphertext
#三重DES解密
def DES_3_decrypt(ciphertext,sub_key1,sub_key2,sub_key3):
	print("***   正在进行三重DES解密   ***")
	sub_key1=sub_key1[::-1]
	sub_key2=sub_key2	#加密密钥
	sub_key3=sub_key3[::-1]
	ciphertext=DES_decrypt(ciphertext,sub_key3,3)
	ciphertext=DES_encrypt(ciphertext,sub_key2,2)
	plaintext=DES_decrypt(ciphertext,sub_key1,1)
	print("***    三重DES解密成功   ***")
	return plaintext

#获取明文的全部分组
def get_group(filename):
	group_list=[]
	f=open(filename,'r')
	for line in f:
		group_list.append(line.strip('\n'))
	f.close()
	return group_list

def main():
	#明文分组文件名
	group_file_name='group_data.txt'
	#获取分组列表
	group_list = get_group(group_file_name)
	#对所有明文分组进行加密
	for s in group_list:
		#s='0010001000011001111010110010000000100011111011100001110000100101'
		print('------------------------------------------------')
		print('初始选取的明文为: ',s)
		print("***   正在随机生成DES密钥   ***")
		key_bin1=get_rand_key(1)
		key_bin2=get_rand_key(2)
		key_bin3=get_rand_key(3)
		sub_key1=get_subkey(key_bin1)
		sub_key2=get_subkey(key_bin2)
		sub_key3=get_subkey(key_bin3)
		#默认选用三重DES加密，也可以选择二重DES进行加密
		# ciphertext=DES_2_encrypt(s,sub_key1,sub_key2)
		# plaintext=DES_2_decrypt(ciphertext,sub_key1,sub_key2)
		ciphertext=DES_3_encrypt(s,sub_key1,sub_key2,sub_key3)
		plaintext=DES_3_decrypt(ciphertext,sub_key1,sub_key2,sub_key3)
		print("***  对比原始数据和解密结果  ***")
		print("原始数据：  ",s)
		print('解密结果：  ',plaintext)
		print('------------------------------------------------')

if __name__ == '__main__':
	main()


