#encoding=utf-8
'''
Author: MonsterFanSec
3分组运行模式:
	说明:本代码旨在利用密码分组链接(CBC)模式对明文分组进行加密，
	选用三重DES加密模式进行加密
'''
import random
import os
############################################################
#                         *引用*                           #
#            引用 2组内加密 相关代码进行三重DES加密           #                                  #
#                  对其中的结果打印部分作注释                #
############################################################
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
    # print('key=',key,'len=',len(key))
    # s = key[l[r] : ] + key[ : l[r]][::-1]
    s=key
    for i in range(l[r]):
    	s=s[1:]+s[:1]
    # print('s=',s,'len=',len(s))
    return s
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
	# print(key1_res,len(key1_res))
	L=key1_res[:28]
	R=key1_res[28:]
	# print('l=',L,len(L))
	# print('r=',R,len(R))
	for i in range(16):
		#循环左移
		L=key_move(L,i)
		R=key_move(R,i)
		#密钥置换选择2
		key.append(key_ds2(L+R))
	# print('keys:')
	# for i in key:
		# print(i)
	#print('16轮子密钥成功生成！')
	# print('key=',key)
	return key

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
		#异或子密钥 K(i)
		#print('r=',R_extend)
		
		#优化算法
		# t=''
		# for j in range(48):
		# 	#print(R_extend[j],key[i][j])
		# 	t+=str(int(R_extend[j])^int(key[i][j]))
		t='{:048b}'.format(int(R_extend,2)^int(key[i],2))
		# print('t=',t)
		#代换选择S盒
		s=alter_s(t)
		# print('s=',s)
		#P置换
		p=p_repl(s)
		#异或L(i-1)
		# print('p=', p)
		
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
	# print(len(KEY_bin_str))		
	return KEY_bin_str

#DES加密函数	
def DES_encrypt(message_bin_data,sub_key,i):
	#print(sub_key[0])
	# print('正在利用密钥',i,'对数据进行DES加密')
	ciphertext=DES(message_bin_data,sub_key)
	# print('加密后得到的二进制流为：',ciphertext,'   ',len(ciphertext),'位')
	return ciphertext

#DES解密函数
def DES_decrypt(ciphertext,key,i):
	# print('正在利用密钥',i,'对数据进行DES解密')
	plainbin=DES(ciphertext,key)
	# print('解密后得到的二进制流为：',plainbin,'   ',len(plainbin),'位')
	return plainbin

#进行二重DES加密
def DES_2_encrypt(s,sub_key1,sub_key2):
	# print("***   开始进行二重DES加密   ***")
	#print("***   正在随机生成DES密钥   ***")
	# print("***   正在进行二重DES加密   ***")
	ciphertext=DES_encrypt(s,sub_key1,1)
	ciphertext=DES_encrypt(ciphertext,sub_key2,2)
	return ciphertext
def DES_2_decrypt(ciphertext,sub_key1,sub_key2):
	# print("***   正在进行二重DES解密   ***")
	sub_key1=sub_key1[::-1]
	sub_key2=sub_key2[::-1]
	ciphertext=DES_decrypt(ciphertext,sub_key2,2)
	plaintext=DES_decrypt(ciphertext,sub_key1,1)
	return plaintext

#三重DES加密
def DES_3_encrypt(s,sub_key1,sub_key2,sub_key3):
	#print(sub_key1[0])
	sub_key2=sub_key2[::-1]	#解密密钥
	# print("***   正在进行三重DES加密   ***")
	ciphertext=DES_encrypt(s,sub_key1,1)
	ciphertext=DES_decrypt(ciphertext,sub_key2,2)
	ciphertext=DES_encrypt(ciphertext,sub_key3,3)
	return ciphertext
#三重DES解密
def DES_3_decrypt(ciphertext,sub_key1,sub_key2,sub_key3):
	# print("***   正在进行三重DES解密   ***")
	sub_key1=sub_key1[::-1]
	sub_key2=sub_key2	#加密密钥
	sub_key3=sub_key3[::-1]
	ciphertext=DES_decrypt(ciphertext,sub_key3,3)
	ciphertext=DES_encrypt(ciphertext,sub_key2,2)
	plaintext=DES_decrypt(ciphertext,sub_key1,1)
	# print("***    三重DES解密成功   ***")
	return plaintext

############################################################
#                                                          #
#      					*结束引用*                          #
#                                                          #
############################################################
#获取明文的全部分组
def get_group(filename):
	group_list=[]
	f=open(filename,'r')
	for line in f:
		group_list.append(line.strip('\n'))
	f.close()
	return group_list
#获取初始IV向量
def get_IV():
	iv_seed=os.urandom(8)	#随机获取8个字符
	iv_bin_str=''
	for i in iv_seed:
		iv_bin_str+='{:08b}'.format(i)
	return iv_bin_str
#CBC加密
def CBC_encrypt(group_list,iv,key_bin1,key_bin2,key_bin3):
	print("***   正在获取子密钥   ***")
	sub_key1=get_subkey(key_bin1)
	sub_key2=get_subkey(key_bin2)
	sub_key3=get_subkey(key_bin3)
	C_list=[]
	Iv=iv
	print("***   正在进行CBC加密   ***")
	for group in group_list:
		xor_res=''
		# for i in range(64):
		# 	xor_res+=str(int(group[i])^int(Iv[i]))
		#优化算法
		xor_res='{:064b}'.format(int(group,2)^int(Iv,2))
		C=DES_3_encrypt(xor_res,sub_key1,sub_key2,sub_key3)
		C_list.append(C)
		Iv=C
	return C_list
#CBC解密
def CBC_decrypt(C_list,iv,key_bin1,key_bin2,key_bin3):
	sub_key1=get_subkey(key_bin1)
	sub_key2=get_subkey(key_bin2)
	sub_key3=get_subkey(key_bin3)
	P_list=[]
	Iv=iv
	for c in C_list:
		res=DES_3_decrypt(c,sub_key1,sub_key2,sub_key3)
		xor_res=''
		# for i in range(64):
		# 	xor_res+=str(int(res[i])^int(Iv[i]))
		#优化算法，加快运算速度
		xor_res='{:064b}'.format(int(res,2)^int(Iv,2))
		P_list.append(xor_res)
		Iv=c
	return P_list
#存储加密后的分组信息
def save_img_data(filename,list_data):
	f=open(filename,'w')
	for i in list_data:
		f.write(i+'\n')
	f.close()

def save_iv_data(filename,iv):
	f=open(filename,'w')
	f.write(iv+'\n')
	f.close()

def save_keys(filename,key_bin1,key_bin2,key_bin3):
	f=open(filename,'w')
	f.write(key_bin1+'\n')
	f.write(key_bin2+'\n')
	f.write(key_bin3+'\n')
	f.close()


def main():
	#明文分组文件名
	group_file_name='group_data.txt'
	#获取分组列表
	group_list = get_group(group_file_name)
	#获取初始向量IV
	iv=get_IV()
	#随机生成3个DES密钥
	key_bin1=get_rand_key(1)
	key_bin2=get_rand_key(2)
	key_bin3=get_rand_key(3)
	#进行CBC模型下的三重DES加密
	c_list=CBC_encrypt(group_list,iv,key_bin1,key_bin2,key_bin3)
	#CBC模型下的三重DES解密
	#p_list=CBC_decrypt(c_list,iv,key_bin1,key_bin2,key_bin3)
	#保存加密后分组数据便于 4密文图像显示
	save_img_data('encrypt_data.txt',c_list)
	#保存初始向量IV信息用于解密
	save_iv_data('iv.txt',iv)
	#保存解密数据
	#save_data('decrypt_data.txt',p_list)
	#保存密钥信息
	save_keys('keys.txt',key_bin1,key_bin2,key_bin3)
	print("***   相关信息保存成功!   ***")

if __name__ == '__main__':
	main()


