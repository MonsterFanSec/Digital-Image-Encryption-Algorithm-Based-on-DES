### **基于DES的数字图像加密算法的设计与实现**

DES填充模式：PKCS#5
选用三重DES进行加密	
选用密码分组链接（CBC）模式作为DES运行模式
按照序号顺序运行文件即可正确的对图像进行加解密
	文件运行顺序：
		1数字图像的处理.py
		2组内加密.py
		3分组运行模式.py
		4密文图像显示.py
		5密文图像解密.py
	或者
	直接运行  6三重DES和CBC分组加密实现.py
文件说明：
	原始图像：original_img.png
	原始分组信息：group_data.txt
	DES密钥信息：keys.txt
	初始向量IV信息：iv.txt
	加密后的分组信息：encrypt_data.txt
	加密后的图像：encrypted_img.png
	解密后的图像：decrypted_img.png
*注意*
	1.由于DES密钥和IV向量每次都是随机生成的，请按照指定代码文件顺序运行代码或直接运行6三重DES和CBC分组加密实现.py
	2.初始加密时仅需保留原始图像：original_img.png和代码文件，其余文件均为程序运行时自动生成的文件
	3.请使用python3运行代码，同时确保相应的库文件已经正确安装
	



**Design and implementation of digital image encryption algorithm based on DES**

DES Fill Mode: PKCS # 5

Triple DES encryption

Select password block link (CBC) mode as DES operation mode

Run the file in the sequence of serial number to correctly encrypt and decrypt the image

File running order:

		1数字图像的处理.py
		2组内加密.py
		3分组运行模式.py
		4密文图像显示.py
		5密文图像解密.py
perhaps

Directly run 6三重DES和CBC分组加密实现.py

Document description:

Original image: original_ img.png

Original group information: group_ data.txt

DES key information: keys.txt

Initial vector IV information: iv.txt

Encrypted packet information: encrypt_ data.txt

Encrypted image: encrypted_ img.png

Decrypted image: decrypted_ img.png

*Attention*

1. Since the DES key and IV vector are randomly generated each time, please run the code in the order of the specified code file or directly run 6三重DES和CBC分组加密实现.py

2. During initial encryption, only the original image: original_ Img.png and code files, and other files are automatically generated when the program runs

3. Please use python 3 to run the code and ensure that the corresponding library files have been installed correctly
