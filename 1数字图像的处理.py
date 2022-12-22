#encoding=utf-8
'''
1数字图像处理
	说明：本代码旨在提取图片中的像素点，将每个像素点的RGB值转换为
	二进制的01比特序列，再将得到的比特序列按照DES明文分组要求进行
	64比特的明文分组，采用了PKCS#5填充标准进行填充，最终得到分组
	的list列表
'''
from PIL import Image

#图片像素二进制值获取函数
def get_pixel(img):	
	im = Image.open(img)
	rgb_im = im.convert('RGB')
	img_width=im.size[0]	#获取图像的宽
	img_height=im.size[1]	#获取图像的高
	bin_data=''
	for i in range(img_width):	#遍历每一个像素点
		for j in range(img_height):
			r, g, b = rgb_im.getpixel((i, j))	#获取像素点的rgb值
			# print(r, g, b)
			bin_data+='{:08b}'.format(r)
			bin_data+='{:08b}'.format(g)
			bin_data+='{:08b}'.format(b)
	return bin_data,img_width,img_height

#DES明文分组处理函数
def set_group(bin_data):
	print("***   正在进行明文分组   ***")
	bin_data_list=[]
	data_length=len(bin_data)
	i=0
	while data_length>=64:		#按照
		#print("正在划分第"+str(i)+"个明文分组  ",data_length)
		bin_data_list.append(bin_data[:64])
		data_length-=64
		bin_data=bin_data[64:]
		i+=1
	print("正在处理最后一个明文分组   ",data_length)
	if data_length == 0:	#若恰好能够完全分组 填充一定要进行，填充8个0x08
		padding_byte_size=8
		padding_data=('{:08b}'.format(padding_byte_size))*padding_byte_size
		last_group_data=padding_data
		bin_data_list.append(last_group_data)
		return bin_data_list
	else:
		padding_length = 64 - data_length
		padding_byte_size = (padding_length)//8
		#填充采用 PKCS#5填充标准
		padding_data = ('{:08b}'.format(padding_byte_size))*padding_byte_size
		last_group_data = bin_data + padding_data
		bin_data_list.append(last_group_data)	#填加最后填充的内容
		print("最后需填充的字节数为  ",padding_byte_size)
		print("最后一个分组的长度为  ",len(last_group_data))
		return bin_data_list
#将明文分组信息储存在txt文件中,便于2组内加密中获取相应的明文数据
def save_group_data(bin_data_list):
	f=open('group_data.txt','w')
	for i in bin_data_list:
		f.write(i+'\n')
	f.close()

def main():
	#需要转换为01比特序列的图片名
	img_dir="original_img.png"
	#获取图像的像素点
	print("***   正在获取图像信息   ***")
	bin_data,img_width,img_height=get_pixel(img_dir)
	print('图像宽度:',img_width,'图像高度:',img_height)
	bin_data_list=set_group(bin_data)
	save_group_data(bin_data_list)
	print("*** 保存明文分组信息成功 ***")
	print("*** 明文分组信息存储在group.txt文件中 ***")
	# print("最终获取的明文分组为：",bin_data_list)

if __name__ == '__main__':
	main()


		

