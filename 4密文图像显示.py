#encoding=utf-8
'''
4密文图像显示:
	说明:本代码旨在将加密后像素值重新绘制成密文图像
'''
from PIL import Image
#获取图像的宽高
def get_img_inf(img):
	im = Image.open(img)
	return im.size[0],im.size[1]
#获取加密后的像素信息
def get_img_data(filename):
	img_data=''
	f=open(filename,'r')
	for line in f:
		img_data+=(line.strip('\n'))
	f.close()
	return img_data
#绘制加密后的图像
def draw_image(img_data,img_filename,img_width,img_height):
	img = Image.new('RGB',(img_width,img_height))
	c=0
	for i in range(img_width):
		for j in range(img_height):
			r=int(img_data[c:c+8],2)
			g=int(img_data[c+8:c+16],2)
			b=int(img_data[c+16:c+24],2)
			# print('绘制加密图片',i,j,r,g,b,sep='  ')
			img.putpixel((i,j),(r,g,b))
			c+=24		
	img.save(img_filename)


def main():
	ori_img='original_img.png'
	img_width,img_height=get_img_inf(ori_img)
	#通过加密后的分组信息绘制密文图像
	filename='encrypt_data.txt'
	img_data=get_img_data(filename)
	img_filename='encrypted_img.png'
	draw_image(img_data,img_filename,img_width,img_height)
	print('绘制加密图片成功！')


if __name__ == '__main__':
	main()



