# 环境准备
安装openssl开发环境。
## 下载源码
wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz
tar zxvf openssl-1.1.1g.tar.gz 

## 编译安装
cd openssl-1.1.1g/
ls
./config # 最好指定prefix，我忘记指定了
sudo make install

## 配置调整
sudo mv `which openssl` /tmp
sudo ln -s /usr/local/bin/openssl /usr/bin/openssl

which openssl
openssl version

sudo cp libssl.so.1.1 /lib/x86_64-linux-gnu
sudo cp libcrypto.so.1.1 /lib/x86_64-linux-gnu

# 编译&运行
make