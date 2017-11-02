OpenSLL Build Instructions

-- Ubuntu -- 
git clone https://github.com/openssl/openssl
cd openssl
git checkout OpenSSL_1_0_1-stable
./config
make
sudo make install


-- Windows --
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout OpenSSL_1_0_1-stable
perl Configure VC-WIN32 --prefix=D:\TBuild\Libraries\openssl\Release
ms\do_ms
nmake -f ms\nt.mak
nmake -f ms\nt.mak install
cd ..
git clone https://github.com/openssl/openssl.git openssl_debug
cd openssl_debug
git checkout OpenSSL_1_0_1-stable
perl Configure debug-VC-WIN32 --prefix=D:\TBuild\Libraries\openssl_debug\Debug
ms\do_ms
nmake -f ms\nt.mak
nmake -f ms\nt.mak install

-- Mac --
git clone https://github.com/openssl/openssl
cd openssl
git checkout OpenSSL_1_0_1-stable
./config
make
sudo make install


