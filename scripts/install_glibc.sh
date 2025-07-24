GLIBC_VERSION=$1
GLIBC_FOLDER=/tmp/glibc

mkdir $GLIBC_FOLDER && cd $GLIBC_FOLDER
wget http://ftp.gnu.org/gnu/libc/glibc-${GLIBC_VERSION}.tar.gz
tar -xvzf glibc-${GLIBC_VERSION}.tar.gz
mkdir build 
mkdir glibc-${GLIBC_VERSION}-install
cd build
$GLIBC_FOLDER/glibc-${GLIBC_VERSION}/configure --prefix=$HOME/glibc/glibc-${GLIBC_VERSION}-install
make
make install

# cd ~ && rm -r ~/glibc