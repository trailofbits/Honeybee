#Fetch submodules
git submodule init
git submodule update --remote

cd xed
./mfile.py &&
	echo "Built xed"

cd ../
cd libipt
cmake -DBUILD_SHARED_LIBS=0 . &&
	make &&
	echo "Built libipt"
