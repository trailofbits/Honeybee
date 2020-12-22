#Fetch submodules
git submodule init
git submodule update --remote

cd xed
./mfile.py &&
echo "Built xed"
