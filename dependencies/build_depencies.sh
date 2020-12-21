#Fetch submodules
git submodule update --remote

cd xed
./mfile.py &&
echo "Built xed"
