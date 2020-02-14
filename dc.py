import sys,zlib,re,warnings
warnings.filterwarnings("ignore")

#python .\dc.py /path/to/file.pdf
path = sys.argv[1]
file = open(path,'rb')
pdf = file.read()
stream = re.compile(rb'.*?FlateDecode.*?stream(.*?)endstream', re.S)
objects = stream.findall(pdf)
#Most times, the object was stored as the last object.
last = objects.pop()
mydata = zlib.decompress(last.strip(b'\r\n'))
print(str(mydata,'utf-8'))