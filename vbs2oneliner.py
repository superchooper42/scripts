#!/usr/bin/env python3
#Created by Cary Hooper
#Automating mundane tasks for AWAE.  
#Turns any VBS script into a "one-liner".

filename = "webshells/conf-os-info.vbs"
newfilename = filename.rsplit(".",1)[0] + ".oneliner." + filename.rsplit(".",1)[1]; 
f = open(filename,'r')
new = open(newfilename,'w')
for line in f.readlines():
	line = line.rstrip().lstrip()
	print(line)
	try:
		if line[0] == "'":
			#Line starts with ', then it is a comment... remove.
			continue
		if line[-2:] == " _":
			#line ends with a _, then don't add a :
			new.write(line[:-2] + " ")
			
		else:
			#Otherwise, add a ":"
			new.write(line + ":")
	except:
		print()

f.close()
new.close()