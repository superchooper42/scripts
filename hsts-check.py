import requests,csv,re,warnings
#from multiprocessing.pool import ThreadPool as Pool
from datetime import datetime,timedelta
warnings.filterwarnings("ignore")
DEBUG = False
initial_time = datetime.now()

#Helper function for debugging.
def log(s):
	if DEBUG:
		print(s)

#Note to self: all HTTP headers are case insensitive - https://tools.ietf.org/html/rfc7230#section-3.2

def checkHSTS(request):
	#Checks for presence of HSTS header.  If header exists, return the header.
	log(f"Checking for HSTS headers.")
	if hasattr(request.a,'HSTStracker'):
		log(f"HSTStracker already set.")
	else:
		log(f"Setting HSTStracker for the first time")
		setattr(request.a,'HSTStracker',[])
	hstsvariants = ['strict-transport-security','Strict-Transport-Security']
	for hsts in hstsvariants:
		if hsts in request.headers:
			setattr(request.a, 'HSTS', request.headers[hsts])
			log("\t HSTS is set: " + request.a.HSTS)
			print(f"Found HSTS for {request.url}: {request.a.HSTS}")
			HSTSdict = dict.fromkeys(['Redirect','HSTS'])
			HSTSdict['URL'] = request.url
			HSTSdict['HSTS'] = request.headers[hsts]
			setattr(request.a, 'HSTStracker', request.a.HSTStracker.append(HSTSdict))
			log(f"HSTS tracker is {request.a.HSTStracker}")
			return request
		else:
			setattr(request.a, 'HSTS', False)
		# try:
		# 	log(f"HSTS tracker is {request.a.HSTStracker}")
		# 	#setattr(request.a, 'HSTStracker', request.a.HSTStracker.append({"Redirect": request.a.lastRedirect,"HSTS": request.headers[hsts]}))
		# 	log(request.__dict__)
		# 	log(request.a.__dict__)
		# 	log(f"HSTS tracker is {request.a.HSTStracker}")
		# except Exception as e:
		# 	log(f"HSTS Exception: {e}")
	return request

def checkRedirect(request):
	#check if a redirect occurred
	log(f"Checking redirect...")
	if request.status_code >= 300 and request.status_code < 400:
		log("\t Redirect detected... Location: (" + str(request.status_code) + ") " + request.headers["Location"])
		request.a = lambda: None
		setattr(request.a, 'lastRedirect', request.headers["Location"])
		setattr(request.a, 'wasRedirected', True)
	else:
		request.a = lambda: None
		setattr(request.a, 'wasRedirected', False)	
	#Redirect? return response object
	return request

def makeRequest(domainstring,first=False):
	#Make request and instantiate object
	#If only a domain is supplied, add "http://"
	if "http" not in domainstring: #includes https!
		domainstring = "http://" + domainstring
	log("Requesting " + domainstring)
	try:
		request = requests.get(domainstring,verify=False,timeout=5,allow_redirects=False)
		if first == True:
			log(f"\tThis is the first request for {domainstring}")
	except Exception as e:
		log(f"An exception occurred for {domainstring}... {e}")
		return False
	return request

def doFlow(domain):
	#This function is the main() for each domain flow. 
	#How do we want to store the response object?
	log(f"Doing flow for {domain}")
	nextURL = ""
	request = makeRequest(domain,True)
	if request == False:
		return request
	request = checkRedirect(request)
	request = checkHSTS(request)
	if request.a.wasRedirected == True:
		log(f"Next URL is {request.a.lastRedirect}")

	#DEBUG
	#request.a.wasRedirected == True|False
	#request.a.HSTS == <str>|False

	#Do loop until site stops redirecting
	
	while((request.a.wasRedirected == True) and ("http" in request.a.lastRedirect) and (request.a.lastRedirect != request.url)): 
	#Checks for presence of "http" too in case of a relative redirect
		request = makeRequest(request.a.lastRedirect)
		request = checkRedirect(request)
		request = checkHSTS(request)
	log(f"Flow completed for {domain}.  \n{request.a.HSTStracker}")
	return request

def main():
	# Open CSV file. File contains list of top X domains to scan.
	csvfile = open('C:\\Temp\\majestic_ten.csv','r')
	csvreader = csv.reader(csvfile)
	brokensites=[]
	for row in csvreader:
		target = row[2]
		try:
			request = doFlow(target)
		except Exception as e:
			print(f"Domain unavailable or redirect broken! - {target}")
			log(f"An exception occurred: {e}")
			brokensites.append(target)
			continue
		print(f"Original domain: {target}. Last Domain: {request.url}. HSTS: {request.a.HSTS}")


		#Is the site misconfigured? Check if HSTS is implemented, if it is implemented correctly, or if HSTS is eventually used
		#Case A - check for HSTS header in first http response
			#Need variable for first HSTS header
		#Case B - check if site redirects from http to https (does HSTS properly)
			#Need variable for first redirect URL
		#Case C - site doesn't return HSTS for https site. (not implemented)
			#For this, I think I need an array of dicts.  
			#request.a.hststracker = [{"redirect":<url>,"HSTS":<hsts>|False},...]
			#Allows us to do analysis later
		#Case D - site redirects to different subdomain (HSTS improperly implemented)
			#Compare first redirect URL to domain // no variable necessary

		#HSTS Analysis
		#Case E - max-age directive is super low < 14 days
		#Case F - no preload is set
		#Case G - preload is set but includeSubdomains 
		#Case H - domain is in preload list but no preload directive is given
		



	#Benchmarking for testing purposes
	end_time = datetime.now()
	diff = end_time - initial_time
	print(f"Seconds that have elapsed: {diff.seconds}")

main()
#test