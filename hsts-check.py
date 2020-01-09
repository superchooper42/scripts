import requests,csv,re,warnings
#from multiprocessing.pool import ThreadPool as Pool
from datetime import datetime,timedelta
warnings.filterwarnings("ignore")
DEBUG = True
pool_size = 4
initial_time = datetime.now()

#Helper function for debugging.
def log(s):
	if DEBUG:
		print(s)

#Note to self: all HTTP headers are case insensitive - https://tools.ietf.org/html/rfc7230#section-3.2

def checkHSTS(request):
	#Checks for presence of HSTS header.  If header exists, return the header.
	hstsvariants = ['strict-transport-security','Strict-Transport-Security']
	for hsts in hstsvariants:
		if hsts in request.headers:
			log("\t HSTS is set: " + request.headers[hsts])
			setattr(request.a, 'HSTS', request.headers[hsts])
		else:
			setattr(request.a, 'HSTS', False)
		return request

def checkRedirect(request):
	#check if a redirect occurred
	request.a = lambda: None
	if request.status_code >= 300 and request.status_code < 400:
		log("\t Redirect detected... Location: (" + str(request.status_code) + ") " + request.headers["Location"])
		setattr(request.a, 'wasRedirected', True)
	else:
		setattr(request.a, 'wasRedirected', False)	
	#Redirect? return response object
	return request

def makeRequest(domainstring):
	#Make request and instantiate object
	#If only a domain is supplied, add "http://"
	if "http" not in domainstring: #includes https!
		domainstring = "http://" + domainstring
	log("Requesting " + domainstring)
	try:
		#Desperately need graceful error handling
		request = requests.get(domainstring,verify=False,timeout=5,allow_redirects=False)
	except Exception as e:
		log(f"An exception occurred for {domainstring}... {e}")
		return False
	return request

def doFlow(domain):
	#This function is the main() for each domain flow. 
	#How do we want to store the response object?
	nextURL = ""
	request = makeRequest(domain)
	if request == False:
		return request
	request = checkRedirect(request)
	request = checkHSTS(request)
	if "Location" in request.headers:
		nextURL = request.headers["Location"]
		log(f"nextURL is {nextURL} .. of type {type(nextURL)}")

	#DEBUG
	#request.a.wasRedirected == True|False
	#request.a.HSTS == <str>|False

	#Do loop until site stops redirecting
	
	while(request.a.wasRedirected == True and "http" in nextURL):
		request = makeRequest(nextURL)
		request = checkRedirect(request)
		request = checkHSTS(request)
		if "Location" in request.headers:
			nextURL = request.headers["Location"]
	print(f"Flow completed for {domain}.  HSTS: {request.a.HSTS}")
	return request

def main():
	# pool = Pool(pool_size)
	#Open CSV file. File contains list of top X domains to scan.
	csvfile = open('C:\\Temp\\majestic_hundred.csv','r')
	csvreader = csv.reader(csvfile)
	for row in csvreader:
		target = row[2]
		request = doFlow(target)
		if request == False:
			print(f"Domain unavailable or redirect broken! - {target}")
			continue
		#Is the site misconfigured?
		#Case A - first redirect doesn't redirect from http to https
		#Case B - site doesn't return HSTS for https site.
		#Case C - max-age directive is super low < 14 days
		#Case D - no preload is set
		#Case E - preload is set but includeSubdomains 
		#Case F - domain is in preload list but no preload directive is given
		#Case G - site responds HSTS for http



	#Benchmarking for testing purposes
	end_time = datetime.now()
	diff = end_time - initial_time
	print(f"Seconds that have elapsed: {diff.seconds}")

main()