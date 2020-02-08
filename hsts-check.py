import requests,csv,re,warnings,sys,json
#from multiprocessing.pool import ThreadPool as Pool
from datetime import datetime,timedelta
warnings.filterwarnings("ignore")
DEBUG = False
initial_time = datetime.now()

#Helper function for debugging.
def log(s):
	if DEBUG:
		print(s)

class requestHSTS:
	"""Class to make HTTP requests, follow redirects, and interpret HSTS.  A domain is required to instantiate."""
	#Attributes:
	# 'URL':	[<str>],
	# 'HSTS':	[False|<str>]
	# 'reqCount': <int>
	def __init__(self):
		self.URL = []
		self.HSTS = []
		self.reqCount = 0	#incremented after every request is made

	def checkHSTS(self):
		#Checks for presence of HSTS header.
		log(f"Checking for HSTS headers...")
		hsts = 'Strict-Transport-Security'
		if hsts not in self.request.headers:
			self.HSTS.append(False)
		else:
			headercontent = self.request.headers[hsts]
			log(f"Header found - {hsts}:{headercontent}")
			self.HSTS.append(headercontent)

	def makeRequest(self):
		#Make the request
		headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0'}
		log(f"Making request to {self.URL[self.reqCount]}")
		self.request = requests.get(self.URL[self.reqCount],verify=False,timeout=5,allow_redirects=False,headers=headers)
		self.reqCount += 1
		log(f"{self.reqCount} request(s) have been made.")
		#First check the response for HSTS header
		try:
			self.checkHSTS()
		except Exception as e:
			print(f"Error with checkHSTS({self.URL[self.reqCount - 1]}) - {e}")
		#Next, see if the site redirected
		try:
			self.checkRedirect()
		except Exception as e:
			print(f"Error with checkRedirect({self.URL[self.reqCount - 1]}) - {e}")	
		#Collect all the things!

	def checkRedirect(self):
		#check if a redirect occurred
		nextURL = False
		log(f"Checking redirect...")
		for loc in ['Location','location']:
			if loc in self.request.headers:
				nextURL = self.request.headers[loc]
		#If nextURL exists, that means a redirect occurred... this guarantees another round.
		if nextURL:
			if "http" in nextURL:
				log(f"\t Redirect detected... Location: ({str(self.request.status_code)}) - {nextURL}")
				self.URL.append(nextURL)
				try:
					#Recursive duh
					self.makeRequest()
				except Exception as e:
					print(f"Error with makeRequest({self.URL[self.reqCount]}) - {e}")	
		else:
			log(f"No redirect found... ending chain.")

	def printResults(self):
		print(f"Results:\n\t{self.HSTS}\n\t{self.URL}\n\t{self.reqCount}")
		resultarray = [self.URL,self.HSTS]
		return resultarray
	#Note to self: all HTTP headers are case insensitive - https://tools.ietf.org/html/rfc7230#section-3.2


def doRequests(target):
	print(f"\n\nTesting {target}\n\n")
	masterresults[target] = {}
	for protocol in ['http','https']:
		try:
			r = requestHSTS()
			url = protocol+ "://" + target
			r.URL.append(url)
			r.makeRequest()
			r.printResults()
			masterresults[target]['URL'] = r.URL
			masterresults[target]['HSTS'] = r.HSTS
		except Exception as e:
			log(f"An exception occurred while processing {target}: {e}")
			errorresults.append(target)


def main():
	# Open CSV file. File contains list of top X domains to scan.
	csvfile = open('C:\\Temp\\majestic_ten.csv','r')
	csvreader = csv.reader(csvfile)
	masterresults = {}#{'target.com':{'URL':[],'HSTS':[]}}
	global masterresults
	errorresults = [] #Need to separate errors for http vs https.
	global errorresults
	# This stub makes all the requests and gathers the information
	for row in csvreader:
		target = row[2]
		doRequests(target)

	#Do things with results... mainly save them in JSON format for further processing		
	print(f"Results: {masterresults}")
	output = json.dumps(masterresults)
	jsonfile = open('C:\\Temp\\results.json','w')
	jsonfile.write(output)
	print(f"An error occurred with the following sites: {errorresults}")
	#20s for 10 sites
	#200s for 100 sites (2s/sites)
	#2000000s = 33,333 minutes = 555hrs = 23.14d

	vulns = {
		'No HSTS':[],
		'HTTPredirectstoHTTP':[],
		'HTTPreturnsHSTS':[],
		'preloadButNoIncludeSubDomains':[],
		'perfectHSTS':[],
		'badHSTSRedirect':[]

	}
	#stats
	countHTTP = 0
	countHTTPS = 0
	preload = 0
	eventualHSTSCount = 0  #HSTS on something in the chain.

	for site in masterresults:
		#{'target.com':{'URL':[url1,url2],'HSTS':[false,HSTSheader]}}
		eventualHSTS = False
		#Search all URLs for HSTS header
		for i in range(0,len(masterresults[site]['URL'])):
			#CHECKS IF HTTPS
			if 'https' in masterresults[site]['URL'][i]:
				countHTTPS += 1
				#CHECKS FOR NO HSTS (HSTS = false)
				if masterresults[site]['HSTS'][i] == False:
					log(f"Vuln Found. {masterresults[site]['URL'][i]} returns HSTS of {masterresults[site]['HSTS'][i]} ")
					vulns['No HSTS'].append(masterresults[site]['URL'][i])
				#HSTS = true
				else:
					eventualHSTS = True
					hstsparts = masterresults[site]['HSTS'][i].split(';')
					for part in hstsparts:
						part = part.rstrip().lstrip().lower()

						if "preload" in part:
							preload += 1
							#Preload without includeSubdomains
							if "include" not in masterresults[site]['HSTS'][i]:
								log(f"Misconfig Found. {masterresults[site]['URL'][i]} returns preload with no includeSubdomains ")
								vulns['preloadButNoIncludeSubDomains'].append(masterresults[site]['URL'][i])
						#Case E - max-age directive is super low < 2592000
						if "max-age" in part:
							age = part.split('=')[1]
							if int(age) < 2592000:
								log(f"Misconfig Found. max-age directive is less than 30 days: max-age={age}  ")
								vulns['preloadButNoIncludeSubDomains'].append(masterresults[site]['URL'][i])

			#HTTP
			else:
				countHTTP = 0
				if masterresults[site]['HSTS'][i] != False:
					log(f"Misconfig Found. {masterresults[site]['URL'][i]} returns HSTS of {masterresults[site]['HSTS'][i]} ")
				#Check for (near) perfect handling of HSTS
				#redirect HTTP --> HTTPS --> HSTS
				#Check if we have enough redirects
				if len(masterresults[site]['URL']) > i+1:
					#Check if domains are same
					if masterresults[site]['URL'][i].split(":")[1] == masterresults[site]['URL'][i+1].split(":")[1]:
						#Check HSTS in 2nd
						if masterresults[site]['HSTS'][i+1] != False:
							print(f"Perfect HSTS for {site}!")
							vulns['perfectHSTS'].append(site)
					else:
						log(f"Domains not equal... {masterresults[site]['URL'][i].split(":")[1]} VS {masterresults[site]['URL'][i+1].split(":")[1]}")
						#Check if first is a subdomain of the second.
						if masterresults[site]['URL'][i].split(":")[1] in masterresults[site]['URL'][i+1].split(":")[1]:
							#Check for includeSubdomains
							hstsparts = masterresults[site]['HSTS'][i+1].split(";")
							includesubs = False
							for part in hstsparts:
								if "includesubdomains" in part.lower():
									includesubs = True
							if includesubs:
								print(f"Wow, HSTS actually handled correctly.  Near perfect HSTS for {site}")
								vulns['perfectHSTS'].append(site)
							else:
								log(f"Vuln Found. {masterresults[site]['URL'][i]} redirects to different domain.")
								vulns['badHSTSRedirect'].append(masterresults[site]['URL'][i])

						#Not a subdomain... misconfigured.	
						else:
							log(f"Vuln Found. {masterresults[site]['URL'][i]} redirects to different domain.")
							vulns['badHSTSRedirect'].append(masterresults[site]['URL'][i])

		if eventualHSTS:
			eventualHSTSCount += 1





		#Case H - domain is in preload list but no preload directive is given
		
	#Benchmarking for testing purposes
	end_time = datetime.now()
	diff = end_time - initial_time
	print(f"Seconds that have elapsed: {diff.seconds}")

main()
#test