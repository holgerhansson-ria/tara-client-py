from django.shortcuts import render, redirect
from django import forms

from .clientconf import *

import urllib, base64, json, jwt, requests

class parameterForm(forms.Form):
    client_id = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Client ID", 'class': "form-control"}))
    secret = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Client Secret", 'class': "form-control"}))
    redirect_uri = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Redirect URI", 'class': "form-control"}))

# Create HTMl friendly parameters
def readableParams(params):
	readable_params = urllib.parse.parse_qs(params)
	readable_params = {k:v[0] for k, v in readable_params.items()}
	return readable_params

def updateParams(old_params, new_id=None, new_uri=None):
	# Extract old parameters
	params = urllib.parse.parse_qs(old_params)

	try:
		if new_uri not in (None, ""):
			params["redirect_uri"][0] = new_uri
			print("Updated URI")
		else:
			print("Cannot update URL, because new_uri parameter is empty")
	except KeyError: 
		print("No redirect uri in URL")
	try:
		if new_id not in (None, ""):
			params["client_id"][0] = new_id
			print("Updated client_id")
		else:
			print("Cannot update client id, because client ID parameter is empty")
	except KeyError: 
		print("No client_id in URL")

	finally:
		# Encode the updated URL
		params = urllib.parse.urlencode(params, doseq=True)
		return params

def generateAuthHeader(old_id=defaultClientId, new_id=None, old_secret=defaultSecret, new_secret=None):
	isnew = False
	if new_id not in (None, ""):
		client_id = new_id
		isnew = True
	else: client_id = old_id
	if new_secret not in (None, ""):
		secret = new_secret
		isnew = True
	else: secret = old_secret
	
	combined = client_id+":"+secret

	# Encode client_id and secret
	try:
		b64auth = base64.b64encode(bytes(combined,'ascii')).decode('ascii')
		if isnew: print("Created new authorization header value")
	except Exception as err:
		print(err)
		b64auth = ""

	return b64auth

def testclient(request):

	# Initiate variables
	response = ""
	updated_query_params = None
	received_id = None
	code = None
	headers = None
	message = None
	params = None
	form = parameterForm()

	# Import default values from clientconf.py
	defaultUrl = defaultAuthUrl
	client_id = defaultClientId
	client_secret = defaultSecret
	scope = defaultScope
	response_type = defaultResponse_type
	redirect_uri = defaultRedirect_uri
	state = defaultState

	# Encode authorization query parameters and add to URL
	query_params = urllib.parse.urlencode({'scope': scope, 'client_id': client_id, 'response_type': response_type, 'redirect_uri': redirect_uri, 'state': state}, doseq=True)
	url_with_params = defaultUrl + "?" + query_params

	# Generate b64 encoded Authorization header value (client_id:secret)
	b64auth = generateAuthHeader()

	# If user submits changes to parameters
	if request.method == 'POST':
		form = parameterForm(request.POST)
		if form.is_valid():
			cd = form.cleaned_data
			request.session['client_id'] = cd['client_id']
			request.session['secret'] = cd['secret']
			request.session['redirect_uri'] = cd['redirect_uri']

			# Update query parameters & URL
			updated_query_params = updateParams(query_params, request.session['client_id'], request.session['redirect_uri'])
			updated_url_with_params = defaultUrl + "?" + updated_query_params

			# Update Authorization URL
			b64auth = generateAuthHeader(client_id, request.session['client_id'], client_secret, request.session['secret'])
			request.session['b64'] = b64auth

			# Empty cookie values
			request.session['client_id'] = ""
			request.session['secret'] = ""
			request.session['redirect_uri'] = ""

	# If user requests authorization code
	if(request.GET.get('auth')):
		if updated_query_params is None:
			return redirect(url_with_params)
		else:
			return redirect(updated_url_with_params)

	# If URL /response receives a code from server
	if(request.GET.get('code')):
		# Extract code from received GET response and update code in cookie
		message = request.GET
		code = request.GET.get('code')
		request.session['code'] = code

		if updated_query_params is None:
			return render(request, 'client/testclient.html', {'message': message, 'code': code, 'form': form, 'url_with_params': url_with_params, 'query_params': readableParams(query_params)})
		else:
			return render(request, 'client/testclient.html', {'message': message, 'code': code, 'form': form, 'url_with_params': updated_url_with_params, 'query_params': readableParams(updated_query_params)})

	# If user requests a id token
	if(request.GET.get('idtoken')):

		# DISABLED: POST request logger
		# http_logger = urllib.request.HTTPSHandler(debuglevel = 1)
		# opener = urllib.request.build_opener(http_logger)
		# urllib.request.install_opener(opener)

		if request.session['b64'] not in (None, ""):
			b64auth = request.session['b64']

		if updated_query_params not in (None, ""):
			redirect_uri = updated_query_params['redirect_uri']

		params = urllib.parse.urlencode({'grant_type': 'authorization_code', 'code': request.session['code'], 'redirect_uri': redirect_uri}).encode("utf-8")
		q = urllib.request.Request("https://tara-test.ria.ee/oidc/token", params)
		q.add_header('Authorization','Basic '+ b64auth)
		params = params.decode("utf-8")
		params = urllib.parse.parse_qs(params)
		params = {k:v[0] for k, v in params.items()}

		try:
			post_request = urllib.request.urlopen(q)
			message = post_request.read().decode("utf-8")

			# Convert str response to dict
			message = json.loads(message)
			message["id_token"] = jwt.decode(message["id_token"], algorithm='RS256', verify=False)

			# Extract POST response headers and their values
			headers = post_request.info().items()

		except urllib.error.HTTPError as e: 
			response = e
			headers = e.headers.items()

		return render(request, 'client/testclient.html', {'message': message, 'headers': headers, 'response': response, 'params': params, 'url_with_params': url_with_params, 'form': form, 'query_params': readableParams(query_params), 'b64value': b64auth})
	
	else:
		if updated_query_params is None:
			return render(request, 'client/testclient.html', {'response': response, 'url_with_params': url_with_params, 'form': form, 'query_params': readableParams(query_params)})
		else:
			return render(request, 'client/testclient.html', {'response': response, 'url_with_params': updated_url_with_params, 'form': form, 'query_params': readableParams(updated_query_params)})