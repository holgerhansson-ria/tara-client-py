from django.shortcuts import render, redirect
from django import forms

from .clientconf import *

import urllib, base64, json, jwt, requests


class parameterForm(forms.Form):
    client_id = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Client ID", "id": "client_id", 'class': "form-control"}))
    secret = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Client Secret", "id": "secret", 'class': "form-control"}))
    redirect_uri = forms.CharField(required=False, max_length=60, widget=forms.TextInput(attrs={'placeholder': "Redirect URI", "id": "redirect_uri", 'class': "form-control"}))
    scope = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Scope", "id": "scope", 'class': "form-control"}))
    state = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "State", "id": "state", 'class': "form-control"}))
    response_type = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Response Type", "id": "response_type", 'class': "form-control"}))
    grant_type = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Grant Type", "id": "grant_type", 'class': "form-control"}))
    code = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Code", "id": "code", 'class': "form-control"}))

# Create HTML friendly parameters
def readableParams(params):
	readable_params = urllib.parse.parse_qs(params)
	readable_params = {k:v[0] for k, v in readable_params.items()}
	return readable_params

def generateAuthHeader(client_id, secret):
	
	# Combine client_id and secret into one string
	combined = client_id+":"+secret

	# Encode client_id and secret
	try:
		b64auth = base64.b64encode(bytes(combined,'ascii')).decode('ascii')
		print("Created new authorization header value")
	except Exception as err:
		print(err)
		b64auth = ""

	return b64auth

def testclient(request, updated=False):

	# Import default values from clientconf.py
	if updated == False:
		params = default_params

	# Initiate form for parameters
	form = parameterForm()

	# If user submits changes to parameters
	if request.method == 'POST':
		updated = True

		form = parameterForm(request.POST)
		if form.is_valid():
			clean_data = form.cleaned_data

		posted_params_list = list(clean_data.keys())

		# Change all new posted parameters
		for new_param in posted_params_list:
			if clean_data.get(new_param) != "":
				params[new_param] = clean_data.get(new_param)

	# Build authorization code GET query
	auth_query_params = urllib.parse.urlencode({'scope': params['scope'], 'client_id': params['client_id'], 'response_type': params['response_type'], 'redirect_uri': params['redirect_uri'], 'state': params['state']}, doseq=True)
	auth_query = params['authUrl'] + "?" + auth_query_params

	# If user requests authorization code
	if(request.GET.get('auth')):
		return redirect(auth_query)

	# If URL /callback receives a code from server
	if(request.GET.get('code')):

		# Won't load old code value
		updated = True

		# Extract code from received GET response and update code in cookie
		message = request.GET
		params['code'] = request.GET.get('code')

		return render(request, 'client/testclient.html', {'message': message, 'code': params['code'], 'form': form, 'auth_query': auth_query, 'params': params})

	# If user requests a id token
	if(request.GET.get('idtoken')):

		try:
			# DISABLED: POST request logger
			# http_logger = urllib.request.HTTPSHandler(debuglevel = 1)
			# opener = urllib.request.build_opener(http_logger)
			# urllib.request.install_opener(opener)

			# Encode POST query parameters and create POST request
			tokenUrl = params['tokenUrl']
			b64value = generateAuthHeader(params['client_id'], params['secret'])
			post_params = urllib.parse.urlencode({'grant_type': params['grant_type'], 'code': params['code'], 'redirect_uri': params["redirect_uri"]}).encode("utf-8")
			post_query = urllib.request.Request(tokenUrl, post_params)
			post_query.add_header('Authorization','Basic '+ b64value)

			post_params = readableParams(post_params.decode("utf-8"))

			message = ""
			response_error = ""

			try:
				# Send request and read response message
				post_request = urllib.request.urlopen(post_query)
				message = post_request.read().decode("utf-8")

				# Convert str response to dict, decode jwt
				message = json.loads(message)
				message["id_token"] = jwt.decode(message["id_token"], algorithm='RS256', verify=False)

				# Extract POST response headers and their values
				headers = post_request.info().items()

			except urllib.error.HTTPError as e: 
				response_error = e
				headers = e.headers.items()

		except Exception as e:
			response_error = e
			message = ""
			headers = ""
			b64value = ""
			tokenUrl = ""
			post_params = ""

		return render(request, 'client/testclient.html', {'message': message, 'headers': headers, 'response_error': response_error, 'post_params': post_params, 'form': form, 'auth_query': auth_query, 'params': params, 'b64value': b64value, 'tokenUrl': tokenUrl})
	
	else:
		return render(request, 'client/testclient.html', {'form': form, 'auth_query': auth_query, 'params': params})
