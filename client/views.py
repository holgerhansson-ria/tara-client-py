from django.shortcuts import render, redirect
from django import forms

from .clientconf import *

import urllib, base64, json, jwt, requests


class parameterForm(forms.Form):
    client_id = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Client ID", "id": "client_id", 'class': "form-control", 'autocomplete': "off"}))
    secret = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Client Secret", "id": "secret", 'class': "form-control", 'autocomplete': "off"}))
    redirect_uri = forms.CharField(required=False, max_length=60, widget=forms.TextInput(attrs={'placeholder': "Redirect URI", "id": "redirect_uri", 'class': "form-control", 'autocomplete': "off"}))
    scope = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Scope", "id": "scope", 'class': "form-control", 'autocomplete': "off"}))
    state = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "State", "id": "state", 'class': "form-control", 'autocomplete': "off"}))
    response_type = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Response Type", "id": "response_type", 'class': "form-control", 'autocomplete': "off"}))
    grant_type = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Grant Type", "id": "grant_type", 'class': "form-control", 'autocomplete': "off"}))
    code = forms.CharField(required=False, max_length=30, widget=forms.TextInput(attrs={'placeholder': "Code", "id": "code", 'class': "form-control", 'autocomplete': "off"}))

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

	# Try to import parameters from cookie
	try:
		if request.session['updated'] == True:
			updated = True
	except Exception e:
		print(e)

	# Import default values from clientconf.py; set initial values
	if updated == False:
		params = default_params
		auth_query_params = {'scope': params['scope'], 'client_id': params['client_id'], 'response_type': params['response_type'], 'redirect_uri': params['redirect_uri'], 'state': params['state']}
		post_query_params = {'grant_type': params['grant_type'], 'code': params['code'], 'redirect_uri': params["redirect_uri"]}


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
				if clean_data.get(new_param) == "removed":
					auth_query_params.pop(new_param, None)
					post_query_params.pop(new_param, None)
					params[new_param] = "removed"
				else:
					params[new_param] = clean_data.get(new_param)

	# Build authorization code GET query
	auth_query_params_ec = urllib.parse.urlencode(auth_query_params, doseq=True)
	auth_query = params['authUrl'] + "?" + auth_query_params_ec

	# If user requests authorization code
	if(request.GET.get('auth')):
		request.session['auth_query_params'] = auth_query_params
		request.session['post_query_params'] = post_query_params
		request.session['params'] = params
		request.session['auth_query'] = auth_query
		request.session['updated'] = True
		return redirect(auth_query)

	# If URL /callback receives a code from server
	if(request.GET.get('code')):

		# Get last values from session cookies
		auth_query_params = request.session['auth_query_params'] 
		post_query_params = request.session['post_query_params']
		params = request.session['params']
		auth_query = request.session['auth_query'] 
		print(auth_query)
		print(params)

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
			try:
					b64value = generateAuthHeader(params['client_id'], params['secret'])
			except KeyError as ke:
				b64value = generateAuthHeader("","")
				print(ke)

			post_query_params_ec = urllib.parse.urlencode(post_query_params).encode("utf-8")
			post_query = urllib.request.Request(tokenUrl, post_query_params_ec)
			post_query.add_header('Authorization','Basic '+ b64value)

			post_query_params_ec = readableParams(post_query_params_ec.decode("utf-8"))

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
			post_query_params_ec = ""

		return render(request, 'client/testclient.html', {'message': message, 'headers': headers, 'response_error': response_error, 'post_query_params_ec': post_query_params_ec, 'form': form, 'auth_query': auth_query, 'params': params, 'b64value': b64value, 'tokenUrl': tokenUrl})
	
	else:
		return render(request, 'client/testclient.html', {'form': form, 'auth_query': auth_query, 'params': params})
