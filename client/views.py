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

def updateAuthQParams(params, removed_params=[]):
	auth_query_params = {'scope': params['scope'], 'client_id': params['client_id'], 'response_type': params['response_type'], 'redirect_uri': params['redirect_uri'], 'state': params['state']}
	for param in removed_params:
		auth_query_params.pop(param, None)
	return auth_query_params

def updateIdQParams(params, removed_params=[]):
	id_query_params = {'grant_type': params['grant_type'], 'code': params['code'], 'redirect_uri': params["redirect_uri"]}
	for param in removed_params:
		id_query_params.pop(param, None)
	return id_query_params

def testclient(request):

	# Initiate form for parameters
	form = parameterForm()
	context = {'form': form}

	# Use updated values or use default ones 
	if request.session.has_key('updated') and request.session['updated'] == True:
		# All parameters
		if request.session.has_key('params'):
			params = request.session['params']
			context.update({'params': params})
		# All parameters, which are removed from queries
		if request.session.has_key('params_removed'):
			params_removed = request.session['params_removed']
		# Authorization code query
		if request.session.has_key('auth_query'):
			auth_query = request.session['auth_query']
			context.update({'auth_query': auth_query})
	else:
		params = default_params
		params_removed = []
		context.update({'params': params})

	# If URL /callback receives a code from server, update the values
	if(request.GET.get('code')):
		params['code'] = request.GET.get('code')
		request.session['params'] = params
		context.update({'response_msg': request.GET, 'code': params['code']})
	
	# If user submits changes to parameters
	if request.method == 'POST':
		request.session['updated'] = True

		form = parameterForm(request.POST)

		if form.is_valid():
			clean_data = form.cleaned_data

		posted_params_list = list(clean_data.keys())
		params_removed = list()	

		# Change all new posted parameters
		for new_param in posted_params_list:
			if clean_data.get(new_param) != "":
				if clean_data.get(new_param) == "removed":
					params_removed.append(new_param)
					params[new_param] = "removed"
				else:
					params[new_param] = clean_data.get(new_param)
		
		# Save new values
		request.session['params'] = params
		request.session['params_removed'] = params_removed

	# If user requests authorization code
	if(request.GET.get('auth')):
		request.session['updated'] = True

		# Update & encode parameters for authorization code query
		auth_query_params = updateAuthQParams(params, params_removed)
		auth_url_params_encoded = urllib.parse.urlencode(auth_query_params, doseq=True)

		# Create redirect query & save response for template
		auth_url = params['authUrl'] + "?" + auth_url_params_encoded
		redirection = redirect(auth_url)
		auth_query = {'status_code': redirection.status_code, 'url': redirection.url}
		request.session['auth_query'] = auth_query
		return redirection

	# If user requests a id token
	if(request.GET.get('idtoken')):
		request.session['updated'] = True

		# DISABLED: POST request logger
		# http_logger = urllib.request.HTTPSHandler(debuglevel = 1)
		# opener = urllib.request.build_opener(http_logger)
		# urllib.request.install_opener(opener)

		# Update id token query POST parameters
		id_query_params = updateIdQParams(params, params_removed)

		# If client_id and client_secret values are present, then encode with base64
		if 'client_id' in params and 'secret' in params:
			b64value = generateAuthHeader(params['client_id'], params['secret'])
		elif 'client_id' in params:
			b64value = generateAuthHeader(params['client_id'],"")
		elif 'secret' in params:
			b64value = generateAuthHeader("", params['secret'])
		else:
			b64value = generateAuthHeader("", params['secret'])

		# Encode POST query parameters and create POST request
		tokenUrl = params['tokenUrl']
		post_query_params_encoded = urllib.parse.urlencode(id_query_params).encode("utf-8")
		post_query = urllib.request.Request(tokenUrl, post_query_params_encoded)
		post_query.add_header('Authorization','Basic '+ b64value)

		post_query_params_encoded = readableParams(post_query_params_encoded.decode("utf-8"))

		try: 
			# Send request and read response message
			post_request = urllib.request.urlopen(post_query)
			response_msg = post_request.read().decode("utf-8")

			# Convert str response to dict, decode jwt
			print(response_msg)
			response_msg = json.loads(response_msg)
			response_msg["id_token"] = jwt.decode(response_msg["id_token"], algorithm='RS256', verify=False)
			print(response_msg["id_token"])

			# Extract POST response headers and their values
			headers = post_request.info().items()

		except urllib.error.HTTPError as e: 
			response_msg = e
			headers = e.headers.items()

		context.update({'b64value': b64value, 'response_msg': response_msg, 'headers': headers, 'post_query_params_encoded': post_query_params_encoded})

	return render(request, 'client/testclient.html', context)