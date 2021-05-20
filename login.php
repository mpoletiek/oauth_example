<?php
// Start Session
session_start();

// If Session doesn't exist, redirect
# Check for proper session
if(!isset($_SESSION['secret']))
{
		header("location: /");
}
$secret=$_SESSION['secret'];
$hashed_secret=hash('sha512',$secret);

# Google returns information we can use to validate the user along with the state we passed earlier we check for validity on our side.
// We should be receiving a token and a auth_provider. Parse that out from $_GET['state'] or $_POST['state']
if(isset($_GET['state'])){
	if(preg_match('/^token=(.*)&auth_provider=(.*)&invite=(.*)$/',urldecode($_GET['state']),$matches)){
		$token = $matches[1];
		$auth_provider = $matches[2];
		$invite_code = $matches[3];
	}
	elseif(preg_match('/^token=(.*)&auth_provider=(.*)$/',urldecode($_GET['state']),$matches)){
		$token = $matches[1];
		$auth_provider = $matches[2];
		$invite_code = '-';
	}
}
elseif(isset($_POST['state'])){
	if(preg_match('/^token=(.*)&auth_provider=(.*)&invite=(.*)$/',urldecode($_POST['state']),$matches)){
		$token = $matches[1];
		$auth_provider = $matches[2];
		$invite_code = $matches[3];
	}
	elseif(preg_match('/^token=(.*)&auth_provider=(.*)$/',urldecode($_POST['state']),$matches)){
		$token = $matches[1];
		$auth_provider = $matches[2];
		$invite_code = '-';
	}
}

# Check the state returned for valid data
if(!$token || !$auth_provider){
	error_log("Didn't receive token or auth_provider");
	header("Location: /");
}

// Get Google's OpenID Discovery Document
$discover_doc = json_decode(file_get_contents($GOOGLE_DISCOVERY_DOCUMENT));

# Validate token provided in state
if($token == $hashed_secret){ // Valid Login, check Auth Provider
	
	// Check for valid auth_provider
	if($auth_provider == "google"){
			
		# Get Client ID (setup provider side, stored in Database)
		$get_google_client_info_sql = "SELECT * FROM auth_provider_configs WHERE value='google' AND name='Google WGM0'";
		$get_google_client_info_ret = pg_query($db,$get_google_client_info_sql);
		$get_google_client_info = pg_fetch_assoc($get_google_client_info_ret);
	
		# Get user information from Google
		# Set Parameters
		$data = array('code' => $_GET['code'], 'client_id' => $get_google_client_info['client_id'], 'client_secret' => $get_google_client_info['client_secret'], 'grant_type' => 'authorization_code', 'redirect_uri' => $DEFAULT_REDIRECT_URI);
		$data_json = json_encode($data);
		$token_endpoint=$discover_doc->token_endpoint;
		
		# Post to OAuth Endpoint to get User Information
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $token_endpoint);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS,$data_json);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		# Receive JWT Response
		$response  = json_decode(curl_exec($ch));
		curl_close($ch);
		
		# Parse the JWT
		$jwt = $response->id_token;
		preg_match('/^(.*)\.(.*)\.(.*)$/',$jwt,$matches);
		$jwt_header = base64_decode($matches[1]);
		$jwt_payload = json_decode(base64_decode($matches[2]));
		$jwt_sig = base64_decode($matches[3]);
		
		// Store User Info in Server Session
		$_SESSION['email'] = $jwt_payload->email;
		$_SESSION['account'] = $jwt_payload->sub;
		$_SESSION['auth_provider'] = $auth_provider_id;
		
		// Does the user already exist?
		if(userExists()){
			// 	Yes? - Check for Service
			if(userHasAccess()){
				// User has Service, forward them behind paywall
			}
			else{
				// User doesn't have Service, send to paywall
			}
		}
		else{
			// No? - Create User
			if(createUser()){
				// User Created, Offer Service
			}
		}
				
	}
	else{
		error_log("Unknown Auth Provider");
		header("Location: /");
	}
	
}
else{
	error_log("Invalid session for login.php");
	error_log("token: ".$token);
	error_log("Sesh: ".$hashed_secret);
	header("Location: /");
}

?>






