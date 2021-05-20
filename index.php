<?php
#	sign-in/sign-up example
#
#
#
# Start server session
session_start();

# Generate secret for individual session (Server Side Security)
$secret = generateNonce(64);
$hashed_secret = hash('sha512',$secret);
# Store secret in session
$_SESSION['secret']=$secret;

# Generate nonce for OAuth call (Provider Side Security)
$nonce = generateNonce(64);

// SETUP LOGIN TO GOOGLE
# Get Client ID Info from Database
$get_google_client_info_sql = "SELECT * FROM auth_provider_configs WHERE value='google' AND name='Google WGM0'";
$get_google_client_info_ret = pg_query($wgm_db,$get_google_client_info_sql);
$get_google_client_info = pg_fetch_assoc($get_google_client_info_ret);

// Get Google's OpenID Discovery Document
$discover_doc = json_decode(file_get_contents($GOOGLE_DISCOVERY_DOCUMENT));

# Identify OAuth Provider Endpoint
$auth_endpoint = $discover_doc->authorization_endpoint;
# Set OAuth Parameters
$response_type="code";
$client_id=$get_google_client_info['client_id'];
$scope=urlencode("openid email");
$redirect_url=$DEFAULT_REDIRECT_URI; // Redirect URI is preconfigured with the provider. In this example we use login.php
$google_state=urlencode("token=".$hashed_secret."&auth_provider=google&invite=".$invite);

// Complete Google OAuth URL
# This is the URL we send the user to for signing-in/signing-up
$google_oauth_url = $auth_endpoint."?response_type=".$response_type."&client_id=".$client_id."&scope=".$scope."&redirect_uri=".$redirect_url."&state=".$google_state."&nonce=".$nonce;

// Below is the HTML the user will interact with.
?>
<a id="google-login-button" class="btn btn-block btn-lg btn-social btn-google" href="
	<?php 
		echo $google_oauth_url; 

	?>
	">
		Google
	</a>
	
	
	
</main>

</body>
</html>

