<?php

session_start();

// check for access_token
if (!isset($_SESSION['access_token'])) {
  // if is not found, move the user to a fallback page
  header('Location: failed.php');
  exit();
}

// Get the variables from the SESSION
$idToken = $_SESSION['id_token'];
$accessToken = $_SESSION['access_token'];

$allowedChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-';
$allowedLengthAccessToken = 2350;
$allowedLengthIdToken = 1020;

if (preg_match($allowedChars, $idToken) || preg_match($allowedChars, $accessToken) || strlen($idToken) > $allowedLengthIdToken || strlen($accessToken) > $allowedLengthAccessToken)
{
  // Input is invalid, handle the error
  echo "Invalid input.";
  die();
}

echo '<h1>Secure Page</h1>';
echo '<p>You are authenticated.';

// load GuzzleHttp library
require 'vendor/autoload.php';
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Cookie\CookieJar;

// Function to get the User Claims
function getUserClaims($accessToken) {
  $client = new Client();
  $url = 'https://graph.microsoft.com/oidc/userinfo';

  try {
    $response = $client->request('GET', $url, [
      'headers' => [
        'Authorization' => 'Bearer ' . $accessToken,
        'Accept' => 'application/json',
      ],
    ]);

    if ($response->getStatusCode() == 200) {
      $claims = json_decode($response->getBody(), true);
      return $claims;
    }
    else {
      throw new Exception('Failed to retrieve user information. Status code: ' . $response->getStatusCode());
    }
  }
  catch (RequestException $e) {
    echo 'HTTP Request failed: ' . $e->getMessage();
    return null;
  }
}

// Function to get the User Info
function getUserInfo($accessToken) {
  $client = new Client();
  $url = 'https://graph.microsoft.com/v1.0/me';

  try {
    $response = $client->request('GET', $url, [
      'headers' => [
        'Authorization' => 'Bearer ' . $accessToken,
        'Accept' => 'application/json',
      ],
    ]);

    if ($response->getStatusCode() == 200) {
      $userInfo = json_decode($response->getBody(), true);
      return $userInfo;
    }
    else {
            throw new Exception('Failed to retrieve user information. Status code: ' . $response->getStatusCode());
    }
  }
  catch (RequestException $e) {
    echo 'HTTP Request failed: ' . $e->getMessage();
    return null;
  }
}

// Encrypt function
function encrypt($data, $key, $nonce) {
    // Convert the key and nonce from hex to binary
    $key = hex2bin($key);
    $nonce = hex2bin($nonce);

    // Ensure the key and nonce are the correct length for AES-128-CTR
    if (strlen($key) !== 16) {
        throw new Exception("Key must be 16 bytes long.");
    }
    if (strlen($nonce) !== 16) {
        throw new Exception("Nonce must be 16 bytes long.");
    }

    // Set the cipher method
    $cipher = 'aes-128-ctr';

    // Encrypt the data
    $encrypted = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $nonce);

    // Encode the result in base64 to make it URL safe
    return base64_encode($encrypted);
}

// get the User Info
// -> You can see userInfo content with:
// echo '<pre>'; print_r($userInfo);
// -> And access specific content like:
// print_r($userInfo['id']);
$userInfo = getUserInfo($accessToken);
$userId = $userInfo['id'];
// If you want to check all info that you can retrieve from User Info, uncomment the below lines:
//echo "<pre>";
//print_r($userInfo);
//die();;

// get the User Claims
// $userClaims = getUserClaims($accessToken);
// Use the $userInfo above examples to access $userClaims content

// Initialize cookies array
$cookies = [];

// Function to extract cookies from response headers
function extractCookies($responseHeaders) {
    $cookies = [];
    foreach ($responseHeaders as $header) {
        if (preg_match('/^Set-Cookie:\s*([^;]*)/mi', $header, $matches)) {
            parse_str($matches[1], $cookie);
            $cookies = array_merge($cookies, $cookie);
        }
    }
    return $cookies;
}

// Function to format cookies as a string
function formatCookies($cookies) {
  $cookieString = '';
  foreach ($cookies as $key => $value) {
    $cookieString .= "$key=$value; ";
  }
  return rtrim($cookieString, '; ');
}

// Function to set cookies for the cURL session
function setCookies($ch, $cookies) {
  $cookieString = formatCookies($cookies);
  curl_setopt($ch, CURLOPT_COOKIE, $cookieString);
}

// Open a Session with EnginFrame and get the CSRF token
function getSession($endpoint) {
  // get JSESSIONID
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, "$endpoint/enginframe/vdi/vdi.xml?_uri=//com.enginframe.interactive/list.sessions");
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Ignore SSL validation
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // Ignore SSL host validation

  // Execute initial request to get cookies
  curl_setopt($ch, CURLOPT_HEADER, true);
  curl_setopt($ch, CURLOPT_NOBODY, true);

  $initialResponse = curl_exec($ch);
  $responseHeaders = explode("\r\n", $initialResponse);
  $cookies = extractCookies($responseHeaders);

  // Set cookies for the next request
  setCookies($ch, $cookies);

  // Execute actual request

  // to get CSRF token
  // Set cURL options
  curl_setopt($ch, CURLOPT_URL, "$endpoint/enginframe/CsrfGuardServlet");
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Ignore SSL validation
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // Ignore SSL host validation
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Referer: $endpoint/enginframe",
    "FETCH-CSRF-TOKEN: 1"
  ]);

  // Execute cURL request
  $response = curl_exec($ch);

  // Use regular expression to extract the token
  if (preg_match('/anti-csrftoken-a2z:([A-Z0-9-]+)/', $response, $matches)) {
    $token = $matches[1];
    return $token;
  }
  else {
    echo "Token not found\n";
    die();
  }

  // Close cURL session
  curl_close($ch);
}

// function to execute the Login into EnginFrame
function doLogin($token,$encrypted_user,$ef_pass) {
  $username = htmlspecialchars($encrypted_user, ENT_QUOTES, 'UTF-8');
  $password = htmlspecialchars($ef_pass, ENT_QUOTES, 'UTF-8');
  setcookie('JSESSIONID', $cookies["JSESSIONID"], time() + 3600, '/');
 
  echo '
    <form id="redirectForm" method="post" action="https://##EFENDPOINT##/enginframe/vdi/vdi.xml?_uri=//com.enginframe.interactive/list.sessions">
      <!--         <form id="redirectForm" method="post" action="https://##EFENDPOINT##/enginframe/vdi/vdi.admin.xml?_uri=//vdi.admin/manage.services">  -->
      <input type="hidden" name="_username" value="' . $username . '">
      <input type="hidden" name="_password" value="' . $password . '">
      <input type="hidden" name="anti-csrftoken-a2z" value="' . htmlspecialchars($token) . '">
    </form>
    <script>
      document.getElementById("redirectForm").submit();
    </script>';
        exit();
}

// set the EnginFrame endpoint
$endpoint = "https://##EFENDPOINT##";

// EnginFrame user and password
// If you want to change which user will be informed to EnginFrame, please modify the $userID variable with the login that you want to set
$ef_user = $userId;
date_default_timezone_set('UTC');
$current_time = date('Y-m-d H:i:s');
$ef_user .=";" . $current_time;
$ef_pass = $accessToken;

// Use a 16-byte key for aes-128
// Just needed if you want to encrypt any data to send to EnginFrame
$key = '##EFAUTHSECRETKEY##';
// Nonce for encryption (must be 16 bytes for aes-128-ctr)
$nonce = '##EFAUTHNONCE##';
// Encrypt the user and the password
$encrypted_user = encrypt($ef_user, $key, $nonce);

// Get the CSRF token
$token = getSession($endpoint);

// Execute the login
doLogin($token,$encrypted_user, $ef_pass);
?>
