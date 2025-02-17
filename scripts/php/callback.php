<?php

session_start();

// Configuration variables
$clientId = '##YOURAPPID##';
$clientSecret = '##YOURAPPSECRET##';
$redirectUri = 'https://##HOSTNAME##/##PHPCALLBACKPATH##/callback.php';
$tenantId = '##YOURTENANTID##';

// Get the authorization code from the query parameters
if (isset($_GET['code'])) {
  $code = $_GET['code'];

$allowedChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-';
$allowedLength = 1000;

if (preg_match($allowedChars, $code) || strlen($code) > $allowedLength)
{
  // Input is invalid, handle the error
  echo "Invalid input.";
  die();
}

  // Exchange the authorization code for an access token
  $tokenUrl = "https://login.microsoftonline.com/##YOURTENANTID##/oauth2/v2.0/token";

  $postData = [
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => $redirectUri,
    'client_id' => $clientId,
    'client_secret' => $clientSecret,
    ];

  // create the curl object and configure the options
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $tokenUrl);
  curl_setopt($ch, CURLOPT_POST, 1);
  curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

  // execute the curl
  $response = curl_exec($ch);
  curl_close($ch);

  // decode the json response
  $responseData = json_decode($response, true);

  // if the access_token was get, redirect the relevant data to secure_page.php
  if (isset($responseData['access_token'])) {
    // Successfully received tokens
    $_SESSION['access_token'] = $responseData['access_token'];
    $_SESSION['id_token'] = $responseData['id_token'];
    $_SESSION['refresh_token'] = $responseData['refresh_token'];
    $_SESSION['secure_page_token'] = '##EFAUTHNONCE##';
    // Redirect to a secure page or perform other actions
    header('Location: secure_page.php');
    exit();
   }
   else {
     echo 'Error retrieving tokens: ' . htmlspecialchars($responseData['error_description']);
   }

} else {
    echo 'No authorization code found in the URL.';
}

?>
