<?php

$client_secret = "nsoiJ6Q4YwuTPozf1A2I0ttzJiNMKAVx"; // This is a dummy value. Place your client_secret key here. You received it from Ecwid team in email when registering the app 
//$cipher = "AES-128-CBC";     
$iv = "abcdefghijklmnopqrstuvwx";// this can be generated random if you plan to store it for later but in this case e.g. openssl_random_pseudo_bytes($ivlen);
$cipher = "aes-128-gcm";
$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
$tag = 0;

// If this is a payment request

if (isset($_POST["data"])) {

// Functions to decrypt the payment request from Ecwid

  function getEcwidPayload($app_secret_key, $data) {
    // Get the encryption key (16 first bytes of the app's client_secret key)
    $encryption_key = substr($app_secret_key, 0, 16);

    // Decrypt payload
    $json_data = aes_128_decrypt($encryption_key, $data);

    // Decode json
    $json_decoded = json_decode($json_data, true);
    return $json_decoded;
  }

  function aes_128_decrypt($key, $data) {
    // Ecwid sends data in url-safe base64. Convert the raw data to the original base64 first
    $base64_original = str_replace(array('-', '_'), array('+', '/'), $data);

    // Get binary data
    $decoded = base64_decode($base64_original);

    // Initialization vector is the first 16 bytes of the received data
    $iv = substr($decoded, 0, 16);

    // The payload itself is is the rest of the received data
    $payload = substr($decoded, 16);

    // Decrypt raw binary payload
    $json = openssl_decrypt($payload, "aes-128-cbc", $key, OPENSSL_RAW_DATA, $iv);
    //$json = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $payload, MCRYPT_MODE_CBC, $iv); // You can use this instead of openssl_decrupt, if mcrypt is enabled in your system

    return $json;
  }

  // Get payload from the POST and decrypt it
  $ecwid_payload = $_POST['data'];

  // The resulting JSON from payment request will be in $order variable
  $order = getEcwidPayload($client_secret, $ecwid_payload);

  // Debug preview of the request decoded earlier
  echo "<h3>REQUEST DETAILS</h3>";

      // Account info from merchant app settings in app interface in Ecwid CP
      $cardNumber = $order['merchantAppSettings']['cardNumber'];
      $expirationMonth = $order['merchantAppSettings']['expirationMonth'];
      $expirationYear = $order['merchantAppSettings']['expirationYear'];

      // OPTIONAL: Split name field into two fields: first name and last name
      $fullName = explode(" ", $order["cart"]["order"]["billingPerson"]["name"]);
      $firstName = $fullName[0]; $lastName = $fullName[1];

      // Encode access token and prepare calltack URL template
      $ciphertext_raw = openssl_encrypt($order['token'],$cipher, $client_secret,$options=0,$iv,$tag);
      $callbackPayload = base64_encode( $ciphertext_raw);
      $callbackUrl = "https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"."?storeId=".$order['storeId']."&orderNumber=".$order['cart']['order']['orderNumber']."&callbackPayload=".$callbackPayload;

      // Request parameters to pass into payment gateway
      function SimpleAuthorizationInternet($flag)
{
	if (isset($flag) && $flag == "true") {
		$capture = true;
	} else {
		$capture = false;
	}
	
	$clientReferenceInformationArr = [
			"code" => "TC50171_3"
	];
	$clientReferenceInformation = new CyberSource\Model\Ptsv2paymentsClientReferenceInformation($clientReferenceInformationArr);

	$processingInformationArr = [
      "capture" => $capture,
	];
	$processingInformation = new CyberSource\Model\Ptsv2paymentsProcessingInformation($processingInformationArr);

	$paymentInformationCardArr = [
			"number" => $cardNumber,
			"expirationMonth" => $expirationMonth,
      "expirationYear" => $expirationYear,
      "type" => "001",
      "useAs"=> "CREDIT"
	];
	$paymentInformationCard = new CyberSource\Model\Ptsv2paymentsPaymentInformationCard($paymentInformationCardArr);

	$paymentInformationArr = [
			"card" => $paymentInformationCard
	];
	$paymentInformation = new CyberSource\Model\Ptsv2paymentsPaymentInformation($paymentInformationArr);

	$orderInformationAmountDetailsArr = [
			"totalAmount" => $order["cart"]["order"]["total"],
			"currency" => $order["cart"]["currency"],
	];
	$orderInformationAmountDetails = new CyberSource\Model\Ptsv2paymentsOrderInformationAmountDetails($orderInformationAmountDetailsArr);

	$orderInformationBillToArr = [
			"firstName" => $firstName,
			"lastName" => $lastName,
			"address1" => str_replace(PHP_EOL, ' ', $order["cart"]["order"]["billingPerson"]["street"]),
			"locality" => $order["cart"]["order"]["billingPerson"]["city"],
			"administrativeArea" => $order["cart"]["order"]["billingPerson"]["stateOrProvinceCode"],
			"postalCode" => $order["cart"]["order"]["billingPerson"]["postalCode"],
			"country" => $order["cart"]["order"]["billingPerson"]["countryCode"],
			"email" => $order["cart"]["order"]["email"],
			"phoneNumber" => $order["cart"]["order"]["billingPerson"]["phone"],
	];
	$orderInformationBillTo = new CyberSource\Model\Ptsv2paymentsOrderInformationBillTo($orderInformationBillToArr);

	$orderInformationArr = [
			"amountDetails" => $orderInformationAmountDetails,
			"billTo" => $orderInformationBillTo
	];
	$orderInformation = new CyberSource\Model\Ptsv2paymentsOrderInformation($orderInformationArr);

	$requestObjArr = [
			"clientReferenceInformation" => $clientReferenceInformation,
			"processingInformation" => $processingInformation,
			"paymentInformation" => $paymentInformation,
			"orderInformation" => $orderInformation
	];
	$requestObj = new CyberSource\Model\CreatePaymentRequest($requestObjArr);


	$commonElement = new CyberSource\ExternalConfiguration();
	$config = $commonElement->ConnectionHost();
	$merchantConfig = $commonElement->merchantConfigObject();

	$api_client = new CyberSource\ApiClient($config, $merchantConfig);
	$api_instance = new CyberSource\Api\PaymentsApi($api_client);

	try {
		$apiResponse = $api_instance->createPayment($requestObj);
		print_r(PHP_EOL);
		print_r($apiResponse);

		return $apiResponse;
	} catch (Cybersource\ApiException $e) {
		print_r($e->getResponseBody());
		print_r($e->getMessage());
	}
}

if(!defined('DO_NOT_RUN_SAMPLES')){
	echo "\nSimpleAuthorizationInternet Sample Code is Running..." . PHP_EOL;
	SimpleAuthorizationInternet('false');
}

        // Sign the payment request
        $signature = payment_sign($orderInformationBillTo) //($request,$api_key);
        $request["x_signature"] = $signature;

        // Print the request variables to debug
        echo "<br/>";
        foreach ($orderInformationBillTo as $name => $value) {
          echo "$name: $value<br/>";
        }
        echo "<br/>";

        // Print form on a page to submit it from a button press
        echo "<form action='https://example.paymentpage.com/checkout' method='post' id='payment_form'>";
            foreach ($orderInformationBillTo as $name => $value) {
                echo "<input type='hidden' name='$name' value='$value'></input>";
            }
        echo "<input type='submit' value='Submit'>";    
        echo "</form>";
        echo "<script>document.querySelector('#payment_form).submit();</script>";

}

      // Function to sign the payment request form
      function payment_sign($query) {
            $clear_text = '';
            ksort($query);
            foreach ($query as $key => $value) {
                if (substr($key, 0, 2) === "x_") {
                    $clear_text .= $key . $value;
                }
            }
            $hash = hash_hmac("sha256", $clear_text);
            return str_replace('-', '', $hash);
      }


// If we are returning back to storefront. Callback from payment

if (isset($_GET["callbackPayload"]) && isset($_GET["status"])) {

    // Set variables
    $client_id = "custom-app-28419181-1";
    $c = base64_decode($_GET['callbackPayload']);
    $token = openssl_decrypt($c, $cipher, $client_secret, $options=0, $iv,$tag);
    $storeId = $_GET['28419181'];
    $orderNumber = $_GET['orderNumber'];
    $status = $_GET['status']; 
    $returnUrl = "https://jncl.store/cart";
    //$returnUrl = "https://app.ecwid.com/custompaymentapps/$storeId?orderId=$orderNumber&clientId=$client_id";

    // Prepare request body for updating the order
    $json = json_encode(array(
        "paymentStatus" => $status,
        "externalTransactionId" => "transaction_".$orderNumber
    ));

    // URL used to update the order via Ecwid REST API
    $url = "https://app.ecwid.com/api/v3/$storeId/orders/transaction_$orderNumber?token=$token";
  
    // Send request to update order
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json','Content-Length: ' . strlen($json)));
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
    curl_setopt($ch, CURLOPT_POSTFIELDS,$json);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    // return customer back to storefront
    echo "<script>window.location = '$returnUrl'</script>";

}

else { 

  header('HTTP/1.0 403 Forbidden');
  echo 'Access forbidden!';

}

// function SimpleAuthorizationInternet($flag)
// {
// 	if (isset($flag) && $flag == "true") {
// 		$capture = true;
// 	} else {
// 		$capture = false;
// 	}
	
// 	$clientReferenceInformationArr = [
// 			"code" => "TC50171_3"
// 	];
// 	$clientReferenceInformation = new CyberSource\Model\Ptsv2paymentsClientReferenceInformation($clientReferenceInformationArr);

// 	$processingInformationArr = [
// 			"capture" => $capture
// 	];
// 	$processingInformation = new CyberSource\Model\Ptsv2paymentsProcessingInformation($processingInformationArr);

// 	$paymentInformationCardArr = [
// 			"number" => "4111111111111111",
// 			"expirationMonth" => "12",
// 			"expirationYear" => "2031"
// 	];
// 	$paymentInformationCard = new CyberSource\Model\Ptsv2paymentsPaymentInformationCard($paymentInformationCardArr);

// 	$paymentInformationArr = [
// 			"card" => $paymentInformationCard
// 	];
// 	$paymentInformation = new CyberSource\Model\Ptsv2paymentsPaymentInformation($paymentInformationArr);

// 	$orderInformationAmountDetailsArr = [
// 			"totalAmount" => "102.21",
// 			"currency" => "USD"
// 	];
// 	$orderInformationAmountDetails = new CyberSource\Model\Ptsv2paymentsOrderInformationAmountDetails($orderInformationAmountDetailsArr);

// 	$orderInformationBillToArr = [
// 			"firstName" => "John",
// 			"lastName" => "Doe",
// 			"address1" => "1 Market St",
// 			"locality" => "san francisco",
// 			"administrativeArea" => "CA",
// 			"postalCode" => "94105",
// 			"country" => "US",
// 			"email" => "test@cybs.com",
// 			"phoneNumber" => "4158880000"
// 	];
// 	$orderInformationBillTo = new CyberSource\Model\Ptsv2paymentsOrderInformationBillTo($orderInformationBillToArr);

// 	$orderInformationArr = [
// 			"amountDetails" => $orderInformationAmountDetails,
// 			"billTo" => $orderInformationBillTo
// 	];
// 	$orderInformation = new CyberSource\Model\Ptsv2paymentsOrderInformation($orderInformationArr);

// 	$requestObjArr = [
// 			"clientReferenceInformation" => $clientReferenceInformation,
// 			"processingInformation" => $processingInformation,
// 			"paymentInformation" => $paymentInformation,
// 			"orderInformation" => $orderInformation
// 	];
// 	$requestObj = new CyberSource\Model\CreatePaymentRequest($requestObjArr);


// 	$commonElement = new CyberSource\ExternalConfiguration();
// 	$config = $commonElement->ConnectionHost();
// 	$merchantConfig = $commonElement->merchantConfigObject();

// 	$api_client = new CyberSource\ApiClient($config, $merchantConfig);
// 	$api_instance = new CyberSource\Api\PaymentsApi($api_client);

// 	try {
// 		$apiResponse = $api_instance->createPayment($requestObj);
// 		print_r(PHP_EOL);
// 		print_r($apiResponse);

// 		return $apiResponse;
// 	} catch (Cybersource\ApiException $e) {
// 		print_r($e->getResponseBody());
// 		print_r($e->getMessage());
// 	}
// }

// if(!defined('DO_NOT_RUN_SAMPLES')){
// 	echo "\nSimpleAuthorizationInternet Sample Code is Running..." . PHP_EOL;
// 	SimpleAuthorizationInternet('false');
// }
?>
