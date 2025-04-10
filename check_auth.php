<?php
require_once('common_headers.php');
header('Content-Type: application/json');
error_reporting(0); // Suppress errors that could interfere with JSON response

if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_secure' => true,
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true
    ]);
}

$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

$authorized_domains = ['octro.com', 'octrotalk.com'];
$authorized_emails = ['muneesh@octro.com', 'shivang.gupta@octrotalk.com' , 'mohit.tiwari@octrotalk.com', 'jasmine.harit@octrotalk.com' , 'piyush.sharma@octrotalk.com'];
$admin_emails = ['muneesh@octro.com'];

function is_authorized($email) {
    global $authorized_domains, $authorized_emails;
    if (in_array($email, $authorized_emails)) {
        return true;
    }
    $domain = substr(strrchr($email, "@"), 1);
    return in_array($domain, $authorized_domains);
}

function is_admin($email) {
    global $admin_emails;
    return in_array($email, $admin_emails);
}

function send_to_dashboard($email) {
    $api_url = "http://localhost:5000/api/login_user";
    $headers = [
        "X-API-KEY: 4403ef5413d9ceadc1aae13821d0046ea38a6d175a936ba389723f1f03bac48a",
        "Content-Type: application/json"
    ];

    // Updated: Use full email address as username
    $user_data = [
        "platform" => "jenkins",
        "url" => "https://octro.atlassian.net/wiki/spaces/OD/pages/361005117/Utilities",
        "username" => $email,  // Store full email address
        "role" => "Developer",
        "status" => "Active"
    ];

    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($user_data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $response = curl_exec($ch);
    curl_close($ch);

    return $response;
}

if (isset($data['email'])) {
    $isAuthorized = is_authorized($data['email']);
    $isAdmin = is_admin($data['email']);

    if ($isAuthorized) {
        $_SESSION['user_email'] = $data['email'];
        $_SESSION['is_admin'] = $isAdmin;
        $_SESSION['last_activity'] = time();

        // Send user details to the dashboard
        $dashboard_response = send_to_dashboard($data['email']);
    }

    echo json_encode([
        'authorized' => $isAuthorized,
        'isAdmin' => $isAdmin,
        'dashboard_response' => json_decode($dashboard_response, true)
    ]);
    exit;
} else {
    session_destroy();
    echo json_encode([
        'authorized' => false,
        'isAdmin' => false
    ]);
    exit;
}
?>
