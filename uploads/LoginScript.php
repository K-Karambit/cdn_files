<?php

// header("Access-Control-Allow-Origin: *");
// header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
// header("Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept");
// header('Cache-Control: no-cache, no-store');

// Start the session (if not already started)
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'use_strict_mode' => true,
        'cookie_secure' => true,
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict'
    ]);
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/backend/config/database.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/backend/config/main.php';


// error_reporting(E_ALL);
// ini_set('display_errors', 0);
// set_error_handler([MainClass::class, 'customErrorHandler']);

if (isset($_POST['btn_login'])) {
    // Create an instance of the DatabaseClass
    $database = DatabaseClass::getInstance();

    $username = MainClass::sanitizeInput($_POST['username']);
    $password = MainClass::sanitizeInput($_POST['password']);

    // Use prepared statement to prevent SQL injection attacks
    $sql = "SELECT * FROM tbl_users WHERE username = :username";
    $stmt = $database->prepareAndExecute(
        $sql,
        [
            ':username' => $username,
        ]
    );

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($result && password_verify($password, $result['password_hashed'])) {
        // Passwords match
        $_SESSION['username'] = $result['username'];
        $_SESSION['user_id'] = $result['unique_id'];
        $_SESSION['role'] = $result['role'];
        $_SESSION['last_activity'] = time();
        $_SESSION['is_active'] = true;
        $_SESSION['is_logged_in'] = true;

        // Regenerate session ID to prevent session fixation attacks
        session_regenerate_id(true);

        // Redirect the user based on their role
        // $roleMappings = [
        //     'ADMIN' => $_SERVER["DOCUMENT_ROOT"] . '/frontend/views/index.php',
        //     'EMPLOYEE' => $_SERVER["DOCUMENT_ROOT"] . '/frontend/views/index.php',
        // ];

        $roleMappings = [
            'ADMIN' => 'http://app.osca.local/backend\scripts\auth\LoginScript.php',
            'EMPLOYEE' => 'http://app.osca.local/backend\scripts\auth\LoginScript.php',
        ];

        $redirectPath = $roleMappings[$result['role']] ?? '/frontend/auth/index.php?alert=user_not_found';

        header('Location: ' . $_SERVER["DOCUMENT_ROOT"] . $redirectPath);
        exit; // Ensure that no further code is executed after the redirect
    } else {
        // Incorrect username or password
        header('Location: ' . $_SERVER["DOCUMENT_ROOT"] . '/frontend/auth/index.php?alert=incorrect_credentials');
        exit; // Ensure that no further code is executed after the redirect
    }
}
