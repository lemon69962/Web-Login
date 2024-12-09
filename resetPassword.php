<?php
// resetPassword.php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $newPassword = $_POST['new_password'];
    $token = $_GET['token'];

    // Database connection
    $conn = new mysqli('localhost', 'root', '', 'user_management');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Verify the token
    $stmt = $conn->prepare("SELECT id, reset_token_expiry FROM users WHERE reset_token = ?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $expiry = $user['reset_token_expiry'];

        if (strtotime($expiry) > time()) {
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = ?");
            $stmt->bind_param("ss", $hashedPassword, $token);
            $stmt->execute();
            echo "Password successfully reset!";
        } else {
            echo "The password reset link has expired.";
        }
    } else {
        echo "Invalid token.";
    }
}
?>
