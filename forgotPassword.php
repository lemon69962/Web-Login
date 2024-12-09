<?php
// forgotPassword.php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Handle sending reset email logic here

    $usernameOrEmail = $_POST['username'];

    // Database connection
    $conn = new mysqli('localhost', 'root', '', 'user_management');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Fetch user by username or email
    $stmt = $conn->prepare("SELECT id, email FROM users WHERE username = ? OR email = ?");
    $stmt->bind_param("ss", $usernameOrEmail, $usernameOrEmail);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $token = bin2hex(random_bytes(50));  // Generate a random token
        $expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));

        // Store the token and its expiry time in the database
        $stmt = $conn->prepare("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?");
        $stmt->bind_param("ssi", $token, $expiry, $user['id']);
        $stmt->execute();

        // Send the password reset email with the token link
        $resetLink = "http://yourdomain.com/resetPassword.php?token=$token";
        mail($user['email'], "Password Reset Request", "Click this link to reset your password: $resetLink");

        echo "An email with password reset instructions has been sent to you.";
    } else {
        echo "User not found!";
    }
}
?>
