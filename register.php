<?php
// Database configuration
$host = 'localhost';
$user = 'root'; 
$pass = '';     
$db = 'tesla';

try {
    // Create PDO connection
    $conn = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Process form submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Sanitize and validate inputs
        $name = trim(htmlspecialchars($_POST['name'] ?? ''));
        $email = trim(htmlspecialchars($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirmPassword'] ?? '';
        
        // Validate inputs
        $errors = [];
        
        if (empty($name)) {
            $errors[] = "Full name is required";
        }
        
        if (empty($email)) {
            $errors[] = "Email address is required";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format";
        }
        
        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters";
        } elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter and one number";
        }
        
        if ($password !== $confirmPassword) {
            $errors[] = "Passwords do not match";
        }
        
        // If no errors, proceed with registration
        if (empty($errors)) {
            // Check if email already exists
            $stmt = $conn->prepare("SELECT id FROM login WHERE email = ?");
            $stmt->execute([$email]);
            
            if ($stmt->rowCount() > 0) {
                header("Location: Register.html?error=Email+already+registered");
                exit;
            }
            
            // Hash password
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
            
            // Insert new user
            $insert = $conn->prepare("INSERT INTO login (name, email, pass) VALUES (?, ?, ?)");
            $insert->execute([$name, $email, $hashedPassword]);
            
            // Start session and redirect
            session_start();
            $_SESSION['user_email'] = $email;
            header("Location: login.html");
            exit;
        } else {
            // Redirect back with errors
            $errorString = implode("+", $errors);
            header("Location: Register.html?error=" . urlencode($errorString));
            exit;
        }
    }
} catch(PDOException $e) {
    // Handle specific duplicate email error
    if ($e->getCode() == 23000) {
        header("Location: Register.html?error=Email+already+registered");
    } else {
        error_log("Database error: " . $e->getMessage());
        header("Location: Register.html?error=Database+error");
    }
    exit;
}
?>