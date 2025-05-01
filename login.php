<?php
session_start();
$errors = [];

// Database configuration
$host = 'localhost';
$user = 'root'; 
$pass = '';     
$db = 'tesla';

try {
    $conn = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Process login form
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $remember = isset($_POST['remember']);

        // Validate inputs
        if (empty($email)) {
            $errors[] = "Email is required";
        }
        
        if (empty($password)) {
            $errors[] = "Password is required";
        }

        if (empty($errors)) {
            // Check user credentials
            $stmt = $conn->prepare("SELECT id, name, email, pass FROM login WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['pass'])) {
                // Successful login
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_name'] = $user['name'];
                
                // Remember me functionality
                if ($remember) {
                    $token = bin2hex(random_bytes(32));
                    setcookie('remember_token', $token, time() + 86400 * 30, "/"); // 30 days
                    
                    // Store token in database
                    $update = $conn->prepare("UPDATE login SET remember_token = ? WHERE id = ?");
                    $update->execute([$token, $user['id']]);
                }
                
                header("Location: index.html");
                exit;
            } else {
                $errors[] = "Invalid email or password";
            }
        }
    }
} catch(PDOException $e) {
    $errors[] = "Database error. Please try again later.";
    error_log("Login error: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="login.css">
  <title>TESLA - Login</title>
  <link rel="icon" href="imgs/R.png" sizes="16x16" type="image/x-icon"> 
</head>

<body class="bg">
    <div class="container">
        <div class="login-box">
          <div class="login-tab">Login</div>
          
          <?php if (!empty($errors)): ?>
            <div class="error-container">
              <?php foreach ($errors as $error): ?>
                <div class="error-message"><?php echo htmlspecialchars($error); ?></div>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>
          
          <form method="POST">
            <div class="input-group">
              <input type="text" name="email" placeholder="Email" 
                    value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required>
              <span class="icon"></span>
            </div>
            <div class="input-group">
              <input type="password" name="password" placeholder="Password" required>
              <span class="icon"></span>
            </div>
            <div class="options">
              <label><input type="checkbox" name="remember"> Remember me</label>
              <a href="Forget_password.html">Forgot password?</a>
            </div>
            <button type="submit">Login</button>
            <p class="register">Don't have an account? <a href="Register.html">Register</a></p>
          </form>
        </div>
      </div>
</body>
</html>