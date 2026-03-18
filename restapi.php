<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/config.php';
require __DIR__ . '/firebase.php';

use Dotenv\Dotenv;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;


// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();


// Create Slim App
// $app = AppFactory::create();

// // Define the base path (make sure it's correctly set)
// $app->setBasePath(BASE_PATH);

// // Add Middleware
// $app->addRoutingMiddleware();
// $errorMiddleware = $app->addErrorMiddleware(true, true, true);

$app = AppFactory::create();

// Set base path to subfolder (important for live server)
$app->setBasePath('/protostar');

// Add Middleware
$app->addRoutingMiddleware();
$errorMiddleware = $app->addErrorMiddleware(true, true, true);



function sendMail($to, $subject, $message, $from = null) {
    $headers = 'MIME-Version: 1.0' . "\r\n" .
               'Content-Type: text/plain; charset=UTF-8' . "\r\n" .
               'X-Mailer: PHP/' . phpversion();
$from = 'Protostar <noreply@protostar.com>';

    if ($from) {
        $headers .= "\r\n" . 'From: ' . $from;
        // $headers .= "\r\n" . 'Reply-To: ' . $from;
    }

    return mail($to, $subject, $message, $headers);
}

$app->get('/test', function (Request $request, Response $response) {
    $response->getBody()->write("Slim is working!");
    // sendMail('prachi@rovista.in','test','test server smtp mail');
    return $response->withHeader('Content-Type', 'text/plain')->withStatus(200);
});

// Login 
$app->post('/login', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';
    $firebaseToken = $data['firebase_token'] ?? '';
    $deviceType = $data['device_type'] ?? '';
    if (empty($email) || empty($password)) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Email and password are required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Hash password using MD5 only
    $hashedPassword = md5($password);

    // Check if user exists
    $check_email = $db->prepare("SELECT * FROM users WHERE email = ? and is_active = 1");
    $check_email->execute([$email]);
    $user = $check_email->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Email not found']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    if ($hashedPassword !== $user['password_hash']) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Incorrect password']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Generate a session token
    $sessionToken = bin2hex(random_bytes(32));

    // Update Firebase Token & Store Session Token
    $update_tokens = $db->prepare("UPDATE users SET firebase_token = ?, token = ?,device_type = ? WHERE id = ?");
    $update_tokens->execute([$firebaseToken, $sessionToken, $deviceType, $user['id']]);

    // Return response
    $responseData = [
        'status' => 'success',
        'message' => 'Login successful',
        'user' => [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'mobile' => $user['mobile'],
            'role' => $user['role'],
            'token' => $sessionToken, 
            'firebase_token' => $firebaseToken, 
            'device_type' => $deviceType, 
            'is_active' => $user['is_active']
        ]
    ];
    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

//Forgot password

$app->post('/forgot-password', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    $email = trim($data['email'] ?? '');
    $otp_code = trim($data['otp_code'] ?? '');

    if (empty($email)) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Email is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    if (empty($otp_code) || !preg_match('/^\d{6}$/', $otp_code)) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'OTP must be a 6-digit number'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    //  Check if user exists
    $stmt = $db->prepare("SELECT id, name FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'User not found'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $user_id = $user['id'];
    $expiresAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

    // Save OTP in DB
    $stmt = $db->prepare("INSERT INTO password_resets (user_id, otp_code, expires_at) 
                          VALUES (?, ?, ?) 
                          ON DUPLICATE KEY UPDATE otp_code = ?, expires_at = ?");
    $stmt->execute([$user_id, $otp_code, $expiresAt, $otp_code, $expiresAt]);

$name = $user['name'];
    $sent = sendMail(
    $email,
    'Protostar Forgot Password OTP',
    "Hello $name,\n\nYour OTP for password reset is: $otp_code\n\nThis OTP is valid for 10 minutes."
);

if ($sent) {
    $response->getBody()->write(json_encode([
        'status' => 'success',
        'message' => 'OTP has been sent to the email.'
    ]));
     return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
} else {
    $response->getBody()->write(json_encode([
        'status' => 'error',
        'message' => 'Failed to send OTP email.'
    ]));
     return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
}
    

});


//Reset Password
$app->post('/reset-password', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    $email = trim($data['email'] ?? '');
    $otp = trim($data['otp_code'] ?? '');
    $new_password = trim($data['new_password'] ?? '');

    //  Validate input
    if (empty($email) || empty($otp) || empty($new_password)) {
        $error = ['status' => 'error', 'message' => 'All fields are required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    //  Ensure password strength
    if (strlen($new_password) < 8 || !preg_match('/[!@#$%^&*]/', $new_password)) {
        $error = ['status' => 'error', 'message' => 'Password must be at least 8 characters long and contain at least one special character (!@#$%^&*)'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    //  Fetch user_id from users table using email
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'User not found'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $user_id = $user['id'];

    //  Validate OTP for this user
    $stmt = $db->prepare("SELECT user_id FROM password_resets WHERE user_id = ? AND otp_code = ? AND expires_at > NOW()");
    $stmt->execute([$user_id, $otp]);
    $resetRecord = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$resetRecord) {
        $error = ['status' => 'error', 'message' => 'Invalid or expired OTP'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

//  Hash the new password using MD5
$hashed_password = md5($new_password);

    //  Update password in users table
    $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
    $stmt->execute([$hashed_password, $user_id]);

    //  Delete used OTP
    $stmt = $db->prepare("DELETE FROM password_resets WHERE user_id = ?");
    $stmt->execute([$user_id]);

    //  Return success response
    $success = ['status' => 'success', 'message' => 'Password reset successfully'];
    $response->getBody()->write(json_encode($success));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});




// Logout
$app->post('/logout', function (Request $request, Response $response) use ($db) {
    // Get token from request header
    $token = $request->getHeaderLine('Authorization');

    if (empty($token)) {
        $error = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if the token exists in the database
    $stmt = $db->prepare("SELECT id FROM users WHERE token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'Invalid token'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Invalidate the session token
    $update = $db->prepare("UPDATE users SET token = NULL WHERE id = ?");
    $update->execute([$user['id']]);

    $data = ['status' => 'success', 'message' => 'Logout successful'];
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    
});


// Clock In 
$app->post('/clock-in', function (Request $request, Response $response) use ($db) {
    // Get token from request header
    $token = $request->getHeaderLine('Authorization');

    if (empty($token)) {
        $error = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get user ID and selected vehicle from token
    $stmt = $db->prepare("SELECT id, selected_vehicle_id FROM users WHERE token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'Invalid token'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if a vehicle is selected
    if (!$user['selected_vehicle_id']) {
        $error = ['status' => 'error', 'message' => 'Please select a vehicle before clocking in'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Set timezone and get current date
    date_default_timezone_set('Asia/Kolkata');
    $current_date = date('Y-m-d');

    // Check if the user has already clocked in today
    $stmt = $db->prepare("SELECT id FROM user_attendance WHERE user_id = ? AND DATE(clock_in_at) = ?");
    $stmt->execute([$user['id'], $current_date]);
    $existingClockIn = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingClockIn) {
        $error = ['status' => 'error', 'message' => 'You have already clocked in today'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Record new clock-in time
    $stmt = $db->prepare("INSERT INTO user_attendance (user_id, clock_in_at) VALUES (?, ?)");
    $stmt->execute([$user['id'], date('Y-m-d H:i:s')]);

    $data = ['status' => 'success', 'message' => 'Clock-in successful'];
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// Clock-out
$app->post('/clock-out', function (Request $request, Response $response) use ($db) {
    // Get token from request header
    $token = $request->getHeaderLine('Authorization');

    if (empty($token)) {
        $error = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get user ID from token
    $stmt = $db->prepare("SELECT id FROM users WHERE token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'Invalid token'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Set timezone and get current date
    date_default_timezone_set('Asia/Kolkata');
    $current_date = date('Y-m-d');

    // Check if the user has already clocked out today
    $stmt = $db->prepare("SELECT id FROM user_attendance WHERE user_id = ? AND DATE(clock_out_at) = ?");
    $stmt->execute([$user['id'], $current_date]);
    $existingClockOut = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingClockOut) {
        $error = ['status' => 'error', 'message' => 'You have already clocked out today'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get the last clock-in record for the user (without clock-out)
    $stmt = $db->prepare("SELECT id FROM user_attendance WHERE user_id = ? AND clock_out_at IS NULL ORDER BY clock_in_at DESC LIMIT 1");
    $stmt->execute([$user['id']]);
    $clockIn = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$clockIn) {
        $error = ['status' => 'error', 'message' => 'No clock-in record found for today'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Update clock-out time
    $stmt = $db->prepare("UPDATE user_attendance SET clock_out_at = ? WHERE id = ?");
    $stmt->execute([date('Y-m-d H:i:s'), $clockIn['id']]);

    $data = ['status' => 'success', 'message' => 'Clock-out successful'];
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});



// Get vehicle types 
$app->get('/vehicle-types', function (Request $request, Response $response) use ($db) {
    // Fetch all vehicle types from the database
    $stmt = $db->prepare("SELECT id, type_name FROM vehicle_types");
    $stmt->execute();
    $vehicleTypes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Return the result as JSON
    if ($vehicleTypes) {
        // Set the content type and return the JSON response
        $response->getBody()->write(json_encode(['status' => 'success', 'data' => $vehicleTypes]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } else {
        // Set the content type and return the JSON response
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'No vehicle types found']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }
});

// Get vehicles as per user and vehicle type
$app->get('/vehicles', function (Request $request, Response $response) use ($db) {
    // Get token from request headers or query parameters
    $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        $error = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Step 1: Query the user ID based on the token
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'Invalid token'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Step 2: Get vehicle_type_id from query parameters
    $vehicleTypeId = $request->getQueryParams()['vehicle_type_id'] ?? 1;

    if (!$vehicleTypeId) {
        $error = ['status' => 'error', 'message' => 'Vehicle Type ID is required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Step 3: Query the vehicles based on the user ID and vehicle type ID
    $stmt = $db->prepare("
        SELECT v.id, v.vehicle_id, v.registration_no, v.color, v.year_of_registration, v.status_id, vs.status_name, vt.type_name , v.vehicle_type_id , u.name AS name
        FROM vehicles v
        JOIN vehicle_statuses vs ON v.status_id = vs.id
         JOIN vehicle_types vt ON v.vehicle_type_id = vt.id
         JOIN users u ON v.user_id = u.id
        WHERE v.is_active = 1
          AND vs.status_name = 'Available'
          AND v.vehicle_type_id = :vehicle_type_id
          AND v.user_id = :user_id
    ");
    $stmt->bindParam(':vehicle_type_id', $vehicleTypeId, PDO::PARAM_INT);
    $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
    $stmt->execute();
    $vehicles = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Return the result as JSON
    $responseData = $vehicles ? 
        ['status' => 'success', 'data' => $vehicles] : 
        ['status' => 'error', 'message' => 'No active and available vehicles found for this vehicle type'];

    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});



//get user

$app->get('/user', function (Request $request, Response $response) use ($db) {
    // Get token from request headers
    $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        // Return error response
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Query the user data based on the token
    $stmt = $db->prepare("SELECT id, name, email, mobile, gender, address, role, user_photo, is_active, created_at, updated_at FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Return error response
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token or user not found']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Return user data
    $response->getBody()->write(json_encode(['status' => 'success', 'data' => $user]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

// get notification as per user

$app->get('/notifications', function (Request $request, Response $response) use ($db) {
    // Get token from request headers or query parameters
    $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        $error = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Step 1: Fetch user ID based on token
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'Invalid token'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Step 2: Fetch notifications for the user in DESCENDING order (latest first)
    $stmt = $db->prepare("
        SELECT id,user_id, user_from, user_to, message, status, created_at, updated_at
        FROM notifications
        WHERE user_to = :user_id
        ORDER BY created_at DESC
    ");
    $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
    $stmt->execute();
    $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Return the result as JSON
    $responseData = $notifications ? 
        ['status' => 'success', 'data' => $notifications] : 
        ['status' => 'error', 'message' => 'No notifications found'];

    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// Read particular notification
$app->post('/notifications/read', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token from Header
    $token = $request->getHeaderLine('Authorization');

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Authorization token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get User ID
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get request body
    $data = $request->getParsedBody();
    if (!isset($data['notification_id'])) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Notification ID is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Update notification status to 'Read' only for the authenticated user
    $stmt = $db->prepare("
        UPDATE notifications 
        SET status = 'Read', updated_at = NOW() 
        WHERE id = :notification_id AND user_to = :user_id
    ");
    $stmt->bindParam(':notification_id', $data['notification_id'], PDO::PARAM_INT);
    $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $response->getBody()->write(json_encode(['status' => 'success', 'message' => 'Notification marked as read']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } else {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Notification not found or already read']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }
});

$app->get('/home', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token
    $token = $request->getHeaderLine('Authorization') ?? null;
    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate User Token
    $stmt = $db->prepare("
        SELECT 
            u.id, 
            u.name, 
            u.selected_vehicle_id, 
            v.vehicle_type_id, 
            vt.type_name AS vehicle_type
        FROM users u
        LEFT JOIN vehicles v ON u.selected_vehicle_id = v.id
        LEFT JOIN vehicle_types vt ON v.vehicle_type_id = vt.id
        WHERE u.token = :token 
        LIMIT 1
    ");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $user_id = $user['id'];

    // Get Unread Notification Count
    $stmt = $db->prepare("SELECT COUNT(*) AS unread_count FROM notifications WHERE user_to = :user_id AND status = 'Unread'");
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    $notificationCount = $stmt->fetch(PDO::FETCH_ASSOC)['unread_count'] ?? 0;

    // Get Today's Attendance Status
    $stmt = $db->prepare("
    SELECT clock_in_at, clock_out_at 
    FROM user_attendance 
    WHERE user_id = :user_id 
      AND DATE(clock_in_at) = CURDATE() 
    ORDER BY created_at DESC 
    LIMIT 1
");
$stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
$stmt->execute();
$attendance = $stmt->fetch(PDO::FETCH_ASSOC);

$attendance_status = false;
if ($attendance && !empty($attendance['clock_in_at']) && $attendance['clock_out_at'] === "0000-00-00 00:00:00") {
    $attendance_status = true;
}


    // Get Today's Assigned Jobs with total completed jobs and total hours
    $stmt = $db->prepare("
        SELECT 
            j.id, 
            j.job_id, 
            j.status_id, 
            j.vehicle_type_id, 
            j.customer_id, 
            c.customer_name, 
            c.customer_mobile, 
            m.marker_name, 
            vt.type_name, 
            js.status_name,
            v.id AS vehicle_id,
            v.registration_no,
            v.color,
            v.year_of_registration,
            CASE WHEN j.status_id = 4 THEN 1 ELSE 0 END AS completed_job, 
        ROUND(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600, 1) AS raw_hours,
IF(ROUND(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600, 1) LIKE '%.0', 
    FLOOR(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600), 
    ROUND(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600, 1)
) AS job_hours
        FROM jobs j
        JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
        JOIN job_statuses js ON j.status_id = js.id
        JOIN vehicles v ON j.vehicle_id = v.id
        JOIN customer c ON j.customer_id = c.id
        JOIN marker m ON j.marker_id = m.id
        WHERE j.user_id = :user_id 
          AND DATE(j.pickup_time) = CURDATE()
    ");

    // TIMESTAMPDIFF(HOUR, j.pickup_time, j.drop_time) AS job_hours
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Calculate total completed jobs and total hours
    $total_completed_jobs = 0;
    $total_hours = 0;

    foreach ($jobs as &$job) {
        $total_completed_jobs += $job['completed_job'];
// Prachi changed to avoid negative values
        $job_hours = $job['job_hours'] ?? 0;
        if ($job_hours > 0) {
            $total_hours += $job_hours;
        }
        // $total_hours += $job['job_hours'] ?? 0;
        unset($job['completed_job'], $job['job_hours']); // Remove individual completed jobs and job hours from each job entry
    }

    // Prepare Response
    $responseData = [
        'status' => 'success',
        'user' => [
            'id' => $user['id'],
            'name' => $user['name'],
        ],
        'vehicle' => $user['selected_vehicle_id'] ? [
            'selected_vehicle_id' => $user['selected_vehicle_id'],
            'vehicle_type_id' => $user['vehicle_type_id'],
            'vehicle_type' => $user['vehicle_type']
        ] : null,
        'notifications_unread_count' => $notificationCount,
        'clock_in' => $attendance_status,
        'total_completed_jobs' => $total_completed_jobs,
        'total_hours' => $total_hours,
        'todays_jobs' => $jobs
    ];

    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});






// Get job as per user
$app->get('/my_jobs', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token
    $token = $request->getHeaderLine('Authorization');

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Authorization token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get User ID
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Fetch Jobs for Authenticated User with Status Name
    $stmt = $db->prepare("
    SELECT 
        j.id,
        j.job_id, 
        j.customer_id,
        c.customer_name,
        c.customer_mobile,
        j.vehicle_type_id, 
        vt.type_name AS vehicle_type, 
        j.status_id,
        js.status_name,
        v.vehicle_id
    FROM jobs j
    LEFT JOIN job_statuses js ON j.status_id = js.id
    LEFT JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
    LEFT JOIN vehicles v ON j.vehicle_id = v.id
    LEFT JOIN customer c ON j.customer_id = c.id
    WHERE j.user_id = :user_id 
    ORDER BY j.created_at DESC
");

    $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
    $stmt->execute();
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode(['status' => 'success', 'jobs' => $jobs]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// Job/trip details
$app->post('/job_details', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token
    $token = $request->getHeaderLine('Authorization');
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Authorization token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get User ID
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get request body
   

    if (!isset($data['job_id'])) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Job ID is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $job_id = $data['job_id'];

    // Fetch Job Details based on job_id
    $stmt = $db->prepare("
        SELECT 
            j.id, 
            j.job_id, 
            j.customer_id,
            c.customer_name,
            c.customer_mobile,
            m.marker_name,
            j.marker_id,
            j.user_id, 
            j.vehicle_id, 
            j.pickup_address, 
            j.drop_address, 
            j.pickup_time, 
            j.drop_time,
              FORMAT(j.pick_latitude, 2) AS pick_latitude, 
        FORMAT(j.pick_longitude, 2) AS pick_longitude,  
             FORMAT(j.drop_latitude, 2) AS drop_latitude, 
        FORMAT(j.drop_longitude, 2) AS drop_longitude, 
            j.vehicle_type_id, 
              j.round_trip,  
            j.status_id, 
            js.status_name, 
            j.special_instructions, 
            j.trip_amount, 
            j.earning_amount, 
            j.completed_at, 
            j.created_at, 
            j.updated_at, 
            v.registration_no, 
            v.color, 
            v.year_of_registration, 
            vt.type_name, 
            u.name AS user_name, 
            u.mobile AS user_mobile
        FROM jobs j
        LEFT JOIN job_statuses js ON j.status_id = js.id
        LEFT JOIN vehicles v ON j.vehicle_id = v.id
        LEFT JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
        LEFT JOIN users u ON j.user_id = u.id
        LEFT JOIN marker m ON j.marker_id = m.id
        LEFT JOIN customer c ON j.customer_id = c.id
        WHERE j.id = :job_id
    ");

    $stmt->bindParam(':job_id', $job_id, PDO::PARAM_INT);
    $stmt->execute();
    $job = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($job) {
        $job['round_trip'] = (bool) $job['round_trip'];
    }
    if (!$job) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Job not found']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $response->getBody()->write(json_encode(['status' => 'success', 'jobs' => $job]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// Select Vehicle
$app->post('/select-vehicle', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token
    $token = $request->getHeaderLine('Authorization');
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get User ID
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get user ID and vehicle ID
    $user_id = $user['id'];
    if (!isset($data['vehicle_id'])) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Vehicle ID is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $vehicle_id = $data['vehicle_id'];

    // Get vehicle_type_id and vehicle_type from vehicles table
    $stmt = $db->prepare("
        SELECT v.id,v.vehicle_type_id, vt.type_name AS vehicle_type
        FROM vehicles v
        LEFT JOIN vehicle_types vt ON v.vehicle_type_id = vt.id
        WHERE v.id = :vehicle_id
    ");
    $stmt->bindParam(':vehicle_id', $vehicle_id, PDO::PARAM_INT);
    $stmt->execute();
    $vehicle = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$vehicle) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid Vehicle ID']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $vehicle_type_id = $vehicle['vehicle_type_id'];
    $vehicle_type = $vehicle['vehicle_type'];

    // Assign Vehicle to User
    $stmt = $db->prepare("UPDATE users SET selected_vehicle_id = :vehicle_id WHERE id = :user_id");
    $stmt->bindParam(':vehicle_id', $vehicle_id, PDO::PARAM_INT);
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();

    // Return success response with vehicle details
    $response->getBody()->write(json_encode([
        'status' => 'success',
        'message' => 'Vehicle selected successfully',
        'vehicle' => $vehicle
    ]));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});




// Update job status
// Update job status
$app->post('/update-job-status', function (Request $request, Response $response) use ($db) {
    date_default_timezone_set('Asia/Kolkata'); // Set to your timezone

    $token = $request->getHeaderLine('Authorization');
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    if (!$token) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "Authorization token is required"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get User ID
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "Invalid token"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $job_id = $data['job_id'] ?? null;
    $status_id = $data['status_id'] ?? null;

    if (!$job_id || !$status_id) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "job_id and status_id are required"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    date_default_timezone_set('Asia/Kolkata');
    // Check if Job Exists
    $stmt = $db->prepare("SELECT id FROM jobs WHERE id = :job_id LIMIT 1");
    $stmt->bindParam(':job_id', $job_id, PDO::PARAM_INT);
    $stmt->execute();
    $job = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$job) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "Job not found"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $stmt = $db->prepare("SELECT status_name FROM job_statuses WHERE id = :status_id LIMIT 1");
    $stmt->bindParam(':status_id', $status_id, PDO::PARAM_INT);
    $stmt->execute();
    $status = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Build update query
    $updateQuery = "UPDATE jobs SET status_id = :status_id, updated_at = NOW()";
    
    // If status is "Completed", update completed_at field
    if (strtolower($status['status_name']) === 'completed') {
        $updateQuery .= ", completed_at = NOW()";
    }else{
        $updateQuery .= ", completed_at = NULL";
    }


    $updateQuery .= " WHERE id = :job_id";

    // Update Job Status
    $stmt = $db->prepare($updateQuery);
    $stmt->bindParam(':status_id', $status_id, PDO::PARAM_INT);
    $stmt->bindParam(':job_id', $job_id, PDO::PARAM_INT);
    $stmt->execute();

    // Get Updated Status Name
    $stmt = $db->prepare("SELECT status_name FROM job_statuses WHERE id = :status_id LIMIT 1");
    $stmt->bindParam(':status_id', $status_id, PDO::PARAM_INT);
    $stmt->execute();
    $status = $stmt->fetch(PDO::FETCH_ASSOC);

    $responseData = [
        "status" => "success",
        "message" => "Job status updated successfully",
        "job_id" => $job_id,
        "status_id" => $status_id,
        "status_name" => $status['status_name'] ?? null
    ];

    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


//Change password inside user login 
$app->post('/change-password', function (Request $request, Response $response) use ($db) {
    // Get request data
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $user_id = $data['user_id'] ?? null;
    $old_password = $data['old_password'] ?? null;
    $new_password = $data['new_password'] ?? null;

    // Validate inputs
    if (!$user_id || !$old_password || !$new_password) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "user_id, old_password, and new_password are required."]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Fetch user details
    $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = :user_id LIMIT 1"); // Corrected column name
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "User not found."]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Convert old password to MD5 and compare
    if (md5($old_password) !== $user['password_hash']) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "Old password is incorrect."]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Hash the new password using MD5
    $hashedPassword = md5($new_password);

    // Update password in database
    $stmt = $db->prepare("UPDATE users SET password_hash = :new_password, updated_at = NOW() WHERE id = :user_id");
    $stmt->bindParam(':new_password', $hashedPassword);
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();

    // Success response
    $responseData = [
        "status" => "success",
        "message" => "Password changed successfully."
    ];
    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// Filter jobs
$app->get('/jobs/filter', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token
    $token = $request->getHeaderLine('Authorization');
    if (!$token) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "Authorization token is required"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get User ID
    $stmt = $db->prepare("SELECT id FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => "Invalid token"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get Filters from Query Params
    $params = $request->getQueryParams();
    $date_filter = $params['date_filter'] ?? 'all';
    $start_date = $params['start_date'] ?? null;
    $end_date = $params['end_date'] ?? null;
    $vehicle_type = $params['vehicle_type'] ?? null;
    $job_status = $params['job_status'] ?? null;
    $location = $params['location'] ?? null;

    // Convert date format to MySQL format
    if ($start_date) {
        $start_date = DateTime::createFromFormat('m-d-Y', $start_date)->format('Y-m-d');
    }
    if ($end_date) {
        $end_date = DateTime::createFromFormat('m-d-Y', $end_date)->format('Y-m-d');
    }
    // Base Query
    $base_sql = "SELECT j.*, js.status_name, vt.type_name, c.customer_name, c.customer_mobile, m.marker_name
                 FROM jobs j
                 LEFT JOIN job_statuses js ON j.status_id = js.id
                 LEFT JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
                 LEFT JOIN customer c ON j.customer_id = c.id
                 LEFT JOIN marker m ON j.marker_id = m.id
                 WHERE j.user_id = :user_id";

    // Date Filter
    if ($date_filter == "today") {
        $base_sql .= " AND DATE(j.created_at) = CURDATE()";
    } elseif ($date_filter == "this_week") {
        $base_sql .= " AND YEARWEEK(j.created_at, 1) = YEARWEEK(CURDATE(), 1)";
    } elseif ($date_filter == "custom" && $start_date && $end_date) {
        $base_sql .= " AND DATE(j.created_at) BETWEEN :start_date AND :end_date";
    }

    // Vehicle Type Filter
    if ($vehicle_type) {
        $base_sql .= " AND vt.type_name = :vehicle_type";
    }

    // Job Status Filter
    if ($job_status) {
        $base_sql .= " AND js.status_name = :job_status";
    }

    // Location Filter (using LIKE)
    if ($location) {
        $base_sql .= " AND (j.pickup_address LIKE :pickup_location OR j.drop_address LIKE :drop_location)";
    }

    // Prepare Query
    $stmt = $db->prepare($base_sql);
    $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);

    // Date Range Params
    if ($date_filter == "custom" && $start_date && $end_date) {
        $stmt->bindParam(':start_date', $start_date);
        $stmt->bindParam(':end_date', $end_date);
    }

    // Vehicle Type
    if ($vehicle_type) {
        $stmt->bindParam(':vehicle_type', $vehicle_type);
    }

    // Job Status
    if ($job_status) {
        $stmt->bindParam(':job_status', $job_status);
    }

    // Location (LIKE)
    if ($location) {
        $location = "%$location%";
        $stmt->bindParam(':pickup_location', $location, PDO::PARAM_STR);
        $stmt->bindParam(':drop_location', $location, PDO::PARAM_STR);
    }

    $stmt->execute();
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // If no result found with LIKE, try with latitude/longitude
    if (empty($jobs) && $location) {
        $geo_url = "https://nominatim.openstreetmap.org/search?format=json&q=" . urlencode($location);
        $options = [
            "http" => [
                "header" => "User-Agent: MyApp/1.0\r\n"
            ]
        ];
        $context = stream_context_create($options);
        $geo_response = file_get_contents($geo_url, false, $context);
        $geo_data = json_decode($geo_response, true);

        if (!empty($geo_data)) {
            $latitude = $geo_data[0]['lat'];
            $longitude = $geo_data[0]['lon'];

            // Now check using latitude and longitude
            $base_sql = "SELECT j.*, js.status_name, vt.type_name, c.customer_name, c.customer_mobile, m.marker_name
                         FROM jobs j
                         LEFT JOIN job_statuses js ON j.status_id = js.id
                         LEFT JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
                         LEFT JOIN customer c ON j.customer_id = c.id
                         LEFT JOIN marker m ON j.marker_id = m.id
                         WHERE j.user_id = :user_id
                         AND (
                             (ABS(j.pick_latitude - :latitude) < 0.01 AND ABS(j.pick_longitude - :longitude) < 0.01) OR
                             (ABS(j.drop_latitude - :latitude) < 0.01 AND ABS(j.drop_longitude - :longitude) < 0.01)
                         )";

            if ($vehicle_type) {
                $base_sql .= " AND vt.type_name = :vehicle_type";
            }

            $stmt = $db->prepare($base_sql);
            $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
            $stmt->bindParam(':latitude', $latitude);
            $stmt->bindParam(':longitude', $longitude);

            if ($vehicle_type) {
                $stmt->bindParam(':vehicle_type', $vehicle_type);
            }

            $stmt->execute();
            $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
    }

    // Return Response
    $response_data = [
        "status" => "success",
        "total_jobs" => $total_jobs,
        "filters" => [
         "date_filter" => $date_filter,
         "start_date" => $start_date,
         "end_date" => $end_date,
         "vehicle_type" => $vehicle_type, 
         "job_status" => $job_status
                ],
        "jobs" => $jobs
    ];

    $response->getBody()->write(json_encode($response_data));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});




$app->get('/user-performance', function (Request $request, Response $response) use ($db) {
    // Get token from request headers
    $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get user ID based on token
    $stmt = $db->prepare("SELECT id,name,email,mobile,gender,address,user_photo FROM users WHERE token = :token LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $userId = $user['id'];

    // Get filter type (daily, weekly, monthly)
    $filter = $request->getQueryParams()['filter'] ?? 'daily';

    if ($filter === 'daily') {
        $dateCondition = "DATE(j.completed_at) = CURDATE()";
        $groupBy = "DATE(j.completed_at)";
        $dateFormat = "CONCAT(DAYNAME(j.completed_at), '  ', DATE_FORMAT(j.completed_at, '%Y-%m-%d'))";
    } elseif ($filter === 'weekly') {
        $dateCondition = "YEARWEEK(j.completed_at, 1) = YEARWEEK(CURDATE(), 1)";
        $groupBy = "DAYNAME(j.completed_at)";
        $dateFormat = "CONCAT(DAYNAME(j.completed_at), ' ', DATE_FORMAT(j.completed_at, '%b %e'))";
    } elseif ($filter === 'monthly') {
        $dateCondition = "YEAR(j.completed_at) = YEAR(CURDATE()) AND MONTH(j.completed_at) = MONTH(CURDATE())";
        $groupBy = "MONTH(j.completed_at)";
        $dateFormat = "DATE_FORMAT(j.completed_at, '%M')";
    } else {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid filter. Use daily, weekly, or monthly.']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get performance data for completed jobs
    $stmt = $db->prepare("SELECT 
            COUNT(j.id) AS completed_jobs,
IFNULL(
    IF(
        ROUND(SUM(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600), 1) = FLOOR(SUM(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600)), 
        CAST(FLOOR(SUM(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600)) AS CHAR), 
        CAST(ROUND(SUM(TIMESTAMPDIFF(SECOND, j.pickup_time, j.drop_time) / 3600), 1) AS CHAR)
    ),
0
) AS total_trip_duration,
            IFNULL(SUM(j.earning_amount), 0) AS total_earnings,
            IFNULL(ROUND(AVG(j.rating), 1), 0) AS avg_rating
        FROM jobs j
        JOIN job_statuses js ON j.status_id = js.id
        WHERE j.user_id = :user_id 
        AND js.status_name = 'Completed' 
        AND $dateCondition");
    $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
    $stmt->execute();
    $performance = $stmt->fetch(PDO::FETCH_ASSOC);


    // Query to fetch trip data overview
    $query = "
    WITH week_days AS (
        SELECT 'Monday' AS day UNION ALL
        SELECT 'Tuesday' UNION ALL
        SELECT 'Wednesday' UNION ALL
        SELECT 'Thursday' UNION ALL
        SELECT 'Friday' UNION ALL
        SELECT 'Saturday' UNION ALL
        SELECT 'Sunday'
    )
    SELECT 
        wd.day AS label,
        IFNULL(COUNT(DISTINCT j.id), 0) AS trips
    FROM week_days wd
    LEFT JOIN jobs j ON DAYNAME(j.completed_at) = wd.day 
        AND DATE(j.completed_at) = CURDATE()
        AND j.user_id = :user_id
    LEFT JOIN job_statuses js ON j.status_id = js.id
        AND js.status_name = 'Completed'
    GROUP BY wd.day
    ORDER BY FIELD(wd.day, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
";

$stmt = $db->prepare($query);
$stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
$stmt->execute();
$tripData = $stmt->fetchAll(PDO::FETCH_ASSOC);


    // Return combined response
    $response->getBody()->write(json_encode(['status' => 'success', 'user'=> $user, 'performance' => $performance, 'overview' => $tripData]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


$app->get('/delete-account', function (Request $request, Response $response) use ($db) {
       $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

      $stmt = $db->prepare("SELECT id,name,email,mobile,gender,address,user_photo FROM users WHERE token = :token AND is_active = 1 LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }
     $userId = $user['id'];
 $deleteStmt = $db->prepare("UPDATE users SET is_active = 0 WHERE id = :id");
    $deleteStmt->bindParam(':id', $userId);

     if ($deleteStmt->execute()) {
        // Invalidate token to log out user
        $logoutStmt = $db->prepare("UPDATE users SET token = NULL WHERE id = :id");
        $logoutStmt->bindParam(':id', $userId);
        $logoutStmt->execute(); // Optional error check if needed

        $response->getBody()->write(json_encode([
            'status' => 'success',
            'message' => 'Account deleted and logged out successfully'
        ]));
    } else {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Failed to delete account'
        ]));
    }
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


$app->post('/sign-up', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    $name = trim($data['name'] ?? '');
    $email = trim($data['email'] ?? '');
    $password = trim($data['password'] ?? '');
    $mobile = trim($data['mobile'] ?? '');
    $otp_code = trim($data['otp_code'] ?? '');

    // Validate required fields
    if (empty($name) || empty($email) || empty($password) || empty($mobile)) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Please fill in all the required fields.'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

     if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = ['status' => 'error', 'message' => 'Invalid email format.'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate OTP
    if (empty($otp_code) || !preg_match('/^\d{6}$/', $otp_code)) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'OTP must be a 6-digit number.'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if user already exists
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'This email is already registered.'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Save new user
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO users (name, email, mobile, password_hash,is_active) VALUES (?, ?, ?, ?,?)");
    $stmt->execute([$name, $email, $mobile, $hashed_password,0]);
    $user_id = $db->lastInsertId(); // Get inserted user ID

    // Save OTP
    $expiresAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    $stmt = $db->prepare("INSERT INTO password_resets (user_id, otp_code, expires_at) 
                          VALUES (?, ?, ?) 
                          ON DUPLICATE KEY UPDATE otp_code = ?, expires_at = ?");
    $stmt->execute([$user_id, $otp_code, $expiresAt, $otp_code, $expiresAt]);

   $sent = sendMail(
    $email,
    'Protostar Sign-Up OTP',
    "Hello $name,\n\nYour OTP for sign-up is: $otp_code\n\nThis OTP is valid for 10 minutes."
);

if ($sent) {
    $response->getBody()->write(json_encode([
        'status' => 'success',
        'message' => 'OTP has been sent to the email.'
    ]));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
} else {
    $response->getBody()->write(json_encode([
        'status' => 'error',
        'message' => 'Failed to send OTP email.'
    ]));
      return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
}

});

$app->post('/verify-signup-otp', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    $email = trim($data['email'] ?? '');
    $otp = trim($data['otp_code'] ?? '');
   
    //  Validate input
    if (empty($email) || empty($otp) ) {
        $error = ['status' => 'error', 'message' => 'All fields are required'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

 if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = ['status' => 'error', 'message' => 'Invalid email format.'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }
    //  Fetch user_id from users table using email
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $error = ['status' => 'error', 'message' => 'User not found'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $user_id = $user['id'];


    //  Validate OTP for this user
    $stmt = $db->prepare("SELECT user_id FROM password_resets WHERE user_id = ? AND otp_code = ?");
    $stmt->execute([$user_id, $otp]);
    $resetRecord = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$resetRecord) {
        $error = ['status' => 'error', 'message' => 'Invalid or expired OTP'];
        $response->getBody()->write(json_encode($error));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }


    //  Update password in users table
    $stmt = $db->prepare("UPDATE users SET is_active = ? WHERE id = ?");
    $stmt->execute([1, $user_id]);

    //  Delete used OTP
    $stmt = $db->prepare("DELETE FROM password_resets WHERE user_id = ?");
    $stmt->execute([$user_id]);

    //  Return success response
    $success = ['status' => 'success', 'message' => 'Signed up successfully'];
    $response->getBody()->write(json_encode($success));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

$app->post('/customer-register', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $name          = trim($data['customer_name'] ?? '');
    $email         = trim($data['email'] ?? '');
    $password      = trim($data['password'] ?? '');
    $mobile        = trim($data['customer_mobile'] ?? '');
    $otp_code      = trim($data['otp_code'] ?? '');
    $firebaseToken = trim($data['firebase_token'] ?? '');
    $deviceType    = trim($data['device_type'] ?? '');

    // Validate required fields
    if (empty($name) || empty($email) || empty($password) || empty($mobile)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Please fill in all required fields."
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Invalid email format."
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate OTP
    if (empty($otp_code) || !preg_match('/^\d{6}$/', $otp_code)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "OTP must be a 6-digit number."
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if customer already exists
    $stmt = $db->prepare("SELECT id, is_active FROM customer WHERE email = ? LIMIT 1");
    $stmt->execute([$email]);
    $existingCustomer = $stmt->fetch(PDO::FETCH_ASSOC);

    $hashed_password = md5($password);

    if ($existingCustomer) {
        if ($existingCustomer['is_active'] == 1) {
            // Already active → block registration
            $response->getBody()->write(json_encode([
                "status"  => "error",
                "message" => "This email is already registered and active."
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } else {
            // Update inactive customer with new details
            $stmt = $db->prepare("UPDATE customer 
                                  SET customer_name = ?, customer_mobile = ?, password_hash = ?, firebase_token = ?, device_type = ?, updated_at = NOW() 
                                  WHERE id = ?");
            $stmt->execute([$name, $mobile, $hashed_password, $firebaseToken, $deviceType, $existingCustomer['id']]);
            $customer_id = $existingCustomer['id'];
        }
    } else {
        // Insert new customer
        $stmt = $db->prepare("INSERT INTO customer 
            (customer_name, email, customer_mobile, password_hash, role, is_active, firebase_token, token, device_type, created_at) 
            VALUES (?, ?, ?, ?, 'customer', 0, ?, '', ?, NOW())");
        $stmt->execute([$name, $email, $mobile, $hashed_password, $firebaseToken, $deviceType]);
        $customer_id = $db->lastInsertId();
    }

    // Save OTP in password_resets
    $expiresAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    $stmt = $db->prepare("INSERT INTO password_resets (user_id, otp_code, expires_at) 
                          VALUES (?, ?, ?) 
                          ON DUPLICATE KEY UPDATE otp_code = VALUES(otp_code), expires_at = VALUES(expires_at)");
    $stmt->execute([$customer_id, $otp_code, $expiresAt]);

    // Send OTP email
    $sent = sendMail(
        $email,
        'Protostar Customer Sign-Up OTP',
        "Hello $name,\n\nYour OTP for sign-up is: $otp_code\n\nThis OTP is valid for 10 minutes."
    );

    $response->getBody()->write(json_encode([
        "status"  => $sent ? "success" : "error",
        "message" => $sent ? "OTP has been sent to your email." : "Failed to send OTP email."
    ]));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


$app->post('/customer-verify-otp', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $email = trim($data['email'] ?? '');
    $otp   = trim($data['otp_code'] ?? '');

    if (empty($email) || empty($otp)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "All fields are required"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Invalid email format"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Get customer
    $stmt = $db->prepare("SELECT * FROM customer WHERE email = ?");
    $stmt->execute([$email]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Customer not found"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check OTP
    $stmt = $db->prepare("SELECT otp_code, expires_at FROM password_resets WHERE user_id = ? AND otp_code = ? LIMIT 1");
    $stmt->execute([$customer['id'], $otp]);
    $resetRecord = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$resetRecord) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Invalid OTP"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    if (strtotime($resetRecord['expires_at']) < time()) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "OTP has expired"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Activate account
    $stmt = $db->prepare("UPDATE customer SET is_active = 1 WHERE id = ?");
    $stmt->execute([$customer['id']]);

    // Delete OTP
    $stmt = $db->prepare("DELETE FROM password_resets WHERE user_id = ?");
    $stmt->execute([$customer['id']]);

    // Success response
    $response->getBody()->write(json_encode([
        "status"   => "success",
        "message"  => "Signup verified successfully",
        "customer" => [
            "id"             => $customer['id'],
            "name"           => $customer['customer_name'],
            "email"          => $customer['email'],
            "mobile"         => $customer['customer_mobile'],
            "firebase_token" => $customer['firebase_token'],
            "device_type"    => $customer['device_type'],
            "is_active"      => 1
        ]
    ]));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});



// ----------------- CUSTOMER LOGIN -----------------
// Customer API: Login
$app->post('/customer-login', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $email         = trim($data['email'] ?? '');
    $password      = trim($data['password'] ?? '');
    $firebaseToken = trim($data['firebase_token'] ?? '');
    $deviceType    = trim($data['device_type'] ?? '');

    if (empty($email) || empty($password)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Email and password are required"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if customer exists
    $stmt = $db->prepare("SELECT * FROM customer WHERE email = ? AND is_active = 1");
    $stmt->execute([$email]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Customer not found or inactive"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Verify password

$hashedPassword = md5($password);

if ($hashedPassword !== $customer['password_hash']) {
    $response->getBody()->write(json_encode([
        "status"  => "error",
        "message" => "Incorrect password"
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
}

    // Generate session token
    $sessionToken = bin2hex(random_bytes(32));

    // Update Firebase token & session token & device_type
    $stmt = $db->prepare("UPDATE customer SET firebase_token = ?, token = ?, device_type = ? WHERE id = ?");
    $stmt->execute([$firebaseToken, $sessionToken, $deviceType, $customer['id']]);

    // Success response
    $response->getBody()->write(json_encode([
        "status"   => "success",
        "message"  => "Login successful",
        "customer" => [
            "id"             => $customer['id'],
            "name"           => $customer['customer_name'],
            "email"          => $customer['email'],
            "mobile"         => $customer['customer_mobile'],
            "token"          => $sessionToken,
            "firebase_token" => $firebaseToken,
            "device_type"    => $deviceType,
            "is_active"      => $customer['is_active']
        ]
    ]));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});




// ----------------- FORGOT PASSWORD -----------------
$app->post('/customer-forgot-password', function (Request $request, Response $response) use ($db) {
    $data     = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    $email    = trim($data['email'] ?? '');
    $otp_code = trim($data['otp_code'] ?? '');

    // Validate email
    if (empty($email)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Email is required"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Invalid email format"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate OTP
    if (empty($otp_code) || !preg_match('/^\d{6}$/', $otp_code)) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "OTP must be a 6-digit number"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if customer exists
    $stmt = $db->prepare("SELECT id, customer_name, email FROM customer WHERE email = ?");
    $stmt->execute([$email]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Customer not found"
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customer_id = $customer['id'];
    $expiresAt   = date('Y-m-d H:i:s', strtotime('+10 minutes'));

    // Save OTP
    $stmt = $db->prepare("
        INSERT INTO password_resets (user_id, otp_code, expires_at)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE otp_code = VALUES(otp_code), expires_at = VALUES(expires_at)
    ");
    $stmt->execute([$customer_id, $otp_code, $expiresAt]);

    // Send OTP email
    $sent = sendMail(
        $customer['email'],
        'Protostar Forgot Password OTP',
        "Hello {$customer['customer_name']},\n\nYour OTP for password reset is: $otp_code\n\nThis OTP is valid for 10 minutes."
    );

    if ($sent) {
        $response->getBody()->write(json_encode([
            "status"  => "success",
            "message" => "OTP has been sent to your email."
        ]));
    } else {
        $response->getBody()->write(json_encode([
            "status"  => "error",
            "message" => "Failed to send OTP email."
        ]));
    }

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// ----------------- RESET PASSWORD -----------------
$app->post('/customer-reset-password', function (Request $request, Response $response) use ($db) {
    $data         = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    $email        = trim($data['email'] ?? '');
    $otp          = trim($data['otp_code'] ?? '');
    $new_password = trim($data['new_password'] ?? '');

    // Validate required fields
    if (empty($email) || empty($otp) || empty($new_password)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'All fields are required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Password strength check
    if (strlen($new_password) < 8 || !preg_match('/[!@#$%^&*]/', $new_password)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Password must be at least 8 characters long and contain a special character (!@#$%^&*)'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if customer exists
    $stmt = $db->prepare("SELECT id, customer_name FROM customer WHERE email = ?");
    $stmt->execute([$email]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Customer not found'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customer_id = $customer['id'];

    // Validate OTP
    $stmt = $db->prepare("
        SELECT user_id 
        FROM password_resets 
        WHERE user_id = ? AND otp_code = ? AND expires_at > NOW()
        LIMIT 1
    ");
    $stmt->execute([$customer_id, $otp]);
    $resetRecord = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$resetRecord) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Invalid or expired OTP'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Hash new password
    $hashed_password = md5($new_password);

    // Update password
    $stmt = $db->prepare("UPDATE customer SET password_hash = ? WHERE id = ?");
    $stmt->execute([$hashed_password, $customer_id]);

    // Remove used OTP
    $stmt = $db->prepare("DELETE FROM password_resets WHERE user_id = ?");
    $stmt->execute([$customer_id]);

    // Success response
    $response->getBody()->write(json_encode([
        'status'  => 'success',
        'message' => 'Password has been reset successfully'
    ]));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

// ----------------- LOGOUT -----------------
$app->post('/customer-logout', function (Request $request, Response $response) use ($db) {
    // Get token from Authorization header
    $token = trim($request->getHeaderLine('Authorization'));

    if (empty($token)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Authorization token is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Find customer by token
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ?");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Invalid or expired token'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Invalidate token
    $stmt = $db->prepare("UPDATE customer SET token = NULL WHERE id = ?");
    $stmt->execute([$customer['id']]);

    $response->getBody()->write(json_encode([
        'status'  => 'success',
        'message' => 'Logout successful'
    ]));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

$app->get('/customer-profile', function (Request $request, Response $response) use ($db) {
    $authHeader = $request->getHeaderLine('Authorization') ?: $request->getHeaderLine('authorization');
    $token = preg_replace('/^Bearer\s+/i', '', trim($authHeader));

    // ===== Automatically create logs folder if it doesn't exist =====
    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0777, true);
    }
    $logFile = $logDir . '/debug.log';

    file_put_contents($logFile, "==== /customer-profile called ====\n", FILE_APPEND);
    file_put_contents($logFile, "Raw Auth Header: [$authHeader]\n", FILE_APPEND);
    file_put_contents($logFile, "Extracted Token: [$token] | Length: " . strlen($token) . "\n", FILE_APPEND);

    if (empty($token)) {
        file_put_contents($logFile, "Token is empty!\n", FILE_APPEND);
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Token is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // ===== Fetch customer =====
    $stmt = $db->prepare("SELECT id, customer_name, customer_mobile, email, gender, is_active, firebase_token, token, device_type, created_at, updated_at, home_address as address
                          FROM customer
                          WHERE token = :token AND is_active = 1
                          LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        file_put_contents($logFile, "No customer found for token: [$token]\n", FILE_APPEND);
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Invalid token'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    file_put_contents($logFile, "Customer fetched successfully: " . json_encode($customer) . "\n", FILE_APPEND);

    $response->getBody()->write(json_encode([
        'status' => 'success',
        'customer' => $customer
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});



// Customer edit profile
$app->post('/customer-edit-profile', function (Request $request, Response $response) use ($db) {
    $token = trim($request->getHeaderLine('Authorization'));
    $data  = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
   
    if (empty($token)) {
        $response->getBody()->write(json_encode(['status'=>'error','message'=>'Token is required']));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Find customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = :token AND is_active = 1 LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode(['status'=>'error','message'=>'Invalid or expired token']));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    $customerId = $customer['id'];

    // Update customer profile including home_address
    $stmt = $db->prepare("UPDATE customer SET
                          customer_name = COALESCE(?, customer_name),
                          customer_mobile = COALESCE(?, customer_mobile),
                          email = COALESCE(?, email),
                          gender = COALESCE(?, gender),
                          home_address = COALESCE(?, home_address),
                          updated_at = NOW()
                          WHERE id = ?");
    $stmt->execute([
        $data['customer_name'] ?? null,
        $data['customer_mobile'] ?? null,
        $data['email'] ?? null,
         $data['gender'] ?? null,
        $data['address'] ?? null,
        $customerId
    ]);

    $response->getBody()->write(json_encode(['status'=>'success','message'=>'Profile updated successfully']));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});


$app->get('/customer-delete-account', function (Request $request, Response $response) use ($db) {
    $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        $payload = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Find customer
    $stmt = $db->prepare("SELECT id
                      FROM customer
                      WHERE token = :token AND is_active = 1
                      LIMIT 1");
$stmt->bindParam(':token', $token);
$stmt->execute();
$customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $payload = ['status' => 'error', 'message' => 'Invalid token'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customerId = $customer['id'];

    // Deactivate account
    $deleteStmt = $db->prepare("UPDATE customer SET is_active = 0, token = NULL WHERE id = :id");
    $deleteStmt->bindParam(':id', $customerId);

    if ($deleteStmt->execute()) {
        $payload = ['status' => 'success', 'message' => 'Account deleted and logged out successfully'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } else {
        $payload = ['status' => 'error', 'message' => 'Failed to delete account'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

$app->post('/customer-change-password', function (Request $request, Response $response) use ($db) {
    $token = trim($request->getHeaderLine('Authorization'));
    $data  = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $old_password = $data['old_password'] ?? null;
    $new_password = $data['new_password'] ?? null;

    // Validate input
    if (empty($token) || empty($old_password) || empty($new_password)) {
        $payload = ['status' => 'error', 'message' => 'Token, old_password, and new_password are required.'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // // Find customer
    // $stmt = $db->prepare("SELECT id, password_hash FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    // $stmt->execute([$token]);
    // $customer = $stmt->fetch(PDO::FETCH_ASSOC);

      $stmt = $db->prepare("SELECT id , password_hash
                      FROM customer
                      WHERE token = :token AND is_active = 1
                      LIMIT 1");
$stmt->bindParam(':token', $token);
$stmt->execute();
$customer = $stmt->fetch(PDO::FETCH_ASSOC);


    if (!$customer) {
        $payload = ['status' => 'error', 'message' => 'Invalid token or customer not found'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Verify old password using MD5
    if (md5($old_password) !== $customer['password_hash']) {
        $payload = ['status' => 'error', 'message' => 'Old password is incorrect'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Enforce strong password
    if (strlen($new_password) < 8 || !preg_match('/[!@#$%^&*]/', $new_password)) {
        $payload = ['status' => 'error', 'message' => 'Password must be at least 8 characters and contain one special character (!@#$%^&*)'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Hash new password with MD5 and update
    $hashedPassword = md5($new_password);
    $stmt = $db->prepare("UPDATE customer SET password_hash = ?, updated_at = NOW() WHERE id = ?");
    $stmt->execute([$hashedPassword, $customer['id']]);

    $payload = ['status' => 'success', 'message' => 'Password changed successfully.'];
    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});






$app->post('/cancel-booking', function (Request $request, Response $response) use ($db) {
    $token = $request->getHeaderLine('Authorization');
    $data  = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    if (empty($token)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Token is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Invalid or expired token'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customerId = $customer['id'];
    $jobId = $data['job_id'] ?? null;

    if (empty($jobId)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Job ID is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Fetch "Cancelled" status_id from job_statuses
    $stmt = $db->prepare("SELECT id FROM job_statuses WHERE LOWER(status_name) = 'cancelled' LIMIT 1");
    $stmt->execute();
    $status = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$status) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Cancelled status not defined'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    $cancelStatusId = $status['id'];

    // Check if booking belongs to this customer AND driver is NOT assigned
    $stmt = $db->prepare("SELECT id, status_id, user_id FROM jobs WHERE id = ? AND customer_id = ? LIMIT 1");
    $stmt->execute([$jobId, $customerId]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$job) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Booking not found'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

  if (!empty($job['user_id']) && $job['user_id'] != 0) {
    $response->getBody()->write(json_encode([
        'status'  => 'error',
        'message' => 'Booking cannot be cancelled as driver is already assigned'
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
}


    if ($job['status_id'] == $cancelStatusId) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Booking already cancelled'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Update booking status → cancelled
    $stmt = $db->prepare("UPDATE jobs 
                          SET status_id = ?, updated_at = NOW() 
                          WHERE id = ? AND customer_id = ?");
    $stmt->execute([$cancelStatusId, $jobId, $customerId]);

    $response->getBody()->write(json_encode([
        'status'  => 'success',
        'message' => 'Booking cancelled successfully'
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});



// booking history working
$app->get('/booking-history', function (Request $request, Response $response) use ($db) {
    $token = trim($request->getHeaderLine('Authorization'));

    if (empty($token)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Token is required'
        ], JSON_UNESCAPED_UNICODE));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Invalid or expired token'
        ], JSON_UNESCAPED_UNICODE));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customerId = $customer['id'];

    // Fetch booking history with driver info
    $stmt = $db->prepare("
        SELECT 
            j.id,
            j.job_id,
            j.pickup_address,
            j.drop_address,
            j.pickup_time,
            j.drop_time,
            j.trip_amount,
            j.rating,
            j.completed_at,
            j.created_at,
            j.updated_at,
            js.status_name AS status,
            v.vehicle_id AS vehicle_number,
            vt.type_name AS vehicle_type,
            u.id AS driver_id,
            u.name AS driver_name,
            u.mobile AS driver_mobile
        FROM jobs j
        LEFT JOIN job_statuses js ON j.status_id = js.id
        LEFT JOIN vehicles v ON j.vehicle_id = v.id
        LEFT JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
        LEFT JOIN users u ON j.user_id = u.id
        WHERE j.customer_id = ?
        ORDER BY j.created_at DESC
    ");
    $stmt->execute([$customerId]);
    $history = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode([
        'status' => 'success',
        'count'  => count($history),
        'data'   => $history
    ], JSON_UNESCAPED_UNICODE | JSON_NUMERIC_CHECK));

    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});



$app->post('/rate-ride', function (Request $request, Response $response) use ($db) {
    $token = $request->getHeaderLine('Authorization');
    $data  = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    // Check token
    if (empty($token)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Token is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Invalid or expired token'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customerId = $customer['id'];
    $jobId      = $data['job_id'] ?? null;
    $rating     = $data['rating'] ?? null;
    $feedback   = trim($data['feedback'] ?? '');

    if (empty($jobId) || empty($rating)) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Job ID and rating are required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Fetch job & driver
    $stmt = $db->prepare("SELECT id, user_id FROM jobs WHERE id = ? AND customer_id = ? LIMIT 1");
    $stmt->execute([$jobId, $customerId]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$job) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => 'Invalid job for this customer'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $driverId = $job['user_id'];

    // Insert rating
    $stmt = $db->prepare("INSERT INTO ratings (job_id, customer_id, driver_id, rating, feedback) 
                          VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$jobId, $customerId, $driverId, $rating, $feedback]);

    $response->getBody()->write(json_encode([
        'status'  => 'success',
        'message' => 'Rating submitted successfully'
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});

$app->post('/support-ticket', function (Request $request, Response $response) use ($db) {
    $token = $request->getHeaderLine('Authorization');
    $data  = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    // Check token
    if (empty($token)) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Token is required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Invalid or expired token'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $customerId = $customer['id'];
    $subject    = trim($data['subject'] ?? '');
    $message    = trim($data['message'] ?? '');

    if (empty($subject) || empty($message)) {
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Subject and message are required'
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Insert support ticket
    $stmt = $db->prepare("INSERT INTO support_tickets (customer_id, subject, message) VALUES (?, ?, ?)");
    $stmt->execute([$customerId, $subject, $message]);

    $response->getBody()->write(json_encode([
        'status' => 'success',
        'message' => 'Support ticket created successfully'
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});
$app->get('/faqs', function (Request $request, Response $response) use ($db) {
    try {
        $stmt = $db->query("SELECT id, question, answer FROM faqs ORDER BY created_at DESC");
        $faqs = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $payload = [
            'status' => 'success',
            'count'  => count($faqs),
            'data'   => $faqs
        ];

        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);

    } catch (Exception $e) {
        $response->getBody()->write(json_encode([
            'status'  => 'error',
            'message' => $e->getMessage()
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});
$app->post('/booking-request', function (Request $request, Response $response) use ($db) {
    $token = trim($request->getHeaderLine('Authorization'));
    $data  = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    // Check token
    if (empty($token)) {
        $payload = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $payload = ['status' => 'error', 'message' => 'Invalid or expired token'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    $customerId = $customer['id'];

    // Extract booking details
    $pickupAddress  = $data['pickup_address'] ?? null;
    $dropAddress    = $data['drop_address'] ?? null;
    $pickLat        = $data['pick_latitude'] ?? null;
    $pickLng        = $data['pick_longitude'] ?? null;
    $dropLat        = $data['drop_latitude'] ?? null;
    $dropLng        = $data['drop_longitude'] ?? null;
    $vehicleTypeId  = $data['vehicle_type_id'] ?? null;
    $pickupTime     = $data['pickup_time'] ?? null;

    // Required fields check
    if (empty($pickupAddress) || empty($dropAddress) || empty($vehicleTypeId) || empty($pickupTime)) {
        $payload = [
            'status' => 'error',
            'message' => 'Pickup address, drop address, vehicle type, and pickup time are required'
        ];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Validate pickup time format (Y-m-d H:i:s)
    $dt = DateTime::createFromFormat('Y-m-d H:i:s', $pickupTime);
    if (!$dt || $dt->format('Y-m-d H:i:s') !== $pickupTime) {
        $payload = ['status' => 'error', 'message' => 'Pickup time must be in format Y-m-d H:i:s'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Generate Job ID
    $jobId = "JOB" . rand(1000, 9999);

    // Insert booking into jobs table
    $stmt = $db->prepare("
        INSERT INTO jobs
        (job_id, customer_id, pickup_address, drop_address, pick_latitude, pick_longitude,
         drop_latitude, drop_longitude, vehicle_type_id, status_id, pickup_time, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");
    $stmt->execute([
        $jobId, $customerId, $pickupAddress, $dropAddress,
        $pickLat, $pickLng, $dropLat, $dropLng,
        $vehicleTypeId, 1, $pickupTime
    ]);

    $newJobId = $db->lastInsertId();

    // Response
    $payload = [
        'status' => 'success',
        'message' => 'Booking request created successfully',
        'job' => [
            'id' => $newJobId,
            'job_id' => $jobId,
            'pickup_address' => $pickupAddress,
            'drop_address' => $dropAddress,
            'pickup_time' => $pickupTime,
            'vehicle_type_id' => $vehicleTypeId,
            'status' => 'pending'
        ]
    ];
    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});


$app->post('/booking-details', function (Request $request, Response $response) use ($db) {
    // Get Authorization Token
    $token = $request->getHeaderLine('Authorization');
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    if (!$token) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Authorization token is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Validate Token & Get Customer ID
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = :token AND is_active = 1 LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);
    //  print_r($customer);
    if (!$customer) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    // Check if job_id is provided
    if (!isset($data['job_id'])) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Job ID is required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $job_id = $data['job_id'];

    // Fetch booking details for the customer
    $stmt = $db->prepare("
        SELECT 
            j.id, 
            j.job_id, 
            j.customer_id,
            c.customer_name,
            c.customer_mobile,
            c.home_address AS customer_address,
             j.marker_id,
            m.marker_name,
            j.vehicle_id, 
             v.vehicle_id as vehicle_no,
              v.registration_no, 
            v.color,  
            v.year_of_registration, 
             j.vehicle_type_id, 
            vt.type_name,
            j.pickup_address, 
            j.drop_address, 
            j.pickup_time, 
            j.drop_time,
            FORMAT(j.pick_latitude, 2) AS pick_latitude, 
            FORMAT(j.pick_longitude, 2) AS pick_longitude,  
            FORMAT(j.drop_latitude, 2) AS drop_latitude, 
            FORMAT(j.drop_longitude, 2) AS drop_longitude, 
            j.round_trip,  
            j.status_id, 
            js.status_name, 
            j.special_instructions, 
            j.user_id as driver_id, 
            u.name AS driver_name, 
            u.mobile AS driver_mobile,
             j.completed_at, 
            j.created_at, 
            j.updated_at
        FROM jobs j
        LEFT JOIN job_statuses js ON j.status_id = js.id
        LEFT JOIN vehicles v ON j.vehicle_id = v.id
        LEFT JOIN vehicle_types vt ON j.vehicle_type_id = vt.id
        LEFT JOIN users u ON j.user_id = u.id
        LEFT JOIN marker m ON j.marker_id = m.id
        LEFT JOIN customer c ON j.customer_id = c.id
        WHERE j.id = :job_id AND j.customer_id = :customer_id
    ");

    $stmt->bindParam(':job_id', $job_id, PDO::PARAM_INT);
    $stmt->bindParam(':customer_id', $customer['id'], PDO::PARAM_INT);
    $stmt->execute();
    $booking = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($booking) {
        $booking['round_trip'] = (bool) $booking['round_trip'];
    }

    if (!$booking) {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Booking not found']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }

    $response->getBody()->write(json_encode(['status' => 'success', 'booking' => $booking]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


// Get all notifications for the customer
// Fetch all notifications for a customer
$app->get('/customer/notifications', function (Request $request, Response $response) use ($db) {
    // Get token from headers or query
    $token = $request->getHeaderLine('Authorization') ?? $request->getQueryParams()['token'] ?? null;

    if (!$token) {
        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200)
                        ->write(json_encode(['status'=>'error','message'=>'Token is required']));
    }

    // Validate token & get customer ID
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = :token AND is_active = 1 LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200)
                        ->write(json_encode(['status'=>'error','message'=>'Invalid token']));
    }

    // Fetch notifications for this customer
    $stmt = $db->prepare("
        SELECT id, customer_id AS user_to, user_from, message, status, created_at, updated_at
        FROM customer_notifications
        WHERE customer_id = :customer_id
        ORDER BY created_at DESC
    ");
    $stmt->bindParam(':customer_id', $customer['id'], PDO::PARAM_INT);
    $stmt->execute();
    $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $responseData = $notifications ? 
        ['status'=>'success','data'=>$notifications] : 
        ['status'=>'error','message'=>'No notifications found'];

    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});


// Mark a particular notification as read for the customer
$app->post('/customer/notifications/read', function (Request $request, Response $response) use ($db) {
    $token = $request->getHeaderLine('Authorization');

    if (!$token) {
        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200)
                        ->write(json_encode(['status'=>'error','message'=>'Authorization token is required']));
    }

    // Validate token & get customer ID
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = :token AND is_active = 1 LIMIT 1");
    $stmt->bindParam(':token', $token);
    $stmt->execute();
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200)
                        ->write(json_encode(['status'=>'error','message'=>'Invalid token']));
    }

    // Get notification ID from request body
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);
    if (empty($data['notification_id'])) {
        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200)
                        ->write(json_encode(['status'=>'error','message'=>'Notification ID is required']));
    }

    // Update notification status to 'Read' for this customer
    $stmt = $db->prepare("
        UPDATE customer_notifications
        SET status = 'Read', updated_at = NOW()
        WHERE id = :notification_id AND customer_id = :customer_id
    ");
    $stmt->bindParam(':notification_id', $data['notification_id'], PDO::PARAM_INT);
    $stmt->bindParam(':customer_id', $customer['id'], PDO::PARAM_INT);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $responseData = ['status'=>'success','message'=>'Notification marked as read'];
    } else {
        $responseData = ['status'=>'error','message'=>'Notification not found or already read'];
    }

    $response->getBody()->write(json_encode($responseData));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});
$app->get('/recent-booking', function (Request $request, Response $response) use ($db) {
    $token = trim($request->getHeaderLine('Authorization'));

    if (empty($token)) {
        $payload = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $payload = ['status' => 'error', 'message' => 'Invalid or expired token'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    $customerId = $customer['id'];

    // Fetch most recent booking with vehicle_type, driver, and vehicle details
    $stmt = $db->prepare("
        SELECT j.id, j.job_id, j.pickup_address, j.drop_address, j.pickup_time,
               j.vehicle_type_id, j.status_id, j.vehicle_id,
               v.type_name AS vehicle_type,
               veh.registration_no AS vehicle_registration, veh.color AS vehicle_color, veh.vehicle_id as vehicle_no,
               d.id AS driver_id, d.name AS driver_name, d.mobile AS driver_mobile
        FROM jobs j
        LEFT JOIN vehicle_types v ON j.vehicle_type_id = v.id
        LEFT JOIN vehicles veh ON j.vehicle_id = veh.id
        LEFT JOIN users d ON j.user_id = d.id
        WHERE j.customer_id = ?
        ORDER BY j.created_at DESC
        LIMIT 1
    ");
    $stmt->execute([$customerId]);
    $booking = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$booking) {
        $payload = ['status' => 'success', 'message' => 'No recent booking found', 'booking' => null];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Map status_id to human-readable status
    $statusMap = [
        1 => 'Pending',
        2 => 'Started',
        3 => 'Picked Up',
        4 => 'Completed',
        5 => 'Cancelled'
    ];
    $booking['status'] = $statusMap[$booking['status_id']] ?? 'unknown';
    unset($booking['status_id']);

    $payload = ['status' => 'success', 'booking' => $booking];
    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});



$app->get('/live-location', function (Request $request, Response $response) use ($db) {
    $token = trim($request->getHeaderLine('Authorization'));
 $jobId = $request->getQueryParams()['job_id'] ?? null;


    if (empty($token)) {
        $payload = ['status' => 'error', 'message' => 'Token is required'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    if (empty($jobId)) {
        $payload = ['status' => 'error', 'message' => 'Job ID is required'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Validate customer
    $stmt = $db->prepare("SELECT id FROM customer WHERE token = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$token]);
    $customer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$customer) {
        $payload = ['status' => 'error', 'message' => 'Invalid or expired token'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    $customerId = $customer['id'];

    // Fetch job & driver location
   $stmt = $db->prepare("
    SELECT j.job_id, j.status_id, u.id AS driver_id, u.name AS driver_name, 
           u.latitude, u.longitude
    FROM jobs j
    LEFT JOIN users u ON j.user_id = u.id
    WHERE j.customer_id = ? 
      AND j.id = ? 
      AND j.status_id IN (2, 3)  
    LIMIT 1
");
    $stmt->execute([$customerId, $jobId]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$job) {
        $payload = ['status' => 'error', 'message' => 'Live location not available or job not started'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    $payload = [
        'status' => 'success',
        'driver' => [
            'id' => $job['driver_id'],
            'name' => $job['driver_name'],
            'latitude' => $job['latitude'],
            'longitude' => $job['longitude']
        ],
        'job_id' => $job['job_id']
    ];

    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});

$app->post('/driver-location', function (Request $request, Response $response) use ($db) {
    $data = $request->getParsedBody() ?: json_decode(file_get_contents("php://input"), true);

    $driverId = $data['driver_id'] ?? null;
    $jobId    = $data['job_id'] ?? null;
    $latitude = $data['latitude'] ?? null;
    $longitude= $data['longitude'] ?? null;

    // Validate input
    if (!$driverId || !$jobId || !$latitude || !$longitude) {
        $payload = ['status'=>'error','message'=>'driver_id, job_id, latitude, and longitude are required'];
        $response->getBody()->write(json_encode($payload));
        return $response->withHeader('Content-Type','application/json')->withStatus(200);
    }

    // Update user's live location
    $stmt = $db->prepare("UPDATE users SET latitude = ?, longitude = ? WHERE id = ?");
    $stmt->execute([$latitude, $longitude, $driverId]);

    $payload = ['status'=>'success','message'=>'Driver location updated'];
    $response->getBody()->write(json_encode($payload));
    return $response->withHeader('Content-Type','application/json')->withStatus(200);
});


// Run the app
$app->run();
