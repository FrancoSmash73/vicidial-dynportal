<?php
/**
 * valid8.php - Agent IP self-service whitelisting portal
 *
 * Agents log in with ViciDial credentials. On successful auth,
 * their IP is added to the ViciWhite list in vicidial_ip_list_entries.
 * The VB-firewall cron job picks up the IP and adds it to the
 * dynamiclist ipset within 60 seconds.
 */

require_once __DIR__ . '/inc/defaults.inc.php';
require_once __DIR__ . '/inc/dbconnect.inc.php';

$error   = '';
$success = '';
$redirect_url = '';
$client_ip = '';

// Determine client IP (support proxies)
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $client_ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
} elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
    $client_ip = trim($_SERVER['HTTP_X_REAL_IP']);
} else {
    $client_ip = $_SERVER['REMOTE_ADDR'];
}

// Validate IP format
if (!filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $error = 'Unable to determine your IPv4 address.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    $user = isset($_POST['user']) ? trim($_POST['user']) : '';
    $pass = isset($_POST['pass']) ? trim($_POST['pass']) : '';

    if ($user === '' || $pass === '') {
        $error = 'Username and password are required.';
    } else {
        // Authenticate against vicidial_users
        $stmt = mysqli_prepare($link,
            "SELECT user_level FROM vicidial_users WHERE user = ? AND pass = ? AND active = 'Y' LIMIT 1"
        );
        mysqli_stmt_bind_param($stmt, 'ss', $user, $pass);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $row = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt);

        if (!$row) {
            $error = 'Invalid username or password.';
        } elseif ((int)$row['user_level'] < $min_user_level) {
            $error = 'Insufficient user level for portal access.';
        } else {
            $user_level = (int)$row['user_level'];

            // Check if IP already exists in the list
            $stmt = mysqli_prepare($link,
                "SELECT ip_address FROM vicidial_ip_list_entries WHERE ip_list_id = ? AND ip_address = ? LIMIT 1"
            );
            mysqli_stmt_bind_param($stmt, 'ss', $ip_list_id, $client_ip);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $exists = mysqli_fetch_assoc($result);
            mysqli_stmt_close($stmt);

            if (!$exists) {
                // Insert the IP with explicit timestamp so VB-firewall's 14-day window sees it
                $stmt = mysqli_prepare($link,
                    "INSERT INTO vicidial_ip_list_entries (ip_list_id, ip_address, entry_date) VALUES (?, ?, NOW())"
                );
                mysqli_stmt_bind_param($stmt, 'ss', $ip_list_id, $client_ip);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
            } else {
                // Refresh entry_date so the 14-day expiry resets on each login
                $stmt = mysqli_prepare($link,
                    "UPDATE vicidial_ip_list_entries SET entry_date = NOW() WHERE ip_list_id = ? AND ip_address = ?"
                );
                mysqli_stmt_bind_param($stmt, 'ss', $ip_list_id, $client_ip);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
            }

            $success = "IP $client_ip whitelisted successfully. Access will be granted within 60 seconds.";

            // Redirect after brief delay
            $redirect_url = ($user_level >= $admin_level) ? $redirect_admin : $redirect_agent;
            header("Refresh: 3; url=$redirect_url");
        }
    }
}

mysqli_close($link);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if (!empty($success) && !empty($redirect_url)): ?>
    <meta http-equiv="refresh" content="3;url=<?php echo htmlspecialchars($redirect_url); ?>">
    <?php endif; ?>
    <title><?php echo htmlspecialchars($portal_title); ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: #16213e;
            padding: 2rem;
            border-radius: 8px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        h1 {
            text-align: center;
            margin-bottom: 0.5rem;
            font-size: 1.4rem;
            color: #4fc3f7;
        }
        .ip-display {
            text-align: center;
            font-size: 0.85rem;
            color: #90a4ae;
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.3rem;
            font-size: 0.9rem;
            color: #b0bec5;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 0.6rem;
            margin-bottom: 1rem;
            border: 1px solid #37474f;
            border-radius: 4px;
            background: #0d1b2a;
            color: #e0e0e0;
            font-size: 1rem;
        }
        input:focus {
            outline: none;
            border-color: #4fc3f7;
        }
        button {
            width: 100%;
            padding: 0.7rem;
            background: #0277bd;
            color: #fff;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
        }
        button:hover { background: #0288d1; }
        .error {
            background: #b71c1c;
            color: #fff;
            padding: 0.6rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            text-align: center;
            font-size: 0.9rem;
        }
        .success {
            background: #1b5e20;
            color: #fff;
            padding: 0.6rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            text-align: center;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1><?php echo htmlspecialchars($portal_title); ?></h1>
        <div class="ip-display">Your IP: <?php echo htmlspecialchars($client_ip); ?></div>

        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <p style="text-align:center; font-size:0.85rem; color:#90a4ae; margin-top:0.5rem;">Redirecting in 3 seconds... <a href="<?php echo htmlspecialchars($redirect_url); ?>" style="color:#4fc3f7;">Click here</a> if not redirected.</p>
            <script>setTimeout(function(){ window.location.href = "<?php echo htmlspecialchars($redirect_url, ENT_QUOTES); ?>"; }, 3000);</script>
        <?php else: ?>
            <form method="POST" action="">
                <label for="user">Username</label>
                <input type="text" id="user" name="user" autocomplete="username" required>

                <label for="pass">Password</label>
                <input type="password" id="pass" name="pass" autocomplete="current-password" required>

                <button type="submit">Login &amp; Whitelist IP</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
