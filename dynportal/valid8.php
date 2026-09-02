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

// Determine client IPv4. The VPS sip-allowlist is IPv4-only, so we must
// record an IPv4 even when the browser reached us over IPv6.
// Priority: form-submitted client_ipv4 (set client-side via api4.ipify.org)
// > CF-Connecting-IP > X-Forwarded-For > X-Real-IP > REMOTE_ADDR.
$candidate_ips = [];
if (!empty($_POST['client_ipv4'])) {
    $candidate_ips[] = trim($_POST['client_ipv4']);
}
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $candidate_ips[] = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
}
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $candidate_ips[] = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
}
if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
    $candidate_ips[] = trim($_SERVER['HTTP_X_REAL_IP']);
}
$candidate_ips[] = $_SERVER['REMOTE_ADDR'];

foreach ($candidate_ips as $candidate) {
    if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $client_ip = $candidate;
        break;
    }
}

if (empty($client_ip) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $error = 'Unable to determine your public IPv4 address. If your browser is using IPv6 only, this page will detect IPv4 in a moment — please wait, then retry.';
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
                // Insert the IP with explicit timestamp (audit trail)
                $stmt = mysqli_prepare($link,
                    "INSERT INTO vicidial_ip_list_entries (ip_list_id, ip_address, entry_date) VALUES (?, ?, NOW())"
                );
                if ($stmt) {
                    mysqli_stmt_bind_param($stmt, 'ss', $ip_list_id, $client_ip);
                    mysqli_stmt_execute($stmt);
                    mysqli_stmt_close($stmt);
                }
            } else {
                // Refresh entry_date on each login (audit trail)
                $stmt = mysqli_prepare($link,
                    "UPDATE vicidial_ip_list_entries SET entry_date = NOW() WHERE ip_list_id = ? AND ip_address = ?"
                );
                if ($stmt) {
                    mysqli_stmt_bind_param($stmt, 'ss', $ip_list_id, $client_ip);
                    mysqli_stmt_execute($stmt);
                    mysqli_stmt_close($stmt);
                }
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
            background: #14231e;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: #203731;
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
            color: #FFB612;
        }
        .ip-display {
            text-align: center;
            font-size: 0.85rem;
            color: #9cb0a8;
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.3rem;
            font-size: 0.9rem;
            color: #c8d2cd;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 0.6rem;
            margin-bottom: 1rem;
            border: 1px solid #3a5a50;
            border-radius: 4px;
            background: #14231e;
            color: #e0e0e0;
            font-size: 1rem;
        }
        input:focus {
            outline: none;
            border-color: #FFB612;
        }
        button {
            width: 100%;
            padding: 0.7rem;
            background: #FFB612;
            color: #203731;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
        }
        button:hover { background: #FFD35C; }
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
            <p style="text-align:center; font-size:0.85rem; color:#9cb0a8; margin-top:0.5rem;">Redirecting in 3 seconds... <a href="<?php echo htmlspecialchars($redirect_url); ?>" style="color:#FFB612;">Click here</a> if not redirected.</p>
            <script>setTimeout(function(){ window.location.href = "<?php echo htmlspecialchars($redirect_url, ENT_QUOTES); ?>"; }, 3000);</script>
        <?php else: ?>
            <form method="POST" action="" id="loginForm">
                <input type="hidden" id="client_ipv4" name="client_ipv4" value="">

                <label for="user">Username</label>
                <input type="text" id="user" name="user" autocomplete="username" required>

                <label for="pass">Password</label>
                <input type="password" id="pass" name="pass" autocomplete="current-password" required>

                <button type="submit" id="submitBtn" disabled>Detecting your IPv4&hellip;</button>
            </form>
            <script>
            (function () {
                var btn = document.getElementById('submitBtn');
                var hidden = document.getElementById('client_ipv4');
                var display = document.querySelector('.ip-display');
                fetch('https://api4.ipify.org/?format=json', { cache: 'no-store' })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (data && /^\d{1,3}(\.\d{1,3}){3}$/.test(data.ip)) {
                            hidden.value = data.ip;
                            if (display) { display.textContent = 'Your public IPv4: ' + data.ip; }
                            btn.disabled = false;
                            btn.textContent = 'Login & Whitelist IP';
                        } else {
                            btn.textContent = 'Could not detect IPv4 — retry';
                        }
                    })
                    .catch(function () {
                        // Allow submission anyway; server will fall back to REMOTE_ADDR.
                        btn.disabled = false;
                        btn.textContent = 'Login & Whitelist IP (IPv4 detection unavailable)';
                    });
            })();
            </script>
        <?php endif; ?>
    </div>
</body>
</html>
