<?php
/**
 * Portal configuration defaults
 */

// IP list ID in vicidial_ip_list_entries
$ip_list_id = 'ViciWhite';

// Minimum user level required to use the portal (1 = all active agents)
$min_user_level = 1;

// Redirect URLs after successful login (full URLs — portal runs on :446, ViciDial on :443)
$redirect_agent = 'https://YOUR_DOMAIN/agc/vicidial.php';
$redirect_admin = 'https://YOUR_DOMAIN/vicidial/welcome.php';

// User level threshold for admin redirect (9 = admin)
$admin_level = 9;

// Portal title
$portal_title = 'ViciDial Agent Portal';
