<?php
/**
 * Database connection - reads credentials from /etc/astguiclient.conf
 */

$conf_file = '/etc/astguiclient.conf';
if (!file_exists($conf_file)) {
    die('Configuration file not found.');
}

$conf = file_get_contents($conf_file);

function get_conf_value($conf, $key) {
    if (preg_match('/^' . preg_quote($key, '/') . '\s*=>\s*(.+)$/m', $conf, $m)) {
        return trim($m[1]);
    }
    return '';
}

$VARDB_server   = get_conf_value($conf, 'VARDB_server');
$VARDB_database = get_conf_value($conf, 'VARDB_database');
$VARDB_user     = get_conf_value($conf, 'VARDB_user');
$VARDB_pass     = get_conf_value($conf, 'VARDB_pass');
$VARDB_port     = get_conf_value($conf, 'VARDB_port');

$link = mysqli_connect($VARDB_server, $VARDB_user, $VARDB_pass, $VARDB_database, (int)$VARDB_port);
if (!$link) {
    die('Database connection failed.');
}
mysqli_set_charset($link, 'utf8');
