<?php
// Run with: php tests/security.php && php tests/security.php --missing-key
define( 'YOURLS_ABSPATH', __DIR__ );
if( !in_array( '--missing-key', $argv, true ) ) {
    define( 'YOURLS_COOKIEKEY', str_repeat( 'private-test-key-', 4 ) );
}

$options = array(
    'm365_tenant_id' => 'contoso.onmicrosoft.com',
    'm365_client_id' => '11111111-1111-1111-1111-111111111111',
    'm365_client_secret' => 'test-secret',
    'm365_allowed_groups' => '22222222-2222-2222-2222-222222222222',
);
$tenant_id = '33333333-3333-3333-3333-333333333333';
$issuer = 'https://login.microsoftonline.com/' . $tenant_id . '/v2.0';
$cookies = array();
$token_response = '';
$site_url = 'https://short.example';

function yourls_get_yourls_site() { global $site_url; return $site_url; }
function yourls_get_option( $key, $default = null ) { global $options; return $options[$key] ?? $default; }
function yourls_update_option( $key, $value ) { global $options; $options[$key] = $value; }
function yourls_add_filter( ...$args ) {}
function yourls_add_action( ...$args ) {}
function yourls_apply_filter( ...$args ) { return true; }
function yourls_http_get_body( $url ) { global $issuer; return json_encode( array( 'issuer' => $issuer ) ); }
function yourls_admin_url( $path ) { return 'https://short.example/admin/' . $path; }
function yourls_setcookie( $name, $value, $expire, $path, $domain, $secure, $httponly ) {
    global $cookies;
    $cookies[$name] = compact( 'value', 'expire', 'path', 'domain', 'secure', 'httponly' );
    return true;
}
function yourls_is_API() { return false; }
function yourls_set_user( $user ) { $GLOBALS['user'] = $user; }
function yourls__( $message ) { return $message; }
function yourls_debug_log( $message ) {}
function yourls_get_cookie_life() { return 3600; }
function yourls_do_action( ...$args ) {}
function yourls_http_post( $url, $headers, $body ) {
    global $token_response;
    check( $url === yourls_m365_token_endpoint(), 'Wrong token endpoint' );
    check( $body['code_verifier'] === 'test-verifier', 'Wrong PKCE verifier' );
    check( $body['redirect_uri'] === yourls_m365_redirect_uri(), 'Wrong redirect URI' );
    return (object) array( 'status_code' => 200, 'body' => json_encode( array( 'id_token' => $token_response ) ) );
}
function yourls_redirect( $url, $status ) { throw new RuntimeException( 'redirect:' . $url ); }

require dirname( __DIR__ ) . '/plugin.php';

function check( $condition, $message ) {
    if( !$condition ) {
        throw new RuntimeException( $message );
    }
}

if( in_array( '--missing-key', $argv, true ) ) {
    check( yourls_m365_cookie_secret() === false, 'Predictable fallback signing key accepted' );
    check( !yourls_m365_set_signed_cookie( YOURLS_M365_SESSION_COOKIE, array( 'exp' => time() + 60 ), 60 ), 'Cookie created without secret' );
    echo "Missing-key checks passed\n";
    exit( 0 );
}

check( yourls_m365_issuer() === $issuer, 'Tenant domain did not resolve to tenant GUID issuer' );
check( !yourls_m365_is_allowed( 'x@example.com', array() ), 'Missing group allowed' );
check( !yourls_m365_is_allowed( 'x@example.com', array( 'wrong' ) ), 'Other group allowed' );
check( yourls_m365_is_allowed( 'x@example.com', array( '22222222-2222-2222-2222-222222222222' ) ), 'Allowed group denied' );

check( yourls_m365_set_signed_cookie( YOURLS_M365_SESSION_COOKIE, array(
    'email' => 'x@example.com',
    'groups' => array( '22222222-2222-2222-2222-222222222222' ),
    'cfg' => yourls_m365_config_fingerprint(),
    'exp' => time() + 3600,
), 3600 ), 'Cookie creation failed' );
$cookie = $cookies[YOURLS_M365_SESSION_COOKIE];
check( str_starts_with( YOURLS_M365_SESSION_COOKIE, '__Host-' ), 'Missing host cookie prefix' );
check( $cookie['domain'] === '' && $cookie['path'] === '/' && $cookie['secure'] && $cookie['httponly'], 'Weak cookie attributes' );
check( yourls_m365_read_signed_cookie( $cookie['value'] ) !== false, 'Signed cookie denied' );
check( yourls_m365_read_signed_cookie( $cookie['value'] . 'x' ) === false, 'Modified cookie accepted' );
$_COOKIE[YOURLS_M365_SESSION_COOKIE] = $cookie['value'];
check( yourls_m365_shunt_is_valid_user( null ) === true, 'Valid SSO session denied' );
check( $GLOBALS['user'] === 'x@example.com', 'SSO user not set' );
$site_url = 'https://other.example';
check( yourls_m365_read_signed_cookie( $cookie['value'] ) === false, 'Cookie accepted for another site' );
$site_url = 'http://short.example';
yourls_m365_set_signed_cookie( YOURLS_M365_SESSION_COOKIE, array(
    'email' => 'x@example.com', 'groups' => array( '22222222-2222-2222-2222-222222222222' ),
    'cfg' => yourls_m365_config_fingerprint(), 'exp' => time() + 3600,
), 3600 );
$_COOKIE[YOURLS_M365_SESSION_COOKIE] = $cookies[YOURLS_M365_SESSION_COOKIE]['value'];
check( yourls_m365_shunt_is_valid_user( null ) === null, 'SSO session accepted on HTTP site' );
$site_url = 'https://short.example';
$_COOKIE[YOURLS_M365_SESSION_COOKIE] = $cookie['value'];
$options['m365_client_id'] = '44444444-4444-4444-4444-444444444444';
check( yourls_m365_shunt_is_valid_user( null ) === null, 'Old SSO session survived client change' );
$options['m365_client_id'] = '11111111-1111-1111-1111-111111111111';
unset( $_COOKIE[YOURLS_M365_SESSION_COOKIE] );

$key = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$csr = openssl_csr_new( array( 'CN' => 'test.example' ), $key, array( 'digest_alg' => 'sha256' ) );
$certificate = openssl_csr_sign( $csr, null, $key, 1, array( 'digest_alg' => 'sha256' ) );
openssl_x509_export( $certificate, $pem );
$der = base64_decode( preg_replace( '/-----[^-]+-----|\s+/', '', $pem ) );
$options['m365_jwks_cache'] = array(
    'tenant' => 'contoso.onmicrosoft.com',
    'fetched' => time(),
    'keys' => array( array( 'kid' => 'test-key', 'x5c' => array( base64_encode( $der ) ), 'issuer' => $issuer ) ),
);

function token( $claims, $key, $algorithm = 'RS256' ) {
    $header = yourls_m365_b64url_encode( json_encode( array( 'alg' => $algorithm, 'kid' => 'test-key' ) ) );
    $body = yourls_m365_b64url_encode( json_encode( $claims ) );
    openssl_sign( $header . '.' . $body, $signature, $key, OPENSSL_ALGO_SHA256 );
    return $header . '.' . $body . '.' . yourls_m365_b64url_encode( $signature );
}

$claims = array(
    'iss' => $issuer, 'tid' => $tenant_id, 'aud' => $options['m365_client_id'],
    'nonce' => 'expected-nonce', 'sub' => 'subject', 'preferred_username' => 'x@example.com', 'iat' => time(),
    'exp' => time() + 3600, 'groups' => array( '22222222-2222-2222-2222-222222222222' ),
);
check( yourls_m365_verify_id_token( token( $claims, $key ), $claims['aud'], $issuer, 'expected-nonce' ) !== false, 'Valid token denied' );
foreach( array(
    'nonce' => 'other-nonce',
    'aud' => 'other-client',
    'iss' => 'https://login.microsoftonline.com/55555555-5555-5555-5555-555555555555/v2.0',
    'tid' => '55555555-5555-5555-5555-555555555555',
    'exp' => time() - 120,
    'iat' => time() + 120,
) as $claim => $bad_value ) {
    $bad = $claims;
    $bad[$claim] = $bad_value;
    check( yourls_m365_verify_id_token( token( $bad, $key ), $claims['aud'], $issuer, 'expected-nonce' ) === false, "Bad $claim accepted" );
}
check( yourls_m365_verify_id_token( token( $claims, $key, 'none' ), $claims['aud'], $issuer, 'expected-nonce' ) === false, 'Wrong algorithm accepted' );
$wrong_key = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
check( yourls_m365_verify_id_token( token( $claims, $wrong_key ), $claims['aud'], $issuer, 'expected-nonce' ) === false, 'Wrong signature accepted' );
$options['m365_jwks_cache']['keys'][0]['issuer'] = 'https://login.microsoftonline.com/{tenantid}/v2.0';
check( yourls_m365_verify_id_token( token( $claims, $key ), $claims['aud'], $issuer, 'expected-nonce' ) !== false, 'Valid templated key issuer denied' );
$options['m365_jwks_cache']['keys'][0]['issuer'] = 'https://login.microsoftonline.com/55555555-5555-5555-5555-555555555555/v2.0';
check( yourls_m365_verify_id_token( token( $claims, $key ), $claims['aud'], $issuer, 'expected-nonce' ) === false, 'Wrong key issuer accepted' );
$options['m365_jwks_cache']['keys'][0]['issuer'] = $issuer;

function callback_state( $state = 'expected-state' ) {
    global $cookies;
    yourls_m365_set_signed_cookie( YOURLS_M365_STATE_COOKIE, array(
        's' => $state, 'v' => 'test-verifier', 'n' => 'expected-nonce',
        'cfg' => yourls_m365_config_fingerprint(), 'exp' => time() + 600,
    ), 600 );
    $_COOKIE[YOURLS_M365_STATE_COOKIE] = $cookies[YOURLS_M365_STATE_COOKIE]['value'];
    $_GET = array( 'code' => 'test-code', 'state' => 'expected-state' );
    unset( $cookies[YOURLS_M365_SESSION_COOKIE] );
}

$token_response = token( $claims, $key );
callback_state( 'wrong-state' );
check( str_contains( yourls_m365_handle_callback(), 'state mismatch' ), 'Wrong state accepted' );
check( !isset( $cookies[YOURLS_M365_SESSION_COOKIE] ), 'Wrong state created a session' );

$bad = $claims;
$bad['nonce'] = 'wrong-nonce';
$token_response = token( $bad, $key );
callback_state();
check( str_contains( yourls_m365_handle_callback(), 'could not be verified' ), 'Wrong nonce accepted by callback' );
check( !isset( $cookies[YOURLS_M365_SESSION_COOKIE] ), 'Wrong nonce created a session' );

$bad = $claims;
$bad['groups'] = array( 'wrong-group' );
$token_response = token( $bad, $key );
callback_state();
$result = yourls_m365_handle_callback();
check( str_contains( $result, 'not authorized' ), 'Wrong group callback result: ' . $result );
check( !isset( $cookies[YOURLS_M365_SESSION_COOKIE] ), 'Wrong group created a session' );

$bad = $claims;
$bad['_claim_names'] = array( 'groups' => 'src1' );
$token_response = token( $bad, $key );
callback_state();
check( str_contains( yourls_m365_handle_callback(), 'not authorized' ), 'Group overage accepted' );
check( !isset( $cookies[YOURLS_M365_SESSION_COOKIE] ), 'Group overage created a session' );

$token_response = token( $claims, $key );
callback_state();
try {
    yourls_m365_handle_callback();
    throw new RuntimeException( 'Valid callback did not redirect' );
} catch( RuntimeException $exception ) {
    check( $exception->getMessage() === 'redirect:' . yourls_m365_redirect_uri(), 'Valid callback redirected incorrectly' );
}
check( isset( $cookies[YOURLS_M365_SESSION_COOKIE] ), 'Valid callback did not create a session' );

$options['m365_tenant_id'] = 'other.onmicrosoft.com';
check( yourls_m365_get_jwks() === array(), 'JWKS cache reused after tenant switch' );

echo "Security checks passed\n";
