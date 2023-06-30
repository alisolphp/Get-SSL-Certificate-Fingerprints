<?php

$hostname = "google.com";
$fingerprints = getSSLCertificateFingerprints($hostname);

echo "hostname: ".$hostname."<br>";
echo "<pre>";
var_dump($fingerprints);
echo "</pre>";
/*
    array(2) {
      ["sha256"]=>
      string(64) "2aa97ca45c98e14d3cd12af65b396f1a51731b94ec4b5f705a8920116775adc2"
      ["sha1"]=>
      string(40) "a8b52bde3bdbfbab1b787ae68fde23236cab863b"
    }
*/

function getSSLCertificateFingerprints($hostname) {
    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false
        ]
    ]);
    $stream = stream_socket_client(
        "ssl://{$hostname}:443",
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if (!$stream) {
        die("Failed to connect: {$errno} - {$errstr}\n");
    }
    $certificate = stream_context_get_params($stream)['options']['ssl']['peer_certificate'];
    $sha256 = openssl_x509_fingerprint($certificate, 'sha256');
    $sha1 = openssl_x509_fingerprint($certificate, 'sha1');

    $fingerprints = [
        "sha256" => $sha256,
        "sha1" => $sha1,
    ];

    return $fingerprints;
}
