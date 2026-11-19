<?php

/*
 * Security releases of PHP and the advisories (CVE / GHSA) each one fixes.
 *
 * GENERATED FILE — do not edit by hand. Regenerate with:
 *
 *     php scripts/update-php-advisories.php
 *
 * Sources: https://www.php.net/ChangeLog-8.php, https://www.php.net/releases/
 */

return [

    'generated' => '2026-11-16',

    // branch => [fixed-in version => [release date, advisory id => summary]]
    'releases' => [

        '8.1' => [
            '8.1.3' => [
                'date' => '2022-02-17',
                'advisories' => [
                    'CVE-2021-21708' => 'Filter: UAF due to php_filter_float() failing for ints',
                ],
            ],
            '8.1.7' => [
                'date' => '2022-06-09',
                'advisories' => [
                    'CVE-2022-31626' => 'mysqlnd: mysqlnd/pdo password buffer overflow',
                    'CVE-2022-31625' => 'pgsql: Uninitialized array in pg_query_params()',
                ],
            ],
            '8.1.8' => [
                'date' => '2022-07-07',
                'advisories' => [
                    'CVE-2022-31627' => 'Fileinfo: Heap buffer overflow in finfo_buffer',
                ],
            ],
            '8.1.11' => [
                'date' => '2022-09-29',
                'advisories' => [
                    'CVE-2022-31628' => 'Core: phar wrapper: DOS when using quine gzip file',
                    'CVE-2022-31629' => 'Core: Don\'t mangle HTTP variable names that clash with ones that have a specific semantic meaning',
                ],
            ],
            '8.1.12' => [
                'date' => '2022-10-27',
                'advisories' => [
                    'CVE-2022-31630' => 'GD: OOB read due to insufficient input validation in imageloadfont()',
                    'CVE-2022-37454' => 'Hash: buffer overflow in hash_update() on long parameter',
                ],
            ],
            '8.1.14' => [
                'date' => '2023-01-05',
                'advisories' => [
                    'CVE-2022-31631' => 'PDO/SQLite: PDO::quote() may return unquoted string',
                ],
            ],
            '8.1.16' => [
                'date' => '2023-02-14',
                'advisories' => [
                    'CVE-2023-0662' => 'SAPI: DOS vulnerability when parsing multipart request body',
                ],
            ],
            '8.1.20' => [
                'date' => '2023-06-08',
                'advisories' => [
                    'CVE-2023-3247' => 'Soap: Missing error check and insufficient random bytes in HTTP Digest authentication for SOAP',
                ],
            ],
            '8.1.22' => [
                'date' => '2023-08-03',
                'advisories' => [
                    'CVE-2023-3823' => 'Libxml: Security issue with external entity loading in XML without enabling it',
                    'CVE-2023-3824' => 'Phar: Buffer mismanagement in phar_dir_read()',
                ],
            ],
            '8.1.28' => [
                'date' => '2024-04-11',
                'advisories' => [
                    'CVE-2024-1874' => 'Standard: Command injection via array-ish $command parameter of proc_open',
                    'CVE-2024-2756' => 'Standard: __Host-/__Secure- cookie bypass due to partial CVE-2022-31629 fix',
                    'CVE-2024-3096' => 'Standard: password_verify can erroneously return true, opening ATO risk',
                ],
            ],
            '8.1.29' => [
                'date' => '2024-06-06',
                'advisories' => [
                    'CVE-2024-4577' => 'CGI: Bypass of CVE-2012-1823, Argument Injection in PHP-CGI',
                    'CVE-2024-5458' => 'Filter: Filter bypass in filter_var FILTER_VALIDATE_URL',
                    'CVE-2024-5585' => 'Standard: Bypass of CVE-2024-1874',
                ],
            ],
            '8.1.30' => [
                'date' => '2024-09-26',
                'advisories' => [
                    'CVE-2024-8926' => 'CGI: Bypass of CVE-2024-4577, Parameter Injection Vulnerability',
                    'CVE-2024-8927' => 'CGI: cgi.force_redirect configuration is bypassable due to the environment variable collision',
                    'CVE-2024-9026' => 'FPM: Logs from childrens may be altered',
                    'CVE-2024-8925' => 'SAPI: Erroneous parsing of multipart form data',
                ],
            ],
            '8.1.31' => [
                'date' => '2024-11-21',
                'advisories' => [
                    'GHSA-4w77-75f9-2c8w' => 'CLI: Heap-Use-After-Free in sapi_read_post_data Processing in CLI SAPI Interface',
                    'CVE-2024-8932' => 'LDAP: OOB access in ldap_escape',
                    'CVE-2024-8929' => 'MySQLnd: Leak partial content of the heap through heap buffer over-read',
                    'CVE-2024-11236' => 'PDO DBLIB: Integer overflow in the dblib quoter causing OOB writes',
                    'CVE-2024-11234' => 'Streams: Configuring a proxy in a stream context might allow for CRLF injection in URIs',
                    'CVE-2024-11233' => 'Streams: Single byte overread with convert.quoted-printable-decode filter',
                ],
            ],
            '8.1.32' => [
                'date' => '2025-03-13',
                'advisories' => [
                    'GHSA-wg4p-4hqh-c3g9' => 'LibXML: Reocurrence of #72714',
                    'CVE-2025-1219' => 'LibXML: libxml streams use wrong `content-type` header when requesting a redirected resource',
                    'CVE-2025-1736' => 'Streams: Stream HTTP wrapper header check might omit basic auth header',
                    'CVE-2025-1861' => 'Streams: Stream HTTP wrapper truncate redirect location to 1024 bytes',
                    'CVE-2025-1734' => 'Streams: Streams HTTP wrapper does not fail for headers without colon',
                    'CVE-2025-1217' => 'Streams: Header parser of `http` stream wrapper does not handle folded headers',
                ],
            ],
            '8.1.33' => [
                'date' => '2025-07-03',
                'advisories' => [
                    'CVE-2025-1735' => 'PGSQL: pgsql extension does not check for errors during escaping',
                    'CVE-2025-6491' => 'SOAP: NULL Pointer Dereference in PHP SOAP Extension via Large XML Namespace Prefix',
                    'CVE-2025-1220' => 'Standard: Null byte termination in hostnames',
                ],
            ],
            '8.1.34' => [
                'date' => '2025-12-18',
                'advisories' => [
                    'CVE-2025-14180' => 'PDO: PDO quoting result null deref',
                    'GHSA-www2-q4fc-65wf' => 'Standard: Null byte termination in dns_get_record()',
                    'CVE-2025-14178' => 'Standard: Heap buffer overflow in array_merge()',
                    'CVE-2025-14177' => 'Standard: Information Leak of Memory in getimagesize',
                ],
            ],
        ],

        '8.2' => [
            '8.2.1' => [
                'date' => '2023-01-05',
                'advisories' => [
                    'CVE-2022-31631' => 'PDO/SQLite: PDO::quote() may return unquoted string',
                ],
            ],
            '8.2.3' => [
                'date' => '2023-02-14',
                'advisories' => [
                    'CVE-2023-0567' => 'Core: Password_verify() always return true with some hash',
                    'CVE-2023-0568' => 'Core: 1-byte array overrun in common path resolve code',
                    'CVE-2023-0662' => 'SAPI: DOS vulnerability when parsing multipart request body',
                ],
            ],
            '8.2.7' => [
                'date' => '2023-06-08',
                'advisories' => [
                    'CVE-2023-3247' => 'Soap: Missing error check and insufficient random bytes in HTTP Digest authentication for SOAP',
                ],
            ],
            '8.2.9' => [
                'date' => '2023-08-03',
                'advisories' => [
                    'CVE-2023-3823' => 'Libxml: Security issue with external entity loading in XML without enabling it',
                    'CVE-2023-3824' => 'Phar: Buffer mismanagement in phar_dir_read()',
                ],
            ],
            '8.2.18' => [
                'date' => '2024-04-11',
                'advisories' => [
                    'CVE-2024-1874' => 'Standard: Command injection via array-ish $command parameter of proc_open',
                    'CVE-2024-2756' => 'Standard: __Host-/__Secure- cookie bypass due to partial CVE-2022-31629 fix',
                    'CVE-2024-3096' => 'Standard: password_verify can erroneously return true, opening ATO risk',
                ],
            ],
            '8.2.20' => [
                'date' => '2024-06-06',
                'advisories' => [
                    'CVE-2024-4577' => 'CGI: Bypass of CVE-2012-1823, Argument Injection in PHP-CGI',
                    'CVE-2024-5458' => 'Filter: Filter bypass in filter_var FILTER_VALIDATE_URL',
                    'CVE-2024-5585' => 'Standard: Bypass of CVE-2024-1874',
                ],
            ],
            '8.2.24' => [
                'date' => '2024-09-26',
                'advisories' => [
                    'CVE-2024-8926' => 'CGI: Bypass of CVE-2024-4577, Parameter Injection Vulnerability',
                    'CVE-2024-8927' => 'CGI: cgi.force_redirect configuration is bypassable due to the environment variable collision',
                    'CVE-2024-9026' => 'FPM: Logs from childrens may be altered',
                    'CVE-2024-8925' => 'SAPI: Erroneous parsing of multipart form data',
                ],
            ],
            '8.2.26' => [
                'date' => '2024-11-21',
                'advisories' => [
                    'GHSA-4w77-75f9-2c8w' => 'CLI: Heap-Use-After-Free in sapi_read_post_data Processing in CLI SAPI Interface',
                    'CVE-2024-8932' => 'LDAP: OOB access in ldap_escape',
                    'CVE-2024-8929' => 'MySQLnd: Leak partial content of the heap through heap buffer over-read',
                    'CVE-2024-11236' => 'PDO DBLIB: Integer overflow in the dblib quoter causing OOB writes',
                    'CVE-2024-11234' => 'Streams: Configuring a proxy in a stream context might allow for CRLF injection in URIs',
                    'CVE-2024-11233' => 'Streams: Single byte overread with convert.quoted-printable-decode filter',
                ],
            ],
            '8.2.28' => [
                'date' => '2025-03-13',
                'advisories' => [
                    'GHSA-wg4p-4hqh-c3g9' => 'LibXML: Reocurrence of #72714',
                    'CVE-2025-1219' => 'LibXML: libxml streams use wrong `content-type` header when requesting a redirected resource',
                    'CVE-2025-1736' => 'Streams: Stream HTTP wrapper header check might omit basic auth header',
                    'CVE-2025-1861' => 'Streams: Stream HTTP wrapper truncate redirect location to 1024 bytes',
                    'CVE-2025-1734' => 'Streams: Streams HTTP wrapper does not fail for headers without colon',
                    'CVE-2025-1217' => 'Streams: Header parser of `http` stream wrapper does not handle folded headers',
                ],
            ],
            '8.2.29' => [
                'date' => '2025-07-03',
                'advisories' => [
                    'CVE-2025-1735' => 'PGSQL: pgsql extension does not check for errors during escaping',
                    'CVE-2025-6491' => 'SOAP: NULL Pointer Dereference in PHP SOAP Extension via Large XML Namespace Prefix',
                    'CVE-2025-1220' => 'Standard: Null byte termination in hostnames',
                ],
            ],
            '8.2.30' => [
                'date' => '2025-12-18',
                'advisories' => [
                    'CVE-2025-14180' => 'PDO: PDO quoting result null deref',
                    'GHSA-www2-q4fc-65wf' => 'Standard: Null byte termination in dns_get_record()',
                    'CVE-2025-14178' => 'Standard: Heap buffer overflow in array_merge()',
                    'CVE-2025-14177' => 'Standard: Information Leak of Memory in getimagesize',
                ],
            ],
            '8.2.31' => [
                'date' => '2026-05-07',
                'advisories' => [
                    'CVE-2026-6735' => 'FPM: XSS within status endpoint',
                    'CVE-2026-7259' => 'MBString: Null pointer dereference in php_mb_check_encoding() via mb_ereg_search_init()',
                    'CVE-2025-14179' => 'PDO_Firebird: SQL injection via NUL bytes in quoted strings',
                    'CVE-2026-6722' => 'SOAP: Stale SOAP_GLOBAL(ref_map) pointer with Apache Map',
                    'CVE-2026-7261' => 'SOAP: Use-after-free after header parsing failure with SOAP_PERSISTENCE_SESSION',
                    'CVE-2026-7262' => 'SOAP: Broken Apache map value NULL check',
                    'CVE-2026-7568' => 'Standard: Signed integer overflow of char array offset',
                    'CVE-2026-7258' => 'Standard: Consistently pass unsigned char to ctype.h functions',
                ],
            ],
            '8.2.32' => [
                'date' => '2026-07-02',
                'advisories' => [
                    'CVE-2026-14355' => 'OpenSSL: Memory corruption (zend_mm_heap corrupted) in openssl_encrypt with AES-WRAP-PAD',
                ],
            ],
            '8.2.33' => [
                'date' => '2026-07-30',
                'advisories' => [
                    'CVE-2026-9672' => 'GD: Upgrade libgd',
                    'CVE-2026-17543' => 'PGSQL: SQL injection via E\'...\' backslash breakout',
                    'CVE-2026-7260' => 'Phar: Crash via recursive symlinks',
                ],
            ],
            '8.2.34' => [
                'date' => '2026-09-24',
                'advisories' => [
                    'GHSA-ch8v-r6jh-4vvr' => 'Filter: FILTER_SANITIZE_ENCODED does not encode 0xFF',
                    'CVE-2026-91768' => 'FPM: IPv6 ACL bypass in FastCGI listen.allowed_clients due to partial address comparison',
                    'CVE-2025-1218' => 'MySQLnd: Various packet overreads in mysqlnd wire protocol',
                    'CVE-2026-91769' => 'OpenSSL: TLS hostname verification falls back to CN after SAN mismatch',
                    'CVE-2026-91767' => 'OpenSSL: Heap buffer overflow in php_openssl_matches_wildcard_name() on crafted server certificate wildcard CN',
                    'CVE-2026-6103' => 'Phar: Integer overflow in phar_tar_number() allowing TAR archive entry injection',
                    'CVE-2026-91765' => 'SOAP: Unbounded recursion in server-side cleanup_xml_node()',
                    'CVE-2025-14181' => 'SOAP: Integer overflow to buffer overflow in SOAP HTTP parsing',
                    'CVE-2026-92842' => 'Standard: Out-of-bounds read in convert.* stream filters when line-break-chars contains NUL',
                    'CVE-2026-91766' => 'Standard: Cross-origin credential leak in HTTP stream wrapper redirects',
                    'CVE-2026-93682' => 'Standard: Out-of-bounds read in the HTTP stream wrapper when following a redirect with an empty Location header',
                    'CVE-2026-17545' => 'Windows: Reserved device names are not rejected before file and stream I/O',
                ],
            ],
            '8.2.35' => [
                'date' => '2026-10-21',
                'advisories' => [
                    'GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp' => 'Core: Avoid state corruption via bailout',
                ],
            ],
        ],

        '8.3' => [
            '8.3.6' => [
                'date' => '2024-04-11',
                'advisories' => [
                    'CVE-2024-1874' => 'Standard: Command injection via array-ish $command parameter of proc_open',
                    'CVE-2024-2756' => 'Standard: __Host-/__Secure- cookie bypass due to partial CVE-2022-31629 fix',
                    'CVE-2024-3096' => 'Standard: password_verify can erroneously return true, opening ATO risk',
                    'CVE-2024-2757' => 'Standard: mb_encode_mimeheader runs endlessly for some inputs',
                ],
            ],
            '8.3.8' => [
                'date' => '2024-06-06',
                'advisories' => [
                    'CVE-2024-4577' => 'CGI: Bypass of CVE-2012-1823, Argument Injection in PHP-CGI',
                    'CVE-2024-5458' => 'Filter: Filter bypass in filter_var FILTER_VALIDATE_URL',
                    'CVE-2024-5585' => 'Standard: Bypass of CVE-2024-1874',
                ],
            ],
            '8.3.12' => [
                'date' => '2024-09-26',
                'advisories' => [
                    'CVE-2024-8926' => 'CGI: Bypass of CVE-2024-4577, Parameter Injection Vulnerability',
                    'CVE-2024-8927' => 'CGI: cgi.force_redirect configuration is bypassable due to the environment variable collision',
                    'CVE-2024-9026' => 'FPM: Logs from childrens may be altered',
                    'CVE-2024-8925' => 'SAPI: Erroneous parsing of multipart form data',
                ],
            ],
            '8.3.14' => [
                'date' => '2024-11-21',
                'advisories' => [
                    'GHSA-4w77-75f9-2c8w' => 'CLI: Heap-Use-After-Free in sapi_read_post_data Processing in CLI SAPI Interface',
                    'CVE-2024-8932' => 'LDAP: OOB access in ldap_escape',
                    'CVE-2024-8929' => 'MySQLnd: Leak partial content of the heap through heap buffer over-read',
                    'CVE-2024-11236' => 'PDO DBLIB: Integer overflow in the dblib quoter causing OOB writes',
                    'CVE-2024-11234' => 'Streams: Configuring a proxy in a stream context might allow for CRLF injection in URIs',
                    'CVE-2024-11233' => 'Streams: Single byte overread with convert.quoted-printable-decode filter',
                ],
            ],
            '8.3.19' => [
                'date' => '2025-03-13',
                'advisories' => [
                    'CVE-2024-11235' => 'Core: Reference counting in php_request_shutdown causes Use-After-Free',
                    'GHSA-wg4p-4hqh-c3g9' => 'LibXML: Reocurrence of #72714',
                    'CVE-2025-1219' => 'LibXML: libxml streams use wrong `content-type` header when requesting a redirected resource',
                    'CVE-2025-1736' => 'Streams: Stream HTTP wrapper header check might omit basic auth header',
                    'CVE-2025-1861' => 'Streams: Stream HTTP wrapper truncate redirect location to 1024 bytes',
                    'CVE-2025-1734' => 'Streams: Streams HTTP wrapper does not fail for headers without colon',
                    'CVE-2025-1217' => 'Streams: Header parser of `http` stream wrapper does not handle folded headers',
                ],
            ],
            '8.3.23' => [
                'date' => '2025-07-03',
                'advisories' => [
                    'CVE-2025-1735' => 'PGSQL: pgsql extension does not check for errors during escaping',
                    'CVE-2025-6491' => 'SOAP: NULL Pointer Dereference in PHP SOAP Extension via Large XML Namespace Prefix',
                    'CVE-2025-1220' => 'Standard: Null byte termination in hostnames',
                ],
            ],
            '8.3.29' => [
                'date' => '2025-12-18',
                'advisories' => [
                    'CVE-2025-14180' => 'PDO: PDO quoting result null deref',
                    'GHSA-www2-q4fc-65wf' => 'Standard: Null byte termination in dns_get_record()',
                    'CVE-2025-14178' => 'Standard: Heap buffer overflow in array_merge()',
                    'CVE-2025-14177' => 'Standard: Information Leak of Memory in getimagesize',
                ],
            ],
            '8.3.31' => [
                'date' => '2026-05-07',
                'advisories' => [
                    'CVE-2026-6735' => 'FPM: XSS within status endpoint',
                    'CVE-2026-7259' => 'MBString: Null pointer dereference in php_mb_check_encoding() via mb_ereg_search_init()',
                    'CVE-2025-14179' => 'PDO_Firebird: SQL injection via NUL bytes in quoted strings',
                    'CVE-2026-6722' => 'SOAP: Stale SOAP_GLOBAL(ref_map) pointer with Apache Map',
                    'CVE-2026-7261' => 'SOAP: Use-after-free after header parsing failure with SOAP_PERSISTENCE_SESSION',
                    'CVE-2026-7262' => 'SOAP: Broken Apache map value NULL check',
                    'CVE-2026-7568' => 'Standard: Signed integer overflow of char array offset',
                    'CVE-2026-7258' => 'Standard: Consistently pass unsigned char to ctype.h functions',
                ],
            ],
            '8.3.32' => [
                'date' => '2026-07-02',
                'advisories' => [
                    'CVE-2026-12184' => 'Streams: Segfault in file_get_contents w/ a https URL and a proxy set',
                    'CVE-2026-14355' => 'OpenSSL: Memory corruption (zend_mm_heap corrupted) in openssl_encrypt with AES-WRAP-PAD',
                ],
            ],
            '8.3.33' => [
                'date' => '2026-07-30',
                'advisories' => [
                    'CVE-2026-9672' => 'GD: Upgrade libgd',
                    'CVE-2026-17543' => 'PGSQL: SQL injection via E\'...\' backslash breakout',
                    'CVE-2026-7260' => 'Phar: Crash via recursive symlinks',
                ],
            ],
            '8.3.35' => [
                'date' => '2026-09-24',
                'advisories' => [
                    'GHSA-ch8v-r6jh-4vvr' => 'Filter: FILTER_SANITIZE_ENCODED does not encode 0xFF',
                    'CVE-2026-91768' => 'FPM: IPv6 ACL bypass in FastCGI listen.allowed_clients due to partial address comparison',
                    'CVE-2025-1218' => 'MySQLnd: Various packet overreads in mysqlnd wire protocol',
                    'CVE-2026-91769' => 'OpenSSL: TLS hostname verification falls back to CN after SAN mismatch',
                    'CVE-2026-91767' => 'OpenSSL: Heap buffer overflow in php_openssl_matches_wildcard_name() on crafted server certificate wildcard CN',
                    'CVE-2026-6103' => 'Phar: Integer overflow in phar_tar_number() allowing TAR archive entry injection',
                    'CVE-2026-91765' => 'SOAP: Unbounded recursion in server-side cleanup_xml_node()',
                    'CVE-2025-14181' => 'SOAP: Integer overflow to buffer overflow in SOAP HTTP parsing',
                    'CVE-2026-92842' => 'Standard: Out-of-bounds read in convert.* stream filters when line-break-chars contains NUL',
                    'CVE-2026-91766' => 'Standard: Cross-origin credential leak in HTTP stream wrapper redirects',
                    'CVE-2026-93682' => 'Standard: Out-of-bounds read in the HTTP stream wrapper when following a redirect with an empty Location header',
                    'CVE-2026-17545' => 'Windows: Reserved device names are not rejected before file and stream I/O',
                ],
            ],
            '8.3.36' => [
                'date' => '2026-10-21',
                'advisories' => [
                    'GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp' => 'Core: Avoid state corruption via bailout',
                ],
            ],
        ],

        '8.4' => [
            '8.4.1' => [
                'date' => '2024-11-21',
                'advisories' => [],
            ],
            '8.4.5' => [
                'date' => '2025-03-13',
                'advisories' => [
                    'CVE-2024-11235' => 'Core: Reference counting in php_request_shutdown causes Use-After-Free',
                    'GHSA-wg4p-4hqh-c3g9' => 'LibXML: Reocurrence of #72714',
                    'CVE-2025-1219' => 'LibXML: libxml streams use wrong `content-type` header when requesting a redirected resource',
                    'CVE-2025-1736' => 'Streams: Stream HTTP wrapper header check might omit basic auth header',
                    'CVE-2025-1861' => 'Streams: Stream HTTP wrapper truncate redirect location to 1024 bytes',
                    'CVE-2025-1734' => 'Streams: Streams HTTP wrapper does not fail for headers without colon',
                    'CVE-2025-1217' => 'Streams: Header parser of `http` stream wrapper does not handle folded headers',
                ],
            ],
            '8.4.10' => [
                'date' => '2025-07-03',
                'advisories' => [
                    'CVE-2025-1735' => 'PGSQL: pgsql extension does not check for errors during escaping',
                    'CVE-2025-6491' => 'SOAP: NULL Pointer Dereference in PHP SOAP Extension via Large XML Namespace Prefix',
                    'CVE-2025-1220' => 'Standard: Null byte termination in hostnames',
                ],
            ],
            '8.4.16' => [
                'date' => '2025-12-18',
                'advisories' => [
                    'CVE-2025-14180' => 'PDO: PDO quoting result null deref',
                    'GHSA-www2-q4fc-65wf' => 'Standard: Null byte termination in dns_get_record()',
                    'CVE-2025-14178' => 'Standard: Heap buffer overflow in array_merge()',
                    'CVE-2025-14177' => 'Standard: Information Leak of Memory in getimagesize',
                ],
            ],
            '8.4.21' => [
                'date' => '2026-05-07',
                'advisories' => [
                    'CVE-2026-7263' => 'DOM: Dom\\XMLDocument::C14N() emits duplicate xmlns declarations after setAttributeNS()',
                    'CVE-2026-6735' => 'FPM: XSS within status endpoint',
                    'CVE-2026-7259' => 'MBString: Null pointer dereference in php_mb_check_encoding() via mb_ereg_search_init()',
                    'CVE-2026-6104' => 'MBString: Out-of-bounds access in mbfl_name2encoding_ex()',
                    'CVE-2025-14179' => 'PDO_Firebird: SQL injection via NUL bytes in quoted strings',
                    'CVE-2026-6722' => 'SOAP: Stale SOAP_GLOBAL(ref_map) pointer with Apache Map',
                    'CVE-2026-7261' => 'SOAP: Use-after-free after header parsing failure with SOAP_PERSISTENCE_SESSION',
                    'CVE-2026-7262' => 'SOAP: Broken Apache map value NULL check',
                    'CVE-2026-7568' => 'Standard: Signed integer overflow of char array offset',
                    'CVE-2026-7258' => 'Standard: Consistently pass unsigned char to ctype.h functions',
                    'CVE-2026-12184' => 'Streams: Segfault in file_get_contents w/ a https URL and a proxy set',
                ],
            ],
            '8.4.23' => [
                'date' => '2026-07-02',
                'advisories' => [
                    'CVE-2026-14355' => 'OpenSSL: Memory corruption (zend_mm_heap corrupted) in openssl_encrypt with AES-WRAP-PAD',
                ],
            ],
            '8.4.24' => [
                'date' => '2026-07-30',
                'advisories' => [
                    'CVE-2026-17544' => 'BCMath: Out-of-bounds write in bccomp()',
                    'CVE-2026-9672' => 'GD: Upgrade libgd',
                    'CVE-2026-17543' => 'PGSQL: SQL injection via E\'...\' backslash breakout',
                    'CVE-2026-7260' => 'Phar: Crash via recursive symlinks',
                ],
            ],
            '8.4.26' => [
                'date' => '2026-09-24',
                'advisories' => [
                    'CVE-2026-91768' => 'FPM: IPv6 ACL bypass in FastCGI listen.allowed_clients due to partial address comparison',
                    'CVE-2025-1218' => 'MySQLnd: Various packet overreads in mysqlnd wire protocol',
                    'CVE-2026-91769' => 'OpenSSL: TLS hostname verification falls back to CN after SAN mismatch',
                    'CVE-2026-91767' => 'OpenSSL: Heap buffer overflow in php_openssl_matches_wildcard_name() on crafted server certificate wildcard CN',
                    'CVE-2026-6103' => 'Phar: Integer overflow in phar_tar_number() allowing TAR archive entry injection',
                    'CVE-2026-91765' => 'SOAP: Unbounded recursion in server-side cleanup_xml_node()',
                    'CVE-2025-14181' => 'SOAP: Integer overflow to buffer overflow in SOAP HTTP parsing',
                    'CVE-2026-93682' => 'Standard: Out-of-bounds read in the HTTP stream wrapper when following a redirect with an empty Location header',
                    'CVE-2026-92842' => 'Standard: Out-of-bounds read in convert.* stream filters when line-break-chars contains NUL',
                    'CVE-2026-91766' => 'Standard: Cross-origin credential leak in HTTP stream wrapper redirects',
                    'CVE-2026-17545' => 'Windows: Reserved device names are not rejected before file and stream I/O',
                ],
            ],
            '8.4.27' => [
                'date' => '2026-10-21',
                'advisories' => [
                    'GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp' => 'Core: Avoid state corruption via bailout',
                ],
            ],
        ],

        '8.5' => [
            '8.5.1' => [
                'date' => '2025-12-18',
                'advisories' => [
                    'CVE-2025-14180' => 'PDO: PDO quoting result null deref',
                    'GHSA-www2-q4fc-65wf' => 'Standard: Null byte termination in dns_get_record()',
                    'CVE-2025-14178' => 'Standard: Heap buffer overflow in array_merge()',
                    'CVE-2025-14177' => 'Standard: Information Leak of Memory in getimagesize',
                    'CVE-2025-67899' => 'URI: uriparser through 0.9.9 allows unbounded recursion and stack consumption',
                ],
            ],
            '8.5.6' => [
                'date' => '2026-05-07',
                'advisories' => [
                    'CVE-2026-7263' => 'DOM: Dom\\XMLDocument::C14N() emits duplicate xmlns declarations after setAttributeNS()',
                    'CVE-2026-6735' => 'FPM: XSS within status endpoint',
                    'CVE-2026-7259' => 'MBString: Null pointer dereference in php_mb_check_encoding() via mb_ereg_search_init()',
                    'CVE-2026-6104' => 'MBString: Out-of-bounds access in mbfl_name2encoding_ex()',
                    'CVE-2025-14179' => 'PDO_Firebird: SQL injection via NUL bytes in quoted strings',
                    'CVE-2026-6722' => 'SOAP: Stale SOAP_GLOBAL(ref_map) pointer with Apache Map',
                    'CVE-2026-7261' => 'SOAP: Use-after-free after header parsing failure with SOAP_PERSISTENCE_SESSION',
                    'CVE-2026-7262' => 'SOAP: Broken Apache map value NULL check',
                    'CVE-2026-7568' => 'Standard: Signed integer overflow of char array offset',
                    'CVE-2026-7258' => 'Standard: Consistently pass unsigned char to ctype.h functions',
                    'CVE-2026-12184' => 'Streams: Segfault in file_get_contents w/ a https URL and a proxy set',
                    'CVE-2026-42371' => 'URI: uriparser before 1.0.1 has numeric truncation in text range comparison',
                ],
            ],
            '8.5.7' => [
                'date' => '2026-06-04',
                'advisories' => [
                    'CVE-2026-44927' => 'URI: In uriparser before 1.0.2, there is pointer difference truncation to int in various places',
                    'CVE-2026-44928' => 'URI: In uriparser before 1.0.2, the function family EqualsUri can misclassify two unequal URIs as equal',
                ],
            ],
            '8.5.8' => [
                'date' => '2026-07-02',
                'advisories' => [
                    'CVE-2026-14355' => 'OpenSSL: Memory corruption (zend_mm_heap corrupted) in openssl_encrypt with AES-WRAP-PAD',
                ],
            ],
            '8.5.9' => [
                'date' => '2026-07-30',
                'advisories' => [
                    'CVE-2026-17544' => 'BCMath: Out-of-bounds write in bccomp()',
                    'CVE-2026-9672' => 'GD: Upgrade libgd',
                    'CVE-2026-17543' => 'PGSQL: SQL injection via E\'...\' backslash breakout',
                    'CVE-2026-7260' => 'Phar: Crash via recursive symlinks',
                ],
            ],
            '8.5.11' => [
                'date' => '2026-09-24',
                'advisories' => [
                    'CVE-2026-91768' => 'FPM: IPv6 ACL bypass in FastCGI listen.allowed_clients due to partial address comparison',
                    'CVE-2025-1218' => 'MySQLnd: Various packet overreads in mysqlnd wire protocol',
                    'CVE-2026-91769' => 'OpenSSL: TLS hostname verification falls back to CN after SAN mismatch',
                    'CVE-2026-91767' => 'OpenSSL: Heap buffer overflow in php_openssl_matches_wildcard_name() on crafted server certificate wildcard CN',
                    'CVE-2026-6103' => 'Phar: Integer overflow in phar_tar_number() allowing TAR archive entry injection',
                    'CVE-2026-91765' => 'SOAP: Unbounded recursion in server-side cleanup_xml_node()',
                    'CVE-2025-14181' => 'SOAP: Integer overflow to buffer overflow in SOAP HTTP parsing',
                    'CVE-2026-93682' => 'Standard: Out-of-bounds read in the HTTP stream wrapper when following a redirect with an empty Location header',
                    'CVE-2026-92842' => 'Standard: Out-of-bounds read in convert.* stream filters when line-break-chars contains NUL',
                    'CVE-2026-91766' => 'Standard: Cross-origin credential leak in HTTP stream wrapper redirects',
                    'CVE-2026-17545' => 'Windows: Reserved device names are not rejected before file and stream I/O',
                ],
            ],
            '8.5.12' => [
                'date' => '2026-10-21',
                'advisories' => [
                    'GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp' => 'Core: Avoid state corruption via bailout',
                ],
            ],
        ],

    ],

];
