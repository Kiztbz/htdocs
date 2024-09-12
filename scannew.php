<?php
ob_start(); // Start output buffering

$serviceMap = [
    21 => 'FTP',
    22 => 'SSH',
    23 => 'Telnet',
    25 => 'SMTP',
    53 => 'DNS',
    80 => 'HTTP',
    110 => 'POP3',
    143 => 'IMAP',
    443 => 'HTTPS',
    3306 => 'MySQL',
    5432 => 'PostgreSQL',
    8080 => 'HTTP-Alt',
    3389 => 'RDP',
    6379 => 'Redis',
    27017 => 'MongoDB'
];

function getService($port)
{
    global $serviceMap;
    return isset($serviceMap[$port]) ? $serviceMap[$port] : 'Unknown';
}

function scanPorts($host, $ports = [], $timeout = 1)
{
    $openPorts = [];
    foreach ($ports as $port) {
        $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if ($connection) {
            $service = getService($port);
            echo "Port $port ($service) is open on $host.<br>";
            $openPorts[] = ['port' => $port, 'service' => $service];
            fclose($connection);
        } else {
            echo "Port $port is closed on $host.<br>";
        }
    }
    return $openPorts;
}

// More functions (getWaybackUrls, extractQueryParameters, checkSQLInjection, checkXSS)...
function getWaybackUrls($domain)
{
    $waybackApiUrl = "http://web.archive.org/cdx/search/cdx?url={$domain}*&fl=original&collapse=urlkey&output=json";
    $waybackResponse = @file_get_contents($waybackApiUrl);

    if ($waybackResponse === false) {
        return "Failed to retrieve data from Wayback Machine API.";
    }

    $waybackUrls = json_decode($waybackResponse, true);

    if ($waybackUrls === null || !is_array($waybackUrls)) {
        return "Invalid response from Wayback Machine API.";
    }

    array_shift($waybackUrls);

    $urls = [];
    foreach ($waybackUrls as $entry) {
        if (isset($entry[0])) {
            $urls[] = $entry[0];
        }
    }

    if (empty($urls)) {
        return "No URLs found for $domain.";
    }

    return $urls;
}

function extractQueryParameters($url)
{
    $parsed_url = parse_url($url);
    if (!isset($parsed_url['query'])) {
        return [];
    }
    parse_str($parsed_url['query'], $params);
    return array_keys($params);
}

function checkSQLInjection($url, $param)
{
    $sqli_payload = "\\";
    $parsed_url = parse_url($url);
    if (!isset($parsed_url['query'])) {
        return "Invalid URL or no query parameters found.";
    }
    parse_str($parsed_url['query'], $params);
    if (!array_key_exists($param, $params)) {
        return "Parameter '$param' not found in the URL query string.";
    }
    $params[$param] = $sqli_payload;
    $query_string = http_build_query($params);
    $test_url = $parsed_url['scheme'] . "://" . $parsed_url['host'] . $parsed_url['path'] . '?' . $query_string;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $test_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
    $response = curl_exec($ch);
    if ($response === false) {
        return "Failed to fetch the URL: " . curl_error($ch);
    }
    curl_close($ch);
    $sqli_patterns = ['SQL', 'database', 'syntax;', 'warning', 'mysql_fetch', 'mysqli', 'pg_query', "MySQL"];
    foreach ($sqli_patterns as $pattern) {
        if (stripos($response, $pattern) !== false) {
            return "SQL Injection vulnerability found at $test_url (Pattern: $pattern)";
        }
    }
    return "No SQL Injection vulnerability detected at $test_url. Response: <pre>" . htmlspecialchars($response) . "</pre>";
}


function checkXSS($url)
{
    $xss_payload = '<script>alert("XSS")</script>';
    $parsed_url = parse_url($url);

    if (!isset($parsed_url['query'])) {
        return "Invalid URL or no query parameters found. Ensure the URL contains query parameters.";
    }

    parse_str($parsed_url['query'], $params);

    $test_url = $parsed_url['scheme'] . "://" . $parsed_url['host'] . $parsed_url['path'];
    $test_url .= '?' . http_build_query(array_map(function ($v) use ($xss_payload) {
        return $xss_payload;
    }, $params), '', '&', PHP_QUERY_RFC3986);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $test_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        return "Failed to fetch the URL: $error";
    }


    if (stripos($response, $xss_payload) !== false) {
        return "XSS vulnerability found at $test_url";
    }

    return "No XSS vulnerability detected at $test_url.";
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action = $_POST['action'];
    $host = filter_var($_POST['host'], FILTER_SANITIZE_STRING);
    $domain = filter_var($_POST['domain'], FILTER_SANITIZE_URL);
    #$url = filter_var($_POST['url'], FILTER_SANITIZE_URL);
    #$param = filter_var($_POST['param'], FILTER_SANITIZE_STRING);

    if ($action === 'port_scan') {
        echo "<h2>Scanning Ports on $host:</h2>";

        $portsToScan = array_keys($GLOBALS['serviceMap']);
        $openPorts = scanPorts($host, $portsToScan);

        echo "<h3>Open ports:</h3>";
        foreach ($openPorts as $portInfo) {
            echo "Port: " . $portInfo['port'] . " - Service: " . $portInfo['service'] . "<br>";
        }

    } elseif ($action === 'wayback_sql_injection') {
        echo "<h2>Wayback Machine Parameter Extraction for $domain:</h2>";

        $waybackUrls = getWaybackUrls($domain);
        if (is_string($waybackUrls)) {
            echo $waybackUrls;
        } else {
            echo "Found URLs:<br>";
            foreach ($waybackUrls as $waybackUrl) {
                echo htmlspecialchars($waybackUrl) . "<br>";

                $params = extractQueryParameters($waybackUrl);
                if (!empty($params)) {
                    echo "Testing SQL injection for parameters: " . implode(", ", $params) . "<br>";
                    foreach ($params as $param) {
                        echo checkSQLInjection($waybackUrl, $param);
                    }
                } else {
                    echo "No query parameters found for $waybackUrl.<br>";
                }
            }
        }
    }
}

$output = ob_get_clean(); // Capture and clean the buffer
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="global.css">
    <title>S-square Security</title>
</head>

<body>
    <header>
        <div class="logo">$-$quare $ecurity</div>
        <div class="navlinks">
            <a href="index.html">Home</a>
            <a href="tips.html">Tips</a>
            <a href="about.html">About</a>
        </div>
        <!-- <div class="themebtn">T</div> -->
    </header>

    <main>
        <div class="card inputcard">
            <h2>INPUT</h2>
            <div class="inputs">
                <form method="post" action="scannew.php">
                    <label for="action">Select Action:</label>
                    <select id="action" name="action">
                        <option value="port_scan">Port Scan</option>
                        <option value="wayback_sql_injection">SQL Injection</option>
                        <option value="check_xss">Check XSS</option>
                    </select>

                    <div class="in" id="hostInput">
                        <label for="host">Host (for port scan):</label>
                        <input type="text" id="host" name="host">
                    </div>

                    <div class="in" id="domainInput">
                        <label for="domain">Domain (for SQL Injection):</label>
                        <input type="text" id="domain" name="domain">
                    </div>

                    <div class="in" id="xssInput">
                        <label for="xss">Domain (for XSS Injection):</label>
                        <input type="text" id="xss" name="xss">
                    </div>

                    <input class="submit" type="submit" value="Submit">
                </form>
            </div>
            <tooltip>
                <span id="tooltip1">TOOLTIP : A port scanner is a tool used to probe a computer or network for open
                    ports. Open ports are communication endpoints that accept data, which can indicate running services
                    or applications. </span>
                <span id="tooltip2">TOOLTIP : SQL Injection is a security vulnerability where an attacker can manipulate
                    SQL queries by inserting malicious code through untrusted input. This can lead to unauthorized
                    access or manipulation of a database. </span>
                <span id="tooltip3">TOOLTIP : SQL Injection is a security vulnerability where an attacker can manipulate
                    SQL queries by inserting malicious code through untrusted input. This can lead to unauthorized
                    access or manipulation of a database. </span>
            </tooltip>
            <div class="credit">$-$quare $ecurity</div>
        </div>
        <div class="card outputcard">
            <h2>Report</h2>
            <div class="outputbox">
                <?php
                // Display the captured output in the correct box
                echo $output;
                ?>
            </div>
        </div>
    </main>

    <footer>
        <div class="logo">$-$quare $ecurity</div>
        <div class="team">
            <a href="#">Falcon</a>
            <a href="#">Kiz</a>
            <a href="#">Manas</a>
            <a href="#">Arsh</a>
        </div>
    </footer>

    <script>
        // Get dropdown and input elements
        const dropdown = document.getElementById("action");
        const hostInput = document.getElementById("hostInput");
        const domainInput = document.getElementById("domainInput");
        const xssInput = document.getElementById("xssInput");
        const t1 = document.getElementById("tooltip1");
        const t2 = document.getElementById("tooltip2");
        const t3 = document.getElementById("tooltip3");

        // Hide all inputs by default
        domainInput.style.display = "none";
        xssInput.style.display = "none";
        t2.style.display = "none";
        t3.style.display = "none";

        // Event listener to show/hide input fields based on selected action
        dropdown.addEventListener("change", function () {
            const selectedOption = dropdown.value;

            // Hide both input fields by default
            hostInput.style.display = "none";
            domainInput.style.display = "none";
            xssInput.style.display = "none";
            t1.style.display = "none";
            t2.style.display = "none";
            t3.style.display = "none";

            // Show the correct input field based on selected option
            if (selectedOption === "port_scan") {
                hostInput.style.display = "flex";
                t1.style.display = "flex";
            } else if (selectedOption === "wayback_sql_injection") {
                domainInput.style.display = "flex";
                t2.style.display = "flex";
            }
            else if (selectedOption === "check_xss") {
                xssInput.style.display = "flex";
                t3.style.display = "flex";
            }
        });
    </script>


</body>

</html>