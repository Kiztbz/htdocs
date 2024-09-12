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
    $c = [];
    foreach ($sqli_patterns as $pattern) {
        if (stripos($response, $pattern) !== false) {
            $c[] = "Location: $url <br> Vulnerable Parameter: $param <br><br>";
        }
        if (count($c) == 5) {
            break;
        }
    }
    if (empty($c)) {
        // return "No SQL Injection vulnerability detected at $test_url. Response: <pre>" . htmlspecialchars($response) . "</pre>";

    } else {
        return implode("<br>", $c);
    }
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
        echo "<h2>Actionable Report: SQL Injection Vulnerability</h2>
        <h2>1. Vulnerability Overview </h2>
        <p>
        SQL Injection is a web security vulnerability that allows attackers to interfere with the queries an application makes to its database. It generally occurs when untrusted data is inserted into a SQL query without proper validation or sanitization, allowing the attacker to execute arbitrary SQL code.
        </p>
        <br>
        <h2>2. Identified Vulnerability</h2>
        ";

        $waybackUrls = getWaybackUrls($domain);
        if (is_string($waybackUrls)) {
            echo $waybackUrls;
        } else {
            // echo "Found URLs:<br>";
            foreach ($waybackUrls as $waybackUrl) {
                // echo htmlspecialchars($waybackUrl) . "<br>";

                $params = extractQueryParameters($waybackUrl);
                if (!empty($params)) {
                    // echo "Testing SQL injection for parameters: " . implode(", ", $params) . "<br>";
                    foreach ($params as $param) {
                        echo checkSQLInjection($waybackUrl, $param);
                    }
                } else {
                    // echo "No query parameters found for $waybackUrl.<br>";
                }
            }
            echo "
            Risk Level: High <br> Type of SQL Injection: <br>- Error-based <br>- Union-based <br>- Blind SQL Injection <br>- Time-based blind SQL Injection<br><br>
                <h2>3. Impact</h2>
                <p>
                - Data Leakage:** Attackers can retrieve sensitive information like usernames, passwords, emails, credit card details, etc.<br>
                - Data Manipulation:** They can modify or delete data in the database.<br>
                - Authentication Bypass:** Attackers can gain unauthorized access to accounts or systems.<br>
                - Remote Code Execution:** In severe cases, attackers can execute system-level commands.<br>
                </p>
                <br>
                <h2>4. Actionable Steps for Mitigation</h2>
                <h3>1. Input Validation:</h3>
                <p>
                - Ensure that all inputs are strictly validated and sanitized.<br>
                - Use input validation libraries to reject harmful SQL queries.<br>
                - Apply whitelisting for specific characters allowed in input fields.<br>
                </p>
                <h3>2. Parameterized Queries (Prepared Statements):</h3>
                - Always use parameterized queries or prepared statements for SQL queries to avoid direct inclusion of user inputs.<br>
                <code>cursor.execute('\SELECT * FROM users WHERE username = %s'\, (username,))<code>
                ";
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
                <span id="tooltip3">TOOLTIP : An XSS (Cross-Site Scripting) attack lets an attacker inject malicious
                    scripts into a website, which then execute in victims' browsers. This can steal sensitive
                    information like cookies or session tokens. </span>
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

    <style>
        @font-face {
            font-family: "Poppins";
            font-weight: normal;
            font-style: normal;
            src: url("/fonts/Poppins/Poppins-Medium.ttf");
        }

        @font-face {
            font-family: "Handjet";
            font-weight: normal;
            font-style: normal;
            src: url("/fonts/Handjet/Handjet-VariableFont_ELGR\,ELSH\,wght.ttf");
        }

        * {
            margin: 0px;
            padding: 0px;
            transition: 0.5s ease-in-out;
            font-family: Poppins;
        }

        *::-webkit-scrollbar {
            width: 5px;
            border-radius: 20px;
        }

        :root {
            --c1: black;
            /*Color1*/
            --c2: rgb(18, 255, 18);
            /*Color2*/
            --tc: rgb(18, 255, 18);
            /*Text-Color*/
            --btc: #e9d6b8;
            /*Button-Text-Color*/
        }

        [data-theme="light"] {
            --c1: #e9d6b8;
            /*Color1*/
            --c2: linear-gradient(#ddc595, #8b7449);
            /*Color2*/
            --tc: black;
            /*Text-Color*/
            --btc: #e9d6b8;
            /*Button-Text-Color*/
        }

        [data-theme="dark"] {
            --bg: #e9d6b8;
            --g1: linear-gradient(black, #4a3d28);
            --tc: white;
            --lc: ;
            --btc: black;
            --invert: invert(0%);
            --invertoff: invert(100%);
            /*Link-Colour*/
        }

        body {
            background-color: var(--c1);
            height: 100vh;
            width: 100%;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            color: var(--tc);
            background-image: url(/images/757530618600.jpg);
            background-size: cover;
            backdrop-filter: blur(5px);
        }

        h2 {
            color: var(--tc);
            font-family: Handjet;
        }

        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 50px;
            width: 90%;
            margin: 20px auto;
        }

        a {
            color: var(--tc);
            text-decoration: none;
        }

        main {
            display: flex;
            margin: 50px auto;
            width: 80%;
        }

        .card {
            width: 400px;
            height: 400px;
            margin: auto;
            border-radius: 10px;
            border: 1px solid var(--tc);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: space-between;
            padding: 30px 30px 5px 30px;
            background-color: var(--c1);
        }

        .outputcard {
            width: 600px;
            background-color: var(--c1);
            overflow: scroll;
        }

        .outputcard h2 {
            margin-bottom: 20px;
        }

        footer {
            color: var(--tc);
            width: 90%;
            margin: auto;
        }

        form {
            display: flex;
            flex-direction: column;
        }

        /*HEADER*/
        .logo {
            width: 20%;
            font-family: Handjet;
            font-size: 35px;
        }

        .navlinks {
            width: 50%;
            display: flex;
            justify-content: space-evenly;
        }

        .navlinks a {
            font-family: Handjet;
            font-size: 25px;
        }

        .themebtn {
            width: 10%;
        }

        /*FORM*/
        .inputs {
            width: 100%;
        }

        select,
        input {
            background-color: var(--c1);
            color: var(--tc);
            border-radius: 3px;
            border: 2px solid var(--tc);
            padding: 2px 5px;
        }

        input:active {
            background-color: var(--c1);
            color: var(--tc);
        }

        .outputbox {
            width: 80%;
            margin: auto;
            overflow: auto;
        }

        .in {
            display: flex;
            flex-direction: column;
            margin: 20px 0px;
        }

        .credit {
            font-size: 10px;
        }

        .submit:hover {
            background-color: var(--tc);
            color: var(--c1);
        }

        tooltip span {
            font-size: 20px;
            font-family: Handjet;
        }
    </style>
</body>

</html>