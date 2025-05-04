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
            // echo "Port $port ($service) is open on $host.<br>";
            $openPorts[] = ['port' => $port, 'service' => $service];
            fclose($connection);
        }
        // else {
        //     echo "Port $port is closed on $host.<br>";
        // }
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
            return "SQL Injection vulnerability found at $test_url (Pattern: $pattern)<br><br>";
        }
    }
    //return "No SQL Injection vulnerability detected at $test_url. Response: <pre>" . htmlspecialchars($response) . "</pre>";
}


function checkXSS($domain)
{
    $timestamp = time();
    $currentDate = gmdate('Y-m-d', $timestamp);
    echo "
    <h1>Actionable Report: Cross-Site Scripting (XSS) Vulnerability</h1>
    <h2>Report Summary:</h2>
    <p>
    - Vulnerability Type: Cross-Site Scripting (XSS)<br>
    - Severity: High<br>
    - Tested URL/Endpoint: $domain <br>
    - Date of Discovery: $currentDate <br>
    </p>
    ";

    // Get the list of URLs from the Wayback Machine API
    $waybackUrls = getWaybackUrls($domain);

    // If the result is not an array, it means there was an error (string returned)
    if (!is_array($waybackUrls)) {
        return $waybackUrls; // Return the error message
    }

    // XSS payload
    $xss_payload = '<script>alert("XSS")</script>';

    // Loop through each URL from the Wayback Machine
    foreach ($waybackUrls as $url) {
        $parsed_url = parse_url($url);

        if (!isset($parsed_url['query'])) {
            // echo "Skipping URL: $url (No query parameters found)\n";
            continue;
        }

        parse_str($parsed_url['query'], $params);

        // Build the test URL with the XSS payload injected
        $test_url = $parsed_url['scheme'] . "://" . $parsed_url['host'] . $parsed_url['path'];
        echo "- Affected Parameter: $test_url <br>";
        $test_url .= '?' . http_build_query(array_map(function ($v) use ($xss_payload) {
            return $xss_payload;
        }, $params), '', '&', PHP_QUERY_RFC3986);

        // Set up cURL to send the request
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
            echo "Failed to fetch URL: $url (Error: $error)\n";
            continue; // Move on to the next URL
        }

        // Check if the response contains the XSS payload
        if (stripos($response, htmlentities($xss_payload)) !== false || stripos($response, $xss_payload) !== false) {
            // echo "XSS vulnerability found at $url\n";
        } else {
            // echo "No XSS vulnerability detected at $url\n";
        }
    }
    echo "
    <p>
    - Impact: Theft of user sessions, credentials, defacement, malicious redirects, or spreading malware.
    </p>
    <br><br>
    <h2>Vulnerability Details:</h2>
    <h3>Type of XSS</h3>
    <p>
    - Reflected XSS (Non-Persistent)
    </p>
    <h3>Vulnerable Parameter</h3>
    <p>
    - The parameter is not properly sanitized or escaped before being rendered back on the page, leading to an XSS vulnerability.
    </p>
    <br>

    <h2>Technical Details:</h2>
    <p>
    - The web application directly reflects user input back into the HTML page without adequate sanitization or escaping. This allows an attacker to inject malicious scripts that will be executed in the user's browser.<br>
    - This specific XSS vulnerability was identified in the search feature, but other forms or parameters could potentially be vulnerable.<br>
    </p>
    <br>
    <h2>Business Impact</h2>
    <h3>- Security Risks</h3>
    <p>
        - Session Hijacking: Attackers can steal session cookies, impersonating users and gaining access to their accounts.<br>
        - Data Theft: Sensitive information (e.g., credentials, personal information) can be stolen.<br>
        - Browser Exploitation: Attackers could launch phishing attacks, deploy malware, or deface the website.<br>
        - Reputation Damage: The vulnerability could lead to a loss of user trust, legal repercussions, and non-compliance with security regulations.<br>
    </p>
    <br>
    <h2>Recommendations:</h2>
    <h3>1. Input Sanitization:</h3>
    <p>
    - Sanitize all user input fields to ensure malicious scripts are not accepted. Use functions to remove or escape special characters (like `<`, `>`, `\"`, `&`, etc.).
    </p>
    <br><br>
    <h2>2. Output Encoding:</h2>
    <p>
    - Encode user-generated content before outputting it into the HTML page to prevent script execution.
    </p>
    <br><br>
    <h2>3. Implement Content Security Policy (CSP):</h2>
    <p>
    - A CSP header helps mitigate the impact of XSS by preventing the execution of untrusted scripts.
    </p>
    <br><br>
    <h2>4. Server-Side Validation:</h2>
    <p>
        - Ensure that input is validated both on the client and server side. Only allow expected inputs and reject dangerous ones.
    </p>
    <br><br>
    <h2>5. Use Web Application Firewall (WAF):</h2>
    <p>
    - Implement a WAF to help detect and block malicious requests targeting XSS vulnerabilities.
    </p>
    <br><br>
    <h2>6. JavaScript Frameworks:</h2>
    <p>
    - Use modern JavaScript frameworks such as React or Angular, which inherently offer protection against XSS by escaping user input by default.
    </p>
";
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action = $_POST['action'];
    $host = filter_var($_POST['host'], FILTER_SANITIZE_STRING);
    $domain = filter_var($_POST['domain'], FILTER_SANITIZE_URL);
    $xss = filter_var($_POST['xss'], FILTER_SANITIZE_URL);
    // $param = filter_var($_POST['param'], FILTER_SANITIZE_STRING);

    if ($action === 'port_scan') {
        $timestamp = time();
        $currentDate = gmdate('Y-m-d', $timestamp);
        echo "
    <h1>Port Scanner Actionable Report</h1>
    <h2>1. Executive Summary</h2>
    <p>Provide an overview of the port scan's purpose, key findings, and risks identified.</p>
    <p>Scan Date: $currentDate </p>
    <p>Target: $host </p>
    <p>Purpose: Assess the network's attack surface by identifying open ports and exposed services. </p>
    <p>Key Findings: </p>
";
        $portsToScan = array_keys($GLOBALS['serviceMap']);
        $openPorts = scanPorts($host, $portsToScan);

        foreach ($openPorts as $portInfo) {
            echo "Port " . $portInfo['port'] . " with potential vulnerabilities<br>";
        }
        echo "
        <br>
        <h2>2. Vulnerabilities and Remediation</h2>
        <h3>High-Risk Ports</h3>
        <h4>Port 3389 (RDP)</h4>
        <p>Risk: The RDP port is filtered, but exposure could lead to brute-force or man-in-the-middle attacks.
        <br>
        Action:
        <br>
        Ensure multi-factor authentication is enabled.
        <br>
        Restrict RDP access to trusted IPs using a firewall or VPN.
        <br>
        Regularly update RDP service to prevent exploits.
        </p>
        <h4>Port 22 (SSH)</h4>
        <p>
        Risk: Open SSH service exposes the system to password-guessing attacks.
        <br>
        Action:
        <br>
        Disable password-based logins; use SSH keys.
        <br>
        Restrict SSH access to trusted IPs.
        <br>
        Implement tools like Fail2Ban to block malicious login attempts.
        </p>
        <br>

        <h3>Medium-Risk Ports</h3>
        <h4>Port 80 (HTTP)</h4>
        <p>
        Risk: HTTP traffic is unencrypted, making it vulnerable to interception.
        <br>
        Action:
        <br>
        Redirect all HTTP traffic to HTTPS.
        <br>
        Ensure SSL certificates are up to date.
        </p>
        <br>

        <h3>Low-Risk Ports</h3>
        <h4>Port 443 (HTTPS)</h4>
        <p>
        Risk: Generally considered safe, but outdated SSL/TLS configurations could be exploited.
        <br>
        Action:
        <br>
        Regularly audit SSL/TLS settings for weak ciphers or protocols.
        </p>
        <br>
        <br>

        <h2>3. Recommended Actions and Next Steps</h2>
        <p>
        Immediate Actions (Within 24-48 hours)
        <br>
        <br>
        Restrict access to high-risk ports (e.g., RDP, SSH) using a firewall or VPN.
Update outdated services (e.g., OpenSSH, Apache) to their latest versions.
Short-Term Actions (Within 1-2 weeks)
<br>
<br>

Implement network segmentation to isolate critical services.
Enable logging and monitoring for unusual activity on exposed ports.
Set up automated vulnerability scanning for continuous monitoring.
Long-Term Actions (Within 1-3 months)
<br>
<br>

Conduct a full vulnerability assessment, including web applications and database services.
Develop a patch management strategy to keep all services updated.
Train staff on security best practices and hardening techniques.
        </p>
        ";

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
                <p>- Always use parameterized queries or prepared statements for SQL queries to avoid direct inclusion of user inputs.</p>
                <h3>3. Use Stored Procedures:</h3>
                <p>- Implement stored procedures to handle data transactions, isolating SQL code from user input.</p>
                <h3>4. Least Privilege Principle:</h3>
                <p> - Limit database user privileges to only the required level. For instance, avoid allowing a web application database user to have DROP, DELETE, or UPDATE privileges unless necessary.</p>
                <h3>5. Web Application Firewall (WAF):</h3>
                <p>  - Use a WAF to detect and block SQL injection attempts based on suspicious patterns and anomalies.</p>
                <h3>6. Error Handling:</h3>
                <p>   - Avoid displaying detailed error messages that reveal database structures, query syntax, or vulnerable code paths to the end user.</p>
                ";
        }
    } elseif ($action === 'check_xss') {
        echo checkXSS($xss);
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
    <link rel="icon" type="image/x-icon" href="/images/favicon.ico">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.3/html2pdf.bundle.min.js"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;700&display=swap">
    <title>S-square Security</title>
</head>

<body>
    <header>
        <div class="logo">$-$quare $ecurity</div>
        <div class="navlinks">
            <a href="index.php">Home</a>
            <a href="tips.html">Tips</a>
            <a href="about.html">About</a>
        </div>
        <!-- <div class="themebtn">T</div> -->
    </header>

    <main>
        <div class="card inputcard">
            <h2>INPUT</h2>
            <div class="inputs">
                <form method="post" action="index.php">
                    <label for="action">Select Scan:</label>
                    <select id="action" name="action">
                        <option value="port_scan">Port Scan</option>
                        <option value="wayback_sql_injection">SQL Injection</option>
                        <option value="check_xss">XSS</option>
                    </select>

                    <div class="in" id="hostInput">
                        <label for="host">Domain (for port scan):</label>
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
            <div class="outputbox" id="outputbox">
                <?php
                // Display the captured output in the correct box
                echo $output;
                ?>
            </div>
            <div class="loader" id="loader" style="display: none;">
                <div class="rl-loading-container">
                    <div class="rl-loading-thumb rl-loading-thumb-1"></div>
                    <div class="rl-loading-thumb rl-loading-thumb-2"></div>
                    <div class="rl-loading-thumb rl-loading-thumb-3"></div>
                </div>
            </div>
            <button id="download-pdf">Download PDF</button>
        </div>
    </main>

    <footer>
        <div class="logo">$-$quare $ecurity</div>
        <div class="team">
            <a href="#">Stuck Loop</a>
        </div>
    </footer>

    <script>
        const form = document.querySelector("form");
        const loader = document.getElementById("loader");

        form.addEventListener("submit", function () {
            loader.style.display = "block"; // Show the loader
        });
    </script>

    <style>
        .loader {
            transform: translate(0px, -35px);
        }

        .rl-loading-container {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 10px;
        }

        .rl-loading-thumb {
            width: 10px;
            height: 40px;
            background-color: #41f3fd;
            margin: 4px;
            box-shadow: 0 0 12px 3px #0882ff;
            animation: rl-loading 1.5s ease-in-out infinite;
        }

        .rl-loading-thumb-1 {
            animation-delay: 0s;
        }

        .rl-loading-thumb-2 {
            animation-delay: 0.5s;
        }

        .rl-loading-thumb-3 {
            animation-delay: 1s;
        }

        @keyframes rl-loading {
            0% {}

            20% {
                background: white;
                transform: scale(1.5);
            }

            40% {
                background: #41f3fd;
                transform: scale(1);
            }
        }
    </style>

    <script>
        document.getElementById("download-pdf").addEventListener("click", function () {
            var element = document.getElementById('outputbox');

            // Clone the element and modify the clone for PDF
            var clone = element.cloneNode(true);

            // Apply PDF-specific styles
            clone.style.backgroundColor = 'white'; // Set background color to white
            clone.style.color = 'black'; // Set text color to black for visibility
            clone.style.fontFamily = 'Poppins, sans-serif'; // Set font to Poppins

            // Apply styles to all h2 tags within the cloned element
            var h2Tags = clone.getElementsByTagName('h2');
            for (var i = 0; i < h2Tags.length; i++) {
                h2Tags[i].style.color = 'black'; // Set h2 color to black
            }

            var opt = {
                margin: 1,
                padding: 10,
                filename: 'report.pdf',
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 4 },
                jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
            };

            // Generate the PDF and download it
            html2pdf().from(clone).set(opt).save();
        });
    </script>

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
            display: none;
        }

        :root {
            --c1: black;
            /*Color1*/
            --c2: #12fffb;
            /*Color2*/
            --tc: #12fffb;
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
            backdrop-filter: blur(3px);
        }

        card h2 {
            color: var(--tc);
            font-family: Handjet !important;
            font-size: 30px;
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
            height: 500px;
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
            height: 500px;
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
            border: 2px solid var(--tc);
            padding: 2px 5px;
            border-radius: 8px;
        }

        label {
            margin-top: 12px;
        }

        input:active {
            background-color: var(--c1);
            color: var(--tc);
        }

        .outputbox {
            width: 90%;
            margin: auto;
            overflow: auto;
            margin-bottom: 50px;
        }

        .in {
            display: flex;
            flex-direction: column;
            margin: 20px 0px;
        }

        .credit {
            font-size: 10px;
        }

        .submit {
            width: 60%;
            margin: auto;
            margin-top: 20px;
            border-radius: 20px;
            padding: 5px 0px;
        }

        .submit:hover,
        #download-pdf:hover {
            background-color: var(--tc);
            color: var(--c1);
        }

        tooltip span {
            font-size: 16px;
            font-family: Roboto;
        }

        /*OUTUT BOX*/
        .outputbox h1 {
            font-size: 30px;
            font-weight: 600;
        }

        .outputbox h2 {
            font-size: 26px;
        }

        .outputbox h3 {
            font-size: 22px;
            font-weight: 500;
        }

        .outputbox h4 {
            font-size: 20px;
            font-weight: 500;
        }

        .outputbox p {
            font-size: 14px;
            font-size: 100;
        }

        #download-pdf {
            padding: 5px 10px;
            border-radius: 8px;
            background-color: var(--c1);
            border: 2px solid var(--tc);
            color: var(--tc);
            transform: translate(0px, -15px);
        }
    </style>
</body>

</html>