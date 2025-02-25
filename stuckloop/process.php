<?php
// Start output buffering
ob_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Include database connection
include('db_connection.php');

// Function to handle JSON response
function jsonResponse($status, $data)
{
    header('Content-Type: application/json');
    echo json_encode(['status' => $status, 'data' => $data]);
    exit; // Ensure no further output is sent
}

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve form data
    $name = isset($_POST['name']) ? trim($_POST['name']) : '';
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    $message = isset($_POST['message']) ? trim($_POST['message']) : '';

    // Validate inputs
    if (empty($name) || empty($email) || empty($message)) {
        jsonResponse('error', 'All fields are required.');
    }

    // Prepare SQL query
    $stmt = $conn->prepare("INSERT INTO contact_form (name, email, message) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $email, $message);

    // Execute the query
    if ($stmt->execute()) {
        jsonResponse('success', 'Your message has been sent successfully.');
    } else {
        jsonResponse('error', 'There was an error sending your message.');
    }

    // Close the statement
    $stmt->close();
} else {
    jsonResponse('error', 'Invalid request method.');
}

// Close database connection
$conn->close();

// Send the output buffer and clean up
ob_end_flush();
