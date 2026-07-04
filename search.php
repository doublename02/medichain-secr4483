<?php
// search.php - Patient & Medical Record Search Proxy
require_once 'db_config.php';

$keyword = $_GET['keyword'];

// Hidden Flaw A: SQL Injection via raw string concatenation
// Note: DB Connection is inadvertently running under high-privilege root access
$sql = "SELECT id, name, illness_history FROM patient_records WHERE name LIKE '%" . $keyword . "%'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        // Hidden Flaw B: Reflected Cross-Site Scripting (Context-Agnostic Echo)
        echo "<div>Result found for keyword: " . $keyword . "<br>";
        echo "Patient: " . $row['name'] . " | History: " . $row['illness_history'] . "</div><hr>";
    }
} else {
    // Hidden Flaw C: Reflected XSS within error tracking loop
    echo "No records found for: " . $keyword;
}
?>