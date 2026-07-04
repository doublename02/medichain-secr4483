<?php
// search_secure.php - Hardened Patient & Medical Record Search Proxy
// Refactored to eliminate SQL Injection (Flaw A) and Reflected XSS (Flaws B & C)

require_once 'db_config.php'; // $pdo must be a PDO instance loaded from .env credentials

// [S1] Presence and type validation at the system input boundary
if (!isset($_GET['keyword']) || trim($_GET['keyword']) === '') {
    http_response_code(400);
    exit('Invalid search query.');
}

$keyword = trim($_GET['keyword']);

// [S2] Semantic character-length boundary using mb_strlen()
// mb_strlen() counts Unicode codepoints (characters), NOT raw bytes.
// This correctly enforces a 100-character limit regardless of UTF-8 byte width,
// preventing byte/character mismatch bypass via multi-byte payloads.
if (mb_strlen($keyword, 'UTF-8') > 100) {
    http_response_code(400);
    exit('Search keyword exceeds maximum allowed length.');
}

// [S3] PDO prepared statement — structural separation of data plane and command plane.
// $pdo->prepare() sends the SQL template as a COM_STMT_PREPARE packet.
// MySQL parses and compiles the template ONCE, with :keyword as a typed parameter slot.
// The user-supplied value is transmitted separately in a COM_STMT_EXECUTE binary packet
// and is NEVER processed by the SQL grammar tokeniser.
try {
    $stmt = $pdo->prepare(
        "SELECT id, name, illness_history FROM patient_records WHERE name LIKE :keyword"
    );

    // The LIKE wildcard characters are appended in PHP string context,
    // not inside the SQL string — so they are part of the parameter value, not SQL syntax.
    $searchParam = '%' . $keyword . '%';
    $stmt->bindParam(':keyword', $searchParam, PDO::PARAM_STR);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    // [S4] Generic error response — never expose stack traces or DB details to the client
    error_log('DB search error: ' . $e->getMessage());
    http_response_code(500);
    exit('Search service temporarily unavailable.');
}

if (count($rows) > 0) {
    foreach ($rows as $row) {
        // [S5] Context-aware output encoding at the HTML document boundary.
        // htmlspecialchars() converts the five HTML-special characters to their entity
        // equivalents: < → &lt;  > → &gt;  " → &quot;  ' → &#039;  & → &amp;
        // The browser HTML5 tokeniser receives character entities, not markup tokens,
        // and renders them as literal text — preventing any script execution state.
        echo "<div>Result found for keyword: "
            . htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8') . "<br>";
        echo "Patient: "
            . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8')
            . " | History: "
            . htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8')
            . "</div><hr>";
    }
} else {
    // [S6] XSS protection applied in the error branch as well
    echo "No records found for: " . htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');
}
?>
