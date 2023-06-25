<?php
if (!empty($_GET['sqlInjectionParams']) && !empty($_GET['sqlInjectionPatterns'])) {
    $sqlInjectionParams = urldecode($_GET['sqlInjectionParams']);
    $sqlInjectionPatterns = urldecode($_GET['sqlInjectionPatterns']);

    parse_str($sqlInjectionParams, $decodedParams);
    parse_str($sqlInjectionPatterns, $decodedPatterns);
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Result</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>SQL Injection Result</h1>
        <?php if (!empty($decodedParams) && !empty($decodedPatterns)): ?>
            <div class="alert alert-danger" role="alert">
                <strong>Potential SQL injection detected!</strong>
                <br>
                <p>The following parameter(s) may be vulnerable:</p>
                <?php foreach ($decodedParams as $name => $value): ?>
                    <p><strong><?php echo htmlspecialchars($name); ?>:</strong> <?php echo htmlspecialchars($value); ?></p>
                <?php endforeach; ?>
                <br>
                <p>The corresponding patterns:</p>
                <?php foreach ($decodedPatterns as $name => $value): ?>
                    <p><strong><?php echo htmlspecialchars($name); ?>:</strong> <?php echo htmlspecialchars($value); ?></p>
                <?php endforeach; ?>
            </div>
            <a href="javascript:history.back()" class="btn btn-primary">Back</a>
        <?php else: ?>
            <div class="alert alert-info" role="alert">
                No SQL injection details found.
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
