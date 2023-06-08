<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Result</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>SQL Injection Result</h1>
        <?php if (!empty($_GET)): ?>
            <div class="alert alert-danger" role="alert">
                <strong>Potential SQL injection detected!</strong>
                <br>
                <p>The following parameter(s) may be vulnerable:</p>
                <ul>
                    <?php foreach ($_GET as $name => $value): ?>
                        <li><strong><?php echo $name; ?>:</strong> <?php echo $value; ?></li>
                    <?php endforeach; ?>
                </ul>
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
