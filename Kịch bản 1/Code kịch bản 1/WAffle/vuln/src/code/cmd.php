<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>os command</title>
</head>

<body>
    <ul>
        <li>
            <a href="?input=nhom3test">nhom3test</a>
        </li>
        <li>
            <a href="?input=aaaaaa">aaaaaa</a>
        </li>
        <li>
            <a href="?input=;ls">ls</a>
        </li>
         <li>
            <a href="?input=;cat /etc/passwd">cat /etc/passwd</a>
        </li>
    </ul>
    <hr>
    <?php
    if (isset($_GET['input'])) {
        exec("echo " . $_GET['input'], $output);
        echo "<pre>";
        print_r($output);
        echo "</pre>";
    }
    ?>
</body>

</html>
