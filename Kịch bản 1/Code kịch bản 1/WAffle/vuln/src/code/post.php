<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>post</title>
</head>

<body>
    <form method="post">
        <input type="text" name="input" size="50" id="input"><br>
        <input type="button" onclick="document.getElementById('input').value = '<script>alert(1)</script>';" value="attack"><input type="submit" value="submit">
    </form>
    <hr>
    output: <?php
            $input = $_POST["input"];
            print $input;
            ?>
</body>

</html>
