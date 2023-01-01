<?php 
require("example-config.php");
$auth->register("username", "mypassword");

if ($auth->login("username", "mypassword")) {
    echo "Logged in!";
} else {
    echo "Invalid username or password.";
}
?>
