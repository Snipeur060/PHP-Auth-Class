<?php
session_start();
$db = new mysqli("localhost", "user", "password", "database");
$auth = new Auth($db);

?>
