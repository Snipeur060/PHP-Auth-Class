<?php

class Auth
{
    private $db; // database connection

    public function __construct($db)
    {
        $this->db = $db;
    }

    public function register($username, $password)
    {
        // Hash the password using the password_hash function
        $password = password_hash($password, PASSWORD_BCRYPT);

        // Insert the new user into the database
        $query = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
    }

    public function login($username, $password)
    {
        // Get the user from the database
        $query = "SELECT * FROM users WHERE username = ?";
        $stmt = $this->db->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        // If the user was found, check the password
        if ($user) {
            if (password_verify($password, $user['password'])) {
                // Password is correct, log the user in
                return true;
            } 
            else {
                // Password is incorrect
                return false;
            }
        } 
        else {
            // User was not found
            return false;
        }
    }
    
    public function check(){
        // Check if the user is logged in by checking the session variable
        if (isset($_SESSION['user_id'])) {
            return true;
        } 
        else {
            return false;
        }
    }
    
    public function logout(){
        // Unset the session variable and destroy the session
        unset($_SESSION['user_id']);
        session_destroy();
    }
}

?>
