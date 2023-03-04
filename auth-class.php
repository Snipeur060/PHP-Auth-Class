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
        // Check if the username already exists
        $query = "SELECT id FROM users WHERE username = ?";
        $stmt  = $this->db->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result       = $stmt->get_result();
        $existingUser = $result->fetch_assoc();
        
        if ($existingUser){
            // Username already exists
            return false;
        }
        
        // Hash the password using the password_hash function
        $password = password_hash($password, PASSWORD_ARGON2ID);
        
        // Insert the new user into the database
        $query = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt  = $this->db->prepare($query);
        $stmt->bind_param("ss", $username, $password);
        $success = $stmt->execute();
        
        if ($success) {
            // Registration successful
            return true;
        } else {
            // Registration failed
            return false;
        }
    }
    
    public function login($username, $password)
    {
        // Get the user from the database
        $query = "SELECT * FROM users WHERE username = ?";
        $stmt  = $this->db->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user   = $result->fetch_assoc();
        
        // If the user was found, check the password
        if ($user) {
            if (password_verify($password, $user['password']) && password_needs_rehash($user['password'], PASSWORD_ARGON2ID)) {
                $newHash = password_hash($password, PASSWORD_ARGON2ID);
                // Mettre à jour le mot de passe haché dans la base de données
                $query   = "UPDATE users SET password = ? WHERE username = ?";
                $stmt    = $this->db->prepare($query);
                $stmt->bind_param("ss", $newHash, $username);
                $stmt->execute();
            } elseif (password_verify($password, $user['password'])) {
                // Le mot de passe est correct et ne nécessite pas de ré-hachage
                return true;
            } else {
                // Le mot de passe est incorrect
                return false;
            }
        } else {
            // User was not found
            return false;
        }
    }
    
    public function check()
    {
        // Check if the user is logged in by checking the session variable
        if (isset($_SESSION['user_id'])) {
            return true;
        } else {
            return false;
        }
    }
    
    public function logout()
    {
        // Unset the session variable and destroy the session
        unset($_SESSION['user_id']);
        session_destroy();
    }
	public function getUsername()
{
    // Check if the user is logged in by checking the session variable
    if (isset($_SESSION['user_id'])) {
        // Get the user from the database
        $query = "SELECT username FROM users WHERE id = ?";
        $stmt  = $this->db->prepare($query);
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $result    = $stmt->get_result();
        $userArray = $result->fetch_assoc();
        
        if ($userArray) {
            // Return the username
            return $userArray['username'];
        }
    }

    // User is not logged in or not found in database
    return null;
}
}

?>
