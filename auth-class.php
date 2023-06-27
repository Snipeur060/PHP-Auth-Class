<?php
/* * * * * * * * * * * * * * * *
 *      Author : Snipeur060    *
 *        Name : Auth.php      *
 *     Version : 1.0.0         *
 *      Status : Stable        *
 * * * * * * * * * * * * * * * */

class Auth
{
    /* Class Auth
     * ----------
     * This class handles the authentication of users.
     * It can register new users, log them in and out,
     * and check if they are logged in.
     * ---------
     * Functions:
     * @register: Registers a new user
     * @login: Logs a user in
     * @logout: Logs a user out
     * @check: Checks if a user is logged in
     * ---------
     * Parameters:
     * @db: The database connection
     * ---------
     * Variables:
     * @db: The database connection
     * ----------
     * Sql table:
     * users: id, username, password,rank
     * id -> int(11), auto increment, primary key
     * username -> varchar(500)
     * password -> varchar(500)
     * rank -> int(11)
     * ----------
     * */
    private $db; // database connection

    public function __construct($db)
    {
        $this->db = $db;
    }

    public function register($username, $password): bool
    {
        /* Function register
         * -----------------
         * This function registers a new user in the database.
         * It returns true if the registration was successful,
         * or false if it failed.
         * -----------------
         * Parameters:
         * @username: The username of the new user
         * @password: The password of the new user
         * -----------------
         * Return:
         * @true: The registration was successful
         * @false: The registration failed
         * */
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
        /* Function login
         * --------------
         * This function logs a user in.
         * It returns true if the login was successful,
         * or false if it failed.
         * --------------
         * Parameters:
         * @username: The username of the user
         * @password: The password of the user
         * --------------
         * Return:
         * @true: The login was successful
         * @false: The login failed
         * */
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
                $_SESSION['user_id'] = $user['id'];
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
        /* Function check
         * --------------
         * This function checks if a user is logged in.
         * It returns true if the user is logged in,
         * or false if they are not.
         * --------------
         * Parameters:
         * None
         * --------------
         * Return:
         * @true: The user is logged in
         * @false: The user is not logged in
         * --------------
         * */
        // Check if the user is logged in by checking the session variable
        if (isset($_SESSION['user_id'])) {
            return true;
        } else {
            return false;
        }
    }

    public function logout()
    {
        /* Function logout
         * ---------------
         * This function logs a user out.
         * ---------------
         * Parameters:
         * None
         * ---------------
         * Return:
         * None
         * ---------------
         * */
        // Unset the session variable and destroy the session
        unset($_SESSION['user_id']);
        session_destroy();
    }
    public function getUsername()
    {
        /* Function getUsername
         * ---------------------
         * This function returns the username of the logged in user.
         * If the user is not logged in, it returns null.
         * ---------------------
         * Parameters:
         * None
         * ---------------------
         * Return:
         * @username: The username of the logged in user
         * @null: The user is not logged in
         * ---------------------
         *  */
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
    public function getRank()
    {
        /* Function getRank
         * ----------------
         * This function returns the rank of the logged in user.
         * If the user is not logged in, it returns null.
         * ----------------
         * Parameters:
         * None
         * ----------------
         * Return:
         * @rank: The rank of the logged in user
         * @null: The user is not logged in
         * ---------------
         * */
        // Check if the user is logged in by checking the session variable
        if (isset($_SESSION['user_id'])) {
            // Get the user from the database
            $query = "SELECT rank FROM users WHERE id = ?";
            $stmt  = $this->db->prepare($query);
            $stmt->bind_param("i", $_SESSION['user_id']);
            $stmt->execute();
            $result    = $stmt->get_result();
            $userArray = $result->fetch_assoc();

            if ($userArray) {
                // Return the rank
                return $userArray['rank'];
            }
        }

        // User is not logged in or not found in database
        return null;
    }
}
?>
