<?php

/**
 * OAuth storage handler built on PDO
 * @todo Add table creation script
 * @todo Database fallback?
 * @author Ben Tadiar <ben@handcraftedbyben.co.uk>
 * @link https://github.com/benthedesigner/dropbox
 * @package Dropbox\Oauth
 * @subpackage Storage
 */
namespace Dropbox\OAuth\Storage;

class Manual extends Session
{

    protected $token = null;
    protected $userID = null;
    protected $encrypter = null;

    /**
     * Construct the parent object and
     * set the authenticated user ID
     * @param \Dropbox\OAuth\Storage\Encrypter $encrypter
     * @param int $userID
     * @throws \Dropbox\Exception
     */
    public function __construct(Encrypter $encrypter = null, $token = null)
    {

        $this->encrypter = $encrypter;

        if($token) {
            $this->token = (is_object($token)) ? $token : $this->decrypt($token);
            $this->userID = $this->token->uid;
        }

        // Construct the parent object so we can access the SESSION
        // instead of querying the database on every request
        parent::__construct($this->encrypter, $this->userID);

    }
            
    /**
     * Get an OAuth token from the database or session (see below)
     * Request tokens are stored in the session, access tokens in the database
     * Once a token is retrieved it will be stored in the users session
     * for subsequent requests to reduce overheads
     * @param string $type Token type to retrieve
     * @return array|bool
     */
    public function get($type, $token = null)
    {
        $token = isset($this->token) ? $this->token : $token;
        if ($type != 'request_token' && $type != 'access_token') {
            throw new \Dropbox\Exception("Expected a type of either 'request_token' or 'access_token', got '$type'");
        } elseif ($type == 'request_token') {
            return parent::get($type);
        } elseif ($_token = parent::get($type)) {
            return $_token;
        } else { 
            return $token;
        }
    }
    
    /**
     * Set an OAuth token in the database or session (see below)
     * Request tokens are stored in the session, access tokens in the database
     * @param \stdClass Token object to set
     * @param string $type Token type
     * @return \stdClass containing token, and userId
     */
    public function set($token, $type)
    {
        if ($type != 'request_token' && $type != 'access_token') {
            $message = "Expected a type of either 'request_token' or 'access_token', got '$type'";
            throw new \Dropbox\Exception($message);
        } elseif ($type == 'request_token') {
            parent::set($token, $type);
        } else {
            $this->token = $token;
            $_SESSION[$this->namespace][$this->userID][$type] = $token;
            return $this->encrypt($this->token);
        }
    }
    
    /**
     * Delete access token for the current user ID from the database
     * @todo Add error checking
     * @return bool
     */
    public function delete(){}

    public function token(){
        return $this->encrypt($this->get('access_token'));
    }

    // public function encrypt($object){
    //     return $this->encrypt($object);
    // }

    public function decrypt($token){
        if(is_object($token)) return $token;
        // Decrypt the token if there is an Encrypter instance
        if ($this->encrypter instanceof Encrypter) {
            $token = $this->encrypter->decrypt($token);
        }
        
        // Return the unserialized token
        return @unserialize($token);
    }
    
}
