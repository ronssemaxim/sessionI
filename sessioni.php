<?php
/*
SessionI, Improved Session for PHP
functions:
set
*/
require_once __DIR__ . '/includes/config.php';
// @TODO sessionkey expiration

class sessioni {
	private $ip;
	public $sessioniId;
	public $sessioniKey;
	private $db;
	private $https;
	private $path;
	private $domain;
	
	/**
	* constructor, fills the variabeles and
	*/
	public function __construct() {
		if (isset($_SERVER["REMOTE_ADDR"])) { // set ip var
			$this->ip = $_SERVER["REMOTE_ADDR"];
		} else if(isset($_SERVER["HTTP_X_FORWARDED_FOR"])) {
			$this->ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
		} else if(isset($_SERVER["HTTP_CLIENT_IP"])) {
			$this->ip = $_SERVER["HTTP_CLIENT_IP"] ;
		} 
		// @TODO:  ipv6
		
		$this->db = $this->dbConnect();
		if(!$this->hasSessioni()) { // if user hasn't got a sessioni, give one
			$this->sessioniId = $this->createSessioni();
		}
		
		$this->https = $this->isHTTPS();
		$this->path = realpath(dirname($_SERVER['PHP_SELF']));
		$this->domain = $_SERVER["SERVER_NAME"];
		
		
		$cookieKey = isset($_COOKIE['sessioniKey']) ? $_COOKIE['sessioniKey'] : ''; // get the client's cookie
		
		if($cookieKey != $this->getSessioniKey()) { // if the key from the db doesn't match the cookie's key
			if(IPMATCHKEY) { // if ip must match key, create new session
				$this->dropSessioni();
				$this->createSessioni();
			}
			else {
				if(COOKIEPRIORITY) { // if cookie has priority, create session based on cookie
					$this->createSessioni(null, $cookieKey);
				}
				else { // else create session based on db key
					setcookie('sessioniKey', $this->getSessioniKey(), time()+60*60*24*365);
				}
			}
		}
		setcookie('sessioniKey', $this->getSessioniKey(), time()+60*60*24*365); // always reinitialize the session, to reset the cookie timer
		$this->loadVars(); // set the session vars (session id, key & datetime)
	}
	
	private function dbConnect() {
		$db;
		try {
			$db = new PDO('mysql:host=' . DB_HOST .';dbname=' . DB_NAME . ';charset=utf8', DB_USER, DB_PASS);
			$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			$db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
		} catch (Exception $e) {
			showDbError('connect', $e->getMessage());
		}
		return $db;
	}
	
	public function loadVars($ip = null) {
		if($ip = null) {
			$ip = $this->ip;
		}
		$this->sessioniId = $this->getSessioniId($ip);
		$this->sessioniKey = $this->getSessioniKey($ip);
		$this->datetime = new Datetime();
	}
	
	public function hasSessioni($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$stmt = $this->db->prepare('SELECT `id` FROM `'.TBL_NAMEKEYS.'` WHERE ip = ?');
		$stmt->execute(array($ip));
		
		$value = $stmt->fetchColumn();
		if(empty($value)) {
			return false;
		}
		return true;
	}
	
	public function getSessioniKey($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$stmt = $this->db->prepare('SELECT `key` from `'.TBL_NAMEKEYS.'` WHERE ip = ?');
		$stmt->execute(array($ip));
		
		return $stmt->fetchColumn();
	}
	
	public function getSessioniId($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$stmt = $this->db->prepare('SELECT `id` from `'.TBL_NAMEKEYS.'` WHERE ip = ?');
		$stmt->execute(array($ip));
		
		return (int)$stmt->fetchColumn();
	}
	
	public function createSessioni($ip = null, $sessioniId = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$this->dropSessioni($ip);
		if($sessioniId == null) {
			$sessioniId = $this->generateRandomString();
		}
		$stmt = $this->db->prepare('INSERT INTO `sessioniId` (`key`, ip) VALUES (?,?)');
		$stmt->execute(array($sessioniId, $ip));
		setcookie('sessioniKey', $this->getSessioniKey($ip), time()+60*60*24*7);
		// @TODO: define key length
		return $this->db->lastInsertId();
	}
	
	public function dropSessioni($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId IN (SELECT id from `'.TBL_NAMEKEYS.'` WHERE ip = ?)');
		$stmt->execute(array($ip));
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEKEYS.'` WHERE ip = ?');
		$stmt->execute(array($ip));
		if($ip == $this->ip) {
			setcookie('sessioniKey', '', time()-60*60*24*7);
		}
	}
	
	public function setVar($var, $value, $expire = null, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if($sessioniId == null) {
			if(!isset($this->sessioniId)) {
				throw new Exception("setVar: Set sessionId first, or pass it");
			}
			$sessioniId = $this->sessioniId;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		if($expire == null) {
			$expire = DEFAULTEXPIRETIME;
		}
		if($secure == null) {
			$secure = DEFAULTSECURE;
		}
		if($domain == null) {
			$domain == '';
		}
		
		$this->dropExpiredVar($var);
		if($this->getVar($var) !=  null && !OVERWRITEVARS) {
			return false;
		}
		else {
			$this->dropVar($var);
		}
		
		if($path == null) {
			$stmt = $this->db->prepare('INSERT INTO `vars` (`sessioniId`, `varName`, `varValue`, `expires`, `domain`, `secure`) VALUES (?, ?, ?, ?, ?, ?)');
			$date = new DateTime();
			$date->add(new DateInterval($expire));

			$stmt->execute(array($sessioniId, $var, $value, $date->format('Y-m-d H:i:s'), $domain, $secure));
		}
		else {
			$stmt = $this->db->prepare('INSERT INTO `vars` (`sessioniId`, `varName`, `varValue`, `expires`, `domain`, `path`, `secure`) VALUES (?, ?, ?, ?, ?, ?, ?)');
			$date = new DateTime();
			$date->add(new DateInterval($expire));

			$stmt->execute(array($sessioniId, $var, $value, $date->format('Y-m-d H:i:s'), $domain, $path, $secure));
		}
		if($stmt->rowCount() <= 0) {
			return false;
		}
		return true;
	}
	
	public function dropExpiredVar($var, $sessioniId = null) {
		if($sessioniId == null) {
			if(!isset($this->sessioniId)) {
				throw new Exception("dropExpiredVar: Set sessionId first, or pass it");
			}
			$sessioniId = $this->sessioniId;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND expires < ?');
		$stmt->execute(array($sessioniId, $var, $this->datetime->format('Y-m-d H:i;s')));
	}
	
	public function dropVar($var, $sessioniId = null) {
		if($sessioniId == null) {
			if(!isset($this->sessioniId)) {
				throw new Exception("dropVar: Set sessionId first, or pass it");
			}
			$sessioniId = $this->sessioniId;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND expires >= ?');
		$stmt->execute(array($sessioniId, $var, $this->datetime->format('Y-m-d H:i;s')));
	}
	
	public function getVar($var, $domain = null, $path = null, $sessioniId = null) {
		if($sessioniId == null) {
			if(!isset($this->sessioniId)) {
				throw new Exception("getVar: Set sessionId first, or pass it");
			}
			$sessioniId = $this->sessioniId;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$secure = $this->https;
		if($domain == null) {
			$domain == $this->domain;
		}
		
		$date = new DateTime();
		$expire = $date->format('Y-m-d H:i;s');
		if($path == null) {
			$stmt = $this->db->prepare('SELECT `varValue` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND expires >= ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $expire, $secure, $this->path, $domain));
		}
		else {
			$stmt = $this->db->prepare('SELECT `varValue` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND expires >= ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $expire, $secure, $path, $domain));
		}
		if($stmt->rowCount() <= 0) {
			return null;
		}
		return $stmt->fetchColumn();
	}
	
	public function getVarExpiration($var, $domain = null, $path = null, $sessioniId = null) {
		if($sessioniId == null) {
			if(!isset($this->sessioniId)) {
				throw new Exception("getVarExpiration: Set sessionId first, or pass it");
			}
			$sessioniId = $this->sessioniId;
		}
		if(!isset($this->db)) {
			throw new Exception("Database not set");
		}
		$secure = $this->https;
		if($domain == null) {
			$domain == $this->domain;
		}
		
		$date = new DateTime();
		$expire = $date->format('Y-m-d H:i;s');
		if($path == null) {
			$stmt = $this->db->prepare('SELECT `expires` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND expires >= ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $expire, $secure, $this->path, $domain));
		}
		else {
			$stmt = $this->db->prepare('SELECT `expires` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND expires >= ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $expire, $secure, $path, $domain));
		}
		if($stmt->rowCount() <= 0) {
			$date->sub(new DateInterval("P7D"));
			return  $date->format('Y-m-d H:i:s');
		}
		return $stmt->fetchColumn();
	}
	
	
	/**
	* generates a random string (with a given length)
	* <param name="length">Length of the output string</param>
	* <return>Random string</return>
	*/
	private function generateRandomString($length = 32) {
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, strlen($characters) - 1)];
		}
		return $randomString;
	}

	/**
	* reterns wether or not the current request was made through https
	* <return>True when https</return>
	*/
	private static function isHTTPS() {
		return isset($_SERVER['HTTPS'] )  && $_SERVER['HTTPS'] != 'off';
	}
}

?>