<?php
/*
SessionI, Improved Session for PHP
@TODO: comments :(
*/
require_once __DIR__ . '/includes/config.php';

class sessioni {
	private $ip; // current client ip;
	public $sessioniId; // current client sessioniId
	public $sessioniKey; // current client sessioniKey
	private $db; // PDO database
	private $https; // boolean https
	private $path; // current execution path
	private $domain; // current domain
	
	/**
	* constructor, fills the variabeles and
	*/
	public function __construct() {
		if (isset($_SERVER["REMOTE_ADDR"])) { // set ip var
			$ip = $_SERVER["REMOTE_ADDR"];
		} else if(isset($_SERVER["HTTP_X_FORWARDED_FOR"])) {
			$ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
		} else if(isset($_SERVER["HTTP_CLIENT_IP"])) {
			$ip = $_SERVER["HTTP_CLIENT_IP"] ;
		} 
		$this->ip = $this->ipToIPV46($ip);
		
		$this->db = $this->dbConnect(); // set db connection
		$this->dropExpiredSessionis();
		
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
			}
		}
		setcookie('sessioniKey', $this->getSessioniKey(), time()+60*60*24*365); // always reinitialize the session, to reset the cookie timer
		
		$this->dropExpiredVars(); // drop expired vars of any sessioni
		$this->loadProperties(); // set the session properties (session id, key & datetime)
		$this->loadVars(); // set the global sessioni[][] var
	}
	
	/**
	* destructor, closes pdo
	*/
	public function __destruct() {
		$this->db = null; // close PDO
		unset($GLOBALS["sessioni"]);
	}
	
	private function dbConnect() {
		try {
			$db = new PDO('mysql:host=' . DB_HOST .';dbname=' . DB_NAME . ';charset=utf8', DB_USER, DB_PASS);
			$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			$db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
		} catch (Exception $e) {
			showDbError('connect', $e->getMessage());
		}
		return $db;
	}
	
	public function loadProperties($ip = null) {
		if($ip = null) {
			$ip = $this->ip;
		}
		if(!$this->hasSessioni()) { // if user hasn't got a sessioni, give one
			$this->sessioniId = $this->createSessioni();
		}
		$this->resetSessioniExpiration();
		$this->sessioniId = $this->getSessioniId($ip);
		$this->sessioniKey = $this->getSessioniKey($ip);
	}
	
	public function hasSessioni($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('SELECT `id` FROM `'.TBL_NAMEKEYS.'` WHERE ip = ? OR `key` = ?');
		$stmt->execute(array($ip, $ip));
		
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
		$stmt = $this->db->prepare('SELECT `key` from `'.TBL_NAMEKEYS.'` WHERE ip = ?');
		$stmt->execute(array($ip));
		
		return $stmt->fetchColumn();
	}
	
	public function getSessioniId($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('SELECT `id` from `'.TBL_NAMEKEYS.'` WHERE ip = ?');
		$stmt->execute(array($ip));
		
		return (int)$stmt->fetchColumn();
	}
	
	public function createSessioni($ip = null, $sessioniId = null, $expire = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		if($expire == null) {
			$expire = DEFAULTKEYEXPIRETIME;
		}
		$this->dropSessioni($ip);
		if($sessioniId == null) {
			do {
				$sessioniId = $this->generateRandomString();
			} while($this->hasSessioni($sessioniId));
		}
		$date = new DateTime();
		$date->add(new DateInterval($expire));
		$stmt = $this->db->prepare('INSERT INTO `'.TBL_NAMEKEYS.'` (`key`, ip, expires) VALUES (?,?, ?)');
		$stmt->execute(array($sessioniId, $ip, $date->format('Y-m-d H:i:s')));
		setcookie('sessioniKey', $this->getSessioniKey($ip), time()+60*60*24*7);
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
	
	public function dropExpiredSessionis() {
		$date = new Datetime();
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEKEYS.'` WHERE expires < ?');
		$stmt->execute(array($date->format('Y-m-d H:i;s')));
	}
	
	public function resetSessioniExpiration($sessioniKey = null) {
		if($sessioniKey == null) {
			$sessioniKey = $this->sessioniKey;
		}
		$date = new DateTime();
		$date->add(new DateInterval(DEFAULTKEYEXPIRETIME));
		
		$stmt = $this->db->prepare('UPDATE `'.TBL_NAMEKEYS.'` SET expires = ? WHERE `key` = ?');
		$stmt->execute(array($date->format('Y-m-d H:i;s'), $sessioniKey));
	}
	
	public function getSessioniExpiration($sessioniKey = null) {
		if($sessioniKey == null) {
			$sessioniKey = $this->sessioniKey;
		}
		$stmt = $this->db->prepare('SELECT expires FROM `'.TBL_NAMEKEYS.'` WHERE `key` = ?');
		$stmt->execute(array($sessioniKey));
		
		
		return $stmt->fetchColumn();
	}
	
	public function setVar($var, $value, $expire = null, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		if($expire == null) {
			$expire = DEFAULTVAREXPIRETIME;
		}
		if($secure == null) {
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}
		if($domain == null) {
			$domain = '';
		}
		
		if($this->getVar($var) !=  null && !OVERWRITEVARS) {
			return false;
		}
		else {
			$this->dropVar($var);
		}
		
		if($path == null) {
			$stmt = $this->db->prepare('INSERT INTO `'.TBL_NAMEVARS.'` (`sessioniId`, `varName`, `varValue`, `expires`, `domain`, `secure`) VALUES (?, ?, ?, ?, ?, ?)');
			$date = new DateTime();
			$date->add(new DateInterval($expire));

			$stmt->execute(array($sessioniId, $var, $value, $date->format('Y-m-d H:i:s'), $domain, $secure));
		}
		else {
			$stmt = $this->db->prepare('INSERT INTO `'.TBL_NAMEVARS.'` (`sessioniId`, `varName`, `varValue`, `expires`, `domain`, `path`, `secure`) VALUES (?, ?, ?, ?, ?, ?, ?)');
			$date = new DateTime();
			$date->add(new DateInterval($expire));

			$stmt->execute(array($sessioniId, $var, $value, $date->format('Y-m-d H:i:s'), $domain, $path, $secure));
		}
		if($stmt->rowCount() <= 0) {
			return false;
		}
		if(!isset($GLOBALS[$var])) {
			$GLOBALS[$var] = $value;
		}
		return true;
	}
	
	public function dropExpiredVars($sessioniId = null) {
		$date = new Datetime();
		if($sessioniId == null) {
			$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE expires < ?');
			$stmt->execute(array($date->format('Y-m-d H:i;s')));
		}
		else {
			$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND expires < ?');
			$stmt->execute(array($sessioniId, $date->format('Y-m-d H:i;s')));
		}
	}
	
	public function dropVar($var, $sessioniId = null) {
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ?');
		$date = new Datetime();
		$stmt->execute(array($sessioniId, $var, $date->format('Y-m-d H:i;s')));
		if(isset($GLOBALS[$var])) {
			unset($GLOBALS[$var]);
		}
	}
	
	public function getVar($var, $domain = null, $path = null, $sessioniId = null) {
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		$secure = $this->https;
		if($domain == null) {
			$domain = $this->domain;
		}

		if($path == null) {
			$stmt = $this->db->prepare('SELECT `varValue` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $secure, $this->path, $domain));
		}
		else {
			$stmt = $this->db->prepare('SELECT `varValue` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $secure, $path, $domain));
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
			$domain = $this->domain;
		}
		
		if($path == null) {
			$stmt = $this->db->prepare('SELECT `expires` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $secure, $this->path, $domain));
		}
		else {
			$stmt = $this->db->prepare('SELECT `expires` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $var, $secure, $path, $domain));
		}
		if($stmt->rowCount() <= 0) {
			$date = new Datetime();
			$date->sub(new DateInterval("P7D"));
			return  $date->format('Y-m-d H:i:s');
		}
		return $stmt->fetchColumn();
	}
	
	private function loadVars($sessioniId = null) {
		if(isset($GLOBALS["_SESSIONI"])) {
			unset($GLOBALS["_SESSIONI"]);
		}
	        global $_SESSIONI;
		$_SESSIONI = array();

		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}

		$secure = $this->https;
		$domain = $this->domain;
		
		// @TODO: LOADALLSESSIONI
		if(LOADALLSESSIONI && $sessioniId == $this->sessioniId) {
			$stmt = $this->db->prepare('SELECT * FROM `'.TBL_NAMEVARS.'` WHERE (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?) ORDER BY sessioniId');
			$stmt->execute(array($secure, $this->path, $domain));
			
			$curSessioniId = 0;
			while ($collection = $stmt->fetch(PDO::FETCH_ASSOC)) {
				echo "ok";
				if($curSessioniId != $collection["sessioniId"]) {
					$curSessioniId = $collection["sessioniId"];
				}
				
				$_SESSIONI[$curSessioniId][$collection["varName"]] = $collection["varValue"];
			}
		}
		else {
			$stmt = $this->db->prepare('SELECT * FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $secure, $this->path, $domain));

			while ($collection = $stmt->fetch(PDO::FETCH_ASSOC)) {
				$_SESSIONI[$collection["varName"]] = $collection["varValue"];
			}
		}
		
		return $_SESSIONI;
	}
	
	
	/**
	* generates a random string (with a given length)
	* <param name="length">Length of the output string</param>
	* <return>Random string</return>
	*/
	private function generateRandomString($length = null) {
		if($length == null) {
			$length = KEYLENGTH;
		}
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
	
	/**
	* converts any ip address to ipv4/ipv6.
	*/
	private function ipToIPV46($addr) {
		$v4mapped_prefix_hex = '00000000000000000000ffff';
		$v4mapped_prefix_bin = pack("H*", $v4mapped_prefix_hex);

		// Or more readable when using PHP >= 5.4
		# $v4mapped_prefix_bin = hex2bin($v4mapped_prefix_hex); 

		// Parse
		$addr = $_SERVER['REMOTE_ADDR'];
		$addr_bin = inet_pton($addr);
		if( $addr_bin === FALSE ) {
		  // Unparsable? How did they connect?!?
		  die('Invalid IP address');
		}

		// Check prefix
		if( substr($addr_bin, 0, strlen($v4mapped_prefix_bin)) == $v4mapped_prefix_bin) {
		  // Strip prefix
		  $addr_bin = substr($addr_bin, strlen($v4mapped_prefix_bin));
		}

		// Convert back to printable address in canonical form
		$addr = inet_ntop($addr_bin);
		return $addr;
	}
}

?>









