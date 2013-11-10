<?php
/*
SessionI, Improved Session for PHP
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
		
		if(!$this->hasSessioni($this->ip)) {
			$this->createSessioni();
		}
		if($cookieKey != $this->getSessioniKey()) { // if the key from the db doesn't match the cookie's key
			if(IPMATCHKEY) { // if ip must match key, create new sessioni
				$this->dropSessioni();
				$this->createSessioni();
			}
			else {
				if(COOKIEPRIORITY) { // if cookie has priority, create sessioni based on cookie
					$this->createSessioni(null, $cookieKey);
				}
			}
		}
		setcookie('sessioniKey', $this->getSessioniKey(), time()+60*60*24*365); // always reinitialize the sessioni, to reset the cookie timer
		
		$this->dropExpiredVars(); // drop expired vars of any sessioni
		$this->loadProperties(); // set the sessioni properties (sessioni id, key & datetime)
		$this->loadVars(); // set the global sessioni[][] var
	}
	
	/**
	* destructor, closes pdo
	*/
	public function __destruct() {
		$this->db = null; // close PDO
		unset($GLOBALS["sessioni"]);
	}
	
	/**
	* connect to db & return pdo object
	* <return>PDO connection</return>
	*/
	private function dbConnect() {
		try {
			$db = new PDO('mysql:host=' . DB_HOST .';dbname=' . DB_NAME . ';charset=utf8', DB_USER, DB_PASS);
			$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // prevent sql injection ;)
			$db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
		} catch (Exception $e) {
			throw new Exception("Unable to connect to DB!");
		}
		return $db;
	}
	
	/**
	* set the class's properties for the choosen ip
	* <param name="ip">Optional. The ip to load the properties with.</param>
	*/
	public function loadProperties($ip = null) {
		if($ip = null) {
			$ip = $this->ip;
		}
		if(!$this->hasSessioni($ip)) { // if user hasn't got a sessioni, give one
			$this->sessioniId = $this->createSessioni($ip);
		}
		$this->sessioniId = $this->getSessioniId($ip);
		$this->sessioniKey = $this->getSessioniKey($ip);
		$this->resetSessioniExpiration(); // reset sessioni expiration each time it is accessed
	}
	
	/**
	* Checks for an ip/key if it has a sessioni linked to it.
	* <param name="ip">Optional. The ip/key to check.</param>
	* <return>Returns true if the choosen ip/key has a sessioni.</return>
	*/
	public function hasSessioni($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('SELECT `id` FROM `'.TBL_NAMEKEYS.'` WHERE `key` = ? OR ip = ?');
		$stmt->execute(array($ip, $ip));
		
		if($stmt->rowCount() <= 0) {
			return false;
		}
		return true;
	}
	
	/**
	* get the sessioni key for the choosen ip/key
	* <param name="ip">Optional. The ip/key to get the sessioni key from.</param>
	* <return>The found sessioniKey. Null if not found.</return>
	*/
	public function getSessioniKey($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('SELECT `key` from `'.TBL_NAMEKEYS.'` WHERE `key` = ? OR ip = ?');
		$stmt->execute(array($ip, $ip));
		if($stmt->rowCount() <= 0) {
			return null;
		}
		return $stmt->fetchColumn();
	}
	
	/**
	* get the sessioni id for the choosen ip/key
	* <param name="ip">Optional. The ip/key to get the sessioniId from.</param>
	* <return>The found sessioniId. Null if not found.</return>
	*/
	public function getSessioniId($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('SELECT `id` from `'.TBL_NAMEKEYS.'` WHERE `key` = ? OR ip = ?');
		$stmt->execute(array($ip, $ip));
		if($stmt->rowCount() <= 0) {
			return null;
		}
		return (int)$stmt->fetchColumn();
	}
	
	/**
	* get the sessioni expiration datetime for the choosen ip/key
	* <param name="ip">Optional. The ip/key to get the sessioni expiration from.</param>
	* <return>The expiration time. Null if not found.</return>
	*/
	public function getSessioniExpiration($ip = null) {
		if($ip == null) {
			$ip = $this->sessioniKey;
		}
		$stmt = $this->db->prepare('SELECT expires FROM `'.TBL_NAMEKEYS.'` WHERE `key` = ? OR ip = ?');
		$stmt->execute(array($ip, $ip));
		
		if($stmt->rowCount() <= 0) {
			return null;
		}
		
		return $stmt->fetchColumn();
	}
	
	/**
	* creates a sessioni for a ip, with a desired sessioniKey and expiration
	* <param name="ip">Optional. Not set: current client ip.</param>
	* <param name="sessioniKey">Optional. Not set: random. Set: choosen key, or random if taken.</param>
	* <param name="expire">Optional. Not set: current datetime + DEFAULTKEYEXPIRETIME.Set: in DateInterval</param>
	* <return>The generated sessioniId.</return>
	*/
	public function createSessioni($ip = null, $sessioniKey = null, $expire = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		
		$this->dropSessioni($ip); // drop the sessioni first
		
		if($expire == null) {
			$expire = DEFAULTKEYEXPIRETIME;
		}
		
		if($sessioniKey == null) { // make sessioniKey
			$sessioniKey = $this->generateRandomString();
		}
		while($this->hasSessioni($sessioniKey)) { // while key taken, generate new one.
			$sessioniKey = $this->generateRandomString();
		}
		
		$date = new DateTime();
		$date->add(new DateInterval($expire));
		$stmt = $this->db->prepare('INSERT INTO `'.TBL_NAMEKEYS.'` (`key`, ip, expires) VALUES (?,?, ?)');
		$stmt->execute(array($sessioniKey, $ip, $date->format('Y-m-d H:i:s')));
		
		setcookie('sessioniKey', $this->getSessioniKey($ip), time()+60*60*24*7);
		
		return $this->db->lastInsertId();
	}
	
	/**
	* Drop the sessioni of the desired ip
	* <param name="ip">Optional. The ip/key to drop the sessioni for.</param>
	*/
	public function dropSessioni($ip = null) {
		if($ip == null) {
			$ip = $this->ip;
		}
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEKEYS.'` WHERE `key` = ? OR ip = ?'); // foreign keys are in cascade, so no need to drop the vars
		$stmt->execute(array($ip, $ip));
		if($ip == $this->ip) {
			setcookie('sessioniKey', '', time()-60*60*24*7);
		}
	}
	
	/**
	* drops expired sessionis
	*/
	public function dropExpiredSessionis() {
		$date = new Datetime();
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEKEYS.'` WHERE expires < ?');
		$stmt->execute(array($date->format('Y-m-d H:i;s')));
	}
	
	/**
	* Resets the ip/key 's sessioni time.
	* <param name="ip">Optional. The ip/key to reset the expiration for.</param>
	*/
	public function resetSessioniExpiration($ip = null) {
		if($ip == null) {
			$ip = $this->sessioniKey;
		}
		$date = new DateTime();
		$date->add(new DateInterval(DEFAULTKEYEXPIRETIME));
		
		$stmt = $this->db->prepare('UPDATE `'.TBL_NAMEKEYS.'` SET expires = ? WHERE `key` = ? OR ip = ?');
		$stmt->execute(array($date->format('Y-m-d H:i;s'), $ip, $ip));
	}

	
	
	/**
	* Sets a var for a sessioni.
	* <param name="var">The name of the variable.</param>
	* <param name="value">The value to set for the variable.</param>
	* <param name="expire">Optional. The expiration time in DateInterval.</param>
	* <param name="domain">Optional. The domain to search the var in. No domain means visible on any domain.</param>
	* <param name="path">Optional. The path to search the path in. No path means visible in any path</param>
	* <param name="secure">Optional. Search in HTTP(S). Note: SECUREGLOBAL (see config).</param>
	* <param name="sessioniId">Optional. the sessioniId to set the var for</param>
	* <return>True if succeeded</return>
	*/
	public function setVar($var, $value, $expire = null, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if(varExists($var, $domain, $path, $secure, $sessioniId)) { // var exists
			if(!OVERWRITEVARS) { // if overwrite is  not permitted
				return false;
			}
			else { // else drop the var & continue
				$this->dropVar($var, $domain, $path, $secure, $sessioniId);
			}
		}
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		if($expire == null) {
			$expire = DEFAULTVAREXPIRETIME;
		}
		else { // check if expire is expired
			$reqDate = new Datetime();
			$reqDate->add(new DateInterval($expire));
			$curDate = new Datetime();
			$diff = $reqDate->getTimestamp() - $curDate->getTimestamp();
			if($diff < 0) { // if expired; drop it & return true
				dropVar($var, $domain, $path, $secure, $sessioniId);
				return true;
			}
		}
		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}
		
		if($domain == null) {
			$domain = '';
		}
		
		if($path == null) { // if no path is set
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
		
		if($stmt->rowCount() <= 0) { // if somehow the db didnt accept the var, return false
			return false;
		}
		$this->loadVars(); // reload $_SESIONI
		return true;
	}
	
	/**
	* Drops expired vars.
	* <param name="sessioniId">Optional. A sessioniId. Set: drop expired vars for this sessioni. Not set: drop expired vars for all sessions.</param>
	*/
	public function dropExpiredVars($expire = null, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		$date = new Datetime();
		
		if($domain == null) {
			$domain = $this->domain;
		}
		if($path == null) {
			$path == $this->path;
		}
		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}
		
		if($sessioniId == null) {
			$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE expires < ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($date->format('Y-m-d H:i;s'), $secure, $path, $domain));
		}
		else {
			$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND expires < ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $date->format('Y-m-d H:i;s'), $secure, $path, $domain));
		}
	}
	
	/**
	* Drop a var.
	* <param name="var">The var to drop.</param>
	* <param name="sessioniId">Optional. The sessioniId. Not set: current sessioniId</param>
	*/
	public function dropVar($var, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if(!varExists($var, $domain, $path, $secure, $sessioniId)) {
			return false;
		}
		if($domain == null) {
			$domain = $this->domain;
		}
		if($path == null) {
			$path == $this->path;
		}
		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}
		
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		$stmt = $this->db->prepare('DELETE FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
		$stmt->execute(array($sessioniId, $var, $secure, $path, $domain));
		if(isset($GLOBALS[$var])) {
			unset($GLOBALS[$var]);
		}
		return true;
	}
	
	/**
	* Checks if a sessioni variable exists
	* <param name="var">The var to check.</param>
	* <param name="domain">Optional. The domain to search in.</param>
	* <param name="path">Optional. The path to search in.</param>
	* <param name="sessioniId">Optional. The sessioniId to search in. Not set: current sessioniId.</param>
	* <return>False if not found. True if found</return>
	*/
	public function varExists($var, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}/*
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}*/
		
		if($domain == null) {
			$domain = $this->domain;
		}

		if($path == null) {
			$path = $this->path;
		}
		
		$stmt = $this->db->prepare('SELECT `id` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = '.($secure ? '1' : '0').(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
		$stmt->execute(array($sessioniId, $var, $path, $domain));
		
		if($stmt->rowCount() <= 0) {
			return false;
		}
		return true;
	}
	
	/**
	* Get a variable value.
	* <param name="var">The var to read.</param>
	* <param name="domain">Optional. The domain to search in.</param>
	* <param name="path">Optional. The path to search in.</param>
	* <param name="sessioniId">Optional. The sessioniId to search in. Not set: current sessioniId.</param>
	* <return>Null if not found. Value if found</return>
	*/
	public function getVar($var, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if(!varExists($var, $domain, $path, $secure, $sessioniId)) {
			return null;
		}
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}/*
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}*/
		
		if($domain == null) {
			$domain = $this->domain;
		}

		if($path == null) {
			$path = $this->path;
		}
		$stmt = $this->db->prepare('SELECT `varValue` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = '.($secure ? '1' : '0').(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
		$stmt->execute(array($sessioniId, $var, $path, $domain));

		return $stmt->fetchColumn();
	}
	
	/**
	* Get the expiration time of a variable.
	* <param name="var">The var.</param>
	* <param name="domain">Optional. The domain to search in.</param>
	* <param name="path">Optional. The path to search in.</param>
	* <param name="sessioniId">Optional. The sessioniId to search in. Not set: current sessioniId.</param>
	* <return>Null if not found, else the expiration time.</return>
	*/
	public function getVarExpiration($var, $domain = null, $path = null, $secure = null, $sessioniId = null) {
		if(!varExists($var, $domain, $path, $secure, $sessioniId)) { // return 1 week ago if it doesnt exist
			$date = new Datetime();
			$date->sub(new DateInterval("P7D"));
			return  $date->format('Y-m-d H:i:s');
		}
		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}
		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}

		if($domain == null) {
			$domain = $this->domain;
		}
		
		if($path == null) {
			$path = $this->path;
		}
		$stmt = $this->db->prepare('SELECT `expires` FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND varName = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
		$stmt->execute(array($sessioniId, $var, $secure, $path, $domain));
		return $stmt->fetchColumn();
	}
	
	/**
	* Populates $_SESSIONI
	* <param name="sessioniId">Optional. The sessioniId used. Not set: current sessioniId or LOADALLSESSIONI (see config).</param>
	* <return>The $_SESSIONI (is defined global)</return>
	*/
	public function loadVars($domain = null, $path = null, $secure = null, $sessioniId = null) {
		if(isset($GLOBALS["_SESSIONI"])) {
			unset($GLOBALS["_SESSIONI"]);
		}
	        global $_SESSIONI;
		$_SESSIONI = array();

		if($sessioniId == null) {
			$sessioniId = $this->sessioniId;
		}

		if($secure == null) { // set the secure
			if(DEFAULTSECURE == "follow") {
				$secure = $this->https;
			}
			else {
				$secure = DEFAULTSECURE;
			}
		}
		else { // check for valid secure
			if(!SECUREGLOBAL && !$this->https) { // if on HTTP & HTTPS vars are invisible on HTTP ==> secure = false
				$secure = false;
			}
		}
		if($domain == null) {
			$domain = $this->domain;
		}
		if($path == null) {
			$path = $this->path;
		}
		
		if(LOADALLSESSIONI && $sessioniId == $this->sessioniId) { // if LOADALLSESSIONI is enabled & the choosen sessioniId is not this sessioniId
			$stmt = $this->db->prepare('SELECT * FROM `'.TBL_NAMEVARS.'` WHERE (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?) ORDER BY sessioniId');
			$stmt->execute(array($secure, $path, $domain));
			
			$curSessioniId = 0;
			while ($collection = $stmt->fetch(PDO::FETCH_ASSOC)) {
				echo "ok";
				if($curSessioniId != $collection["sessioniId"]) { // new associative sub array when new sessioniId
					$curSessioniId = $collection["sessioniId"];
				}
				
				$_SESSIONI[$curSessioniId][$collection["varName"]] = $collection["varValue"];
			}
		}
		else {
			$stmt = $this->db->prepare('SELECT * FROM `'.TBL_NAMEVARS.'` WHERE sessioniId = ? AND (secure = ?'.(SECUREGLOBAL ? ' OR secure = 1' : '').') AND (ISNULL(path) OR path = ?) AND (domain = "" OR domain = ?)');
			$stmt->execute(array($sessioniId, $secure, $path, $domain));

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