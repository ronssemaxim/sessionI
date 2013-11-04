<?php
// Database config
define('DB_HOST', 'localhost');
define('DB_USER', 'sessioni');
define('DB_PASS', 'sessioni');
define('DB_NAME', 'sessioni');
define('TBL_NAMEKEYS', 'sessioniId');
define('TBL_NAMEVARS', 'vars');

define('IPMATCHKEY', false); // ip's must match their keys
define('COOKIEPRIORITY', false); // (if IPMATCHKEY is false; And record in database was found, and cookie key is not same as that record) priority to db record or cookie. true highly recommended!!
define('OVERWRITEVARS', true); // overwrite vars on setVar
define('DEFAULTEXPIRETIME', 'PT20M'); // default time before a sessioni variable expires, in DateInterval
define('DEFAULTSECURE', true); // create https vars by default; true/false/ "follow" (follow uses url)
define('SECUREGLOBAL', false); // wether or not you can see secure var's on non-https domains (true = everywhere visible)
?>