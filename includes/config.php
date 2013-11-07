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
define('DEFAULTVAREXPIRETIME', 'PT20M'); // default time before a sessioni variable expires, in DateInterval
define('DEFAULTKEYEXPIRETIME', 'PT20M'); // default time before a sessioni expires, in DateInterval
define('DEFAULTSECURE', "follow"); // create https vars by default; true/false/ "follow" (follow uses url)
define('SECUREGLOBAL', false); // whether or not you can see secure var's on non-https domains (true = everywhere visible)
define('LOADALLSESSIONI', false); // false: $sessioni contains only the current user's values; true: $sessioni contains all sessioni's and their vars (experimental)
define('KEYLENGTH', 32); // keylength of the sessioniKey; 62^KEYLENGTH = max amount of keys; Keys are random generated, so choose wise (automatic regeneration if key is already taken)
?>