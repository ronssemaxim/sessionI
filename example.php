<?php
include 'sessioni.php';
$sessioni = new sessioni(); // create the object

/*some testing*/
echo 'sessioni id: '.$sessioni->sessioniId.'<br />'; // print the sessioni id (alternative: getSessioniId())
echo '1: '.$sessioni->getVar("secureVar", null, null, 56).$sessioni->getVarExpiration("secureVar").'<br />'; // get var value & expiration, if expired the date substracted by one week is returned
echo '2: '.$sessioni->getVar("noSecure").$sessioni->getVarExpiration("noSecure").'<br />';
$sessioni->dropSessioni("1.1.1.1"); // drop the session for ip 1.1.1.1

?>