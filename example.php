<?php
include 'sessioni.php';
$si = new sessioni(); // create the object

/*some testing*/
echo 'sessioni id: '.$si->sessioniId.'<br />'; // print the sessioni id (alternative: getSessioniId())

echo $si->getVar("test", null, null, false).'<br />';
echo 'Expires on: '.$si->getVarExpiration("test", '', null, false, $si->sessioniId).'<br />';
$si->loadVars(null, null, false);
// echo $si->getSessioniExpiration();
echo print_r($_SESSIONI);
?>