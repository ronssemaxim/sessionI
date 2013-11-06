<?php
include 'sessioni.php';
$si = new sessioni(); // create the object

/*some testing*/
echo 'sessioni id: '.$si->sessioniId.'<br />'; // print the sessioni id (alternative: getSessioniId())

echo $si->getSessioniExpiration();
echo print_r($_SESSIONI);
?>