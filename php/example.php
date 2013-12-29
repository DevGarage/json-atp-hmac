<?php
/**
 * DevGar
 * Ukraine, Odessa
 * Author: Bubelich Nikolay
 * Email: thesimj@gmail.com
 * GitHub: https://github.com/DevGarage/json-atp-hmac
 * Date: 29.11.13
 * VERSION 0.1
 *
 * =========================================
 * Apache License, Version 2.0, January 2004
 * http://www.apache.org/licenses/
 */

require_once('json-atp-hmac.php');

$atphamc = new JsonAtpHmac();

try{

    $atphamc->setToken('client-1');
    $atphamc->setKey('public-key','private-key-for-client-1');

    $encmsg = $atphamc->encode('Super secret message!');

    var_dump($atphamc, $encmsg,sha1('cls1'));

    $atphamc->clear();

    var_dump($atphamc,$atphamc->getToken($encmsg));


    ## Get hash from Token
    var_dump($atphamc->getToken($encmsg));

    ## Set Key
    $atphamc->setKey('public-key','private-key-for-client-1');

    ## Decode message
    $decmsg = $atphamc->decode($encmsg);

    ## Show message
    var_dump($atphamc,$decmsg);

    $atphamc->clear();

}catch (Exception $ex){
    var_dump($ex);
}