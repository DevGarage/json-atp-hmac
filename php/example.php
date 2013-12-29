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

try{

    ## New instance
    $atphamc = new JsonAtpHmac();

    ## Set token name (Clients ID)
    $atphamc->setToken('client-1');

    ## Set public and private key (token key)
    $atphamc->setKey('public-key','private-key-for-client-1');

    ## Encode message
    $encmsg = $atphamc->encode('Super secret message!');

    ## Show status end encoded message ##
    var_dump($atphamc, $encmsg);

    ## Clear instance
    $atphamc->clear();

    ## Get token (client) hash from message
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