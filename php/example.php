<?php
/**
 * DevGar
 * Ukraine, Odessa
 * Author: Bubelich Nikolay
 * Email: thesimj@gmail.com
 * GitHub: https://github.com/DevGarage/json-atp-hmac
 * Date: 02.01.2014
 * VERSION 0.2
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

//    $atphamc->setFlag(JsonAtpHmac::FLAG_CLEAR_TEXT);

    ## Encode message
    $encmsg = $atphamc->encode('Super secret message!');

    ## Show status end encoded message ##
    var_dump($atphamc, $encmsg);

    ## Clear instance
    $atphamc->clear();

    ## Get token (client) hash from message
    var_dump($atphamc->getToken($encmsg));

    $encmsg = 'cda92dc03e91ddd2d018fe89c506b30f020e23b8c361c11776adfa8308d25677d52087b3f67fbb671U3VwZXIgc2VjcmV0IG1lc3NhZ2Uh';

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