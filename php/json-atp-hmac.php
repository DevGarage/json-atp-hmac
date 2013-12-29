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

class JsonAtpHmac {
    const PROTOCOL          = 1;

    const FLAG_ERROR        = 0x0;
    const FLAG_CLEAR_TEXT   = 0x1;
    const FLAG_COMPRESSION  = 0x2;
    const FLAG_ENCRYPTION   = 0x4;
    const FLAG_DEFAULT      = 0x6;

    const CIPHER            = 'aes-128-cbc';
    const COMPRESSION_LEVEL = 6;

    const HASH_ALGORITHM    = 'sha1';
    const HASH_LENGTH       = 40;

    const HASH_CLEAR_SHA1   = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';

    private $key_public     = null;
    private $key_token      = null;
    private $flag           = self::FLAG_DEFAULT;

    /** @var string Used for identity clients  */
    private $token          = null;
    private $signature      = null;

    public static function hash($data,$key = null){
        return hash_hmac(self::HASH_ALGORITHM,$data,$key);
    }

    public function clear(){
        $this->token        = null;

        $this->flag         = self::FLAG_DEFAULT;
        $this->key_public   = null;
        $this->key_token    = null;
        $this->signature    = null;
    }

    public function encode($message){
        if( !is_string($message) ||  strlen($message) < 0 )
            throw new Exception('Wrong message',11);

        ## HEAD TOKEN ##
        $hash_token = isset($this->token) ? $this->token : 'da39a3ee5e6b4b0d3255bfef95601890afd80709';

        if(strlen($hash_token) !== self::HASH_LENGTH)
            throw new Exception('Wrong token hash length',12);

        ## HASH MESSAGE ##
        $this->signature = self::hash(self::hash($message,$this->key_public),$this->key_token);

        if(strlen($this->signature) !== self::HASH_LENGTH)
            throw new Exception('Wrong signature length',13);

        ## COMPRESS MESSAGE ##
        $message = self::compress($message);

        if($message === false)
            throw new Exception("Error in compress!",14);

        ## ENCRYPT ##
        $message = self::encrypt($message,self::hash($this->token,$this->key_token));

        if($message === false)
            throw new Exception("Error in encryption!",15);

        ## BASE64 MESSAGE ##
        $msg = base64_encode($message);

        if($msg === false)
            throw new Exception("Error in base64 encoding!",16);

        return $this->signature . $hash_token . $this->flag  . $msg;

    }

    public function decode($message){

        ## Data check ##
        if(!is_string($message) || strlen($message) <= 80)
            throw new Exception('Wrong message',21);

        $msg_signature      = substr($message,0,self::HASH_LENGTH);
        $this->flag         = intval(substr($message,self::HASH_LENGTH * 2,1));

        $this->token        = substr($message,self::HASH_LENGTH,self::HASH_LENGTH);

        if(strcmp($this->token,self::HASH_CLEAR_SHA1) == 0)
            $this->token = null;

        ## TEST ERROR FLAG ##
        if(self::flagError($this->flag)){
            $err = json_decode(base64_decode(substr($message,self::HASH_LENGTH * 2 + 1)),true);
            if(is_array($err)){
                throw new Exception($err['message'],$err['code']);
            }else
                throw new Exception('Error flag',1001);
        }

        ## GET MESSAGE ##
        $msg = substr($message,self::HASH_LENGTH * 2 + 1);

        ## BASE64 DECODE ##
        $msg = base64_decode($msg);

        ## DECRYPT MESSAGE ##
        $msg = self::decrypt($msg,self::hash($this->token,$this->key_token));

        ## DECOMPRESS MESSAGE ##
        $msg = self::uncompress($msg);

        ## HASH MESSAGE ##
        $this->signature = self::hash(self::hash($msg,$this->key_public),$this->key_token);

        ## COMPARE SIGNATURE ##
        if(strcmp($this->signature,$msg_signature) != 0)
            throw new Exception('Wrong signature',22);

        return $msg;
    }

    public static function error($token, $message, $code){

        $hash_token = sha1($token);

        $msg = json_encode(array('message'=>$message, 'code'=>$code));
        $hash_data  = self::hash($msg);

        $msg = base64_encode($msg);

        return $hash_data . $hash_token . self::FLAG_ERROR . $msg;
    }

    private function flagClearText($flag){
        return ($flag & self::FLAG_CLEAR_TEXT) > 0 ? true : false;
    }

    private function flagCompression($flag){
        return ($flag & self::FLAG_COMPRESSION) > 0 ? true : false;
    }

    private function flagEncryption($flag){
        return ($flag & self::FLAG_ENCRYPTION) > 0 ? true : false;
    }

    private function flagError($flag){
        return ($flag == 0 ) ? true : false;
    }

    public function setFlag($flag){
        $this->flag     = intval($flag);
    }

    public function getToken($message){
        ## Data check ##
        if(is_string($message) == false || strlen($message) <= 80)
            return false;

        $token = substr($message,self::HASH_LENGTH,self::HASH_LENGTH);

        if(strcmp($token,self::HASH_CLEAR_SHA1) == 0)
            return null;
        else
            return $token;
    }

    public function setToken($token){
        $this->token    = is_string($token) ? sha1($token) : null;
    }

    public function setKey($public = null, $token = null){
        $this->key_public   = is_string($public)    ? $public   : null;
        $this->key_token    = is_string($token)     ? $token    : null;
    }

    private function encrypt($data,$password){
        if(self::flagEncryption($this->flag))
            return @openssl_encrypt($data,self::CIPHER,$password,true);

        return $data;
    }

    public function decrypt($data,$password){
        if(self::flagEncryption($this->flag))
            return @openssl_decrypt($data,self::CIPHER,$password,true);

        return $data;
    }

    private function compress($data){
        if(self::flagCompression($this->flag))
            return @gzcompress($data,self::COMPRESSION_LEVEL);

        return $data;
    }

    private function uncompress($data){
        if(self::flagCompression($this->flag))
            return @gzuncompress($data);

        return $data;
    }
}