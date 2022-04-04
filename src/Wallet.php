<?php

namespace samyan\HierarchicalDeterministic;

class Wallet
{
    private $address;
    private $publicKey;
    private $privateKey;
    
    /**
     * Constructor
     *
     * @param string $address
     * @param string $publicKey
     * @param string $privateKey
     */
    public function __construct(string $address, string $publicKey, string $privateKey)
    {
        $this->address = $address;
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    /**
     * Get address
     *
     * @return string
     */
    public function getAddress(): string
    {
        return $this->address;
    }

    /**
     * Get public key
     *
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Get private key
     *
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }
}
