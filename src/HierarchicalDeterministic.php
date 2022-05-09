<?php

namespace samyan\HierarchicalDeterministic;

use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Buffertools\BufferInterface;
use Exception;
use Web3p\EthereumUtil\Util;
use Elliptic\EC;

class HierarchicalDeterministic
{
    public const WORDS_12 = 128;
    public const WORDS_24 = 256;

    private string $path;
    private Bip39SeedGenerator $bip39;
    private HierarchicalKeyFactory $hdFactory;
    private BufferInterface $seed;
    private HierarchicalKey $masterKey;
    private HierarchicalKey $rootChildKey;
    private Util $util;
    private string $mnemonicWords;

    /**
     * Constructor
     *
     * @param string $path
     * @param string|null $mnemonicWords
     */
    public function __construct(string $path, ?string $mnemonicWords = null)
    {
        $this->path = $path;
        $this->bip39 = new Bip39SeedGenerator();
        $this->hdFactory = new HierarchicalKeyFactory();
        $this->util = new Util();

        if ($mnemonicWords !== null) {
            $this->setMnemonicWords($mnemonicWords);
        }
    }

    /**
     * Generate mnemonic words
     *
     * @param integer $entropySize
     * @return string
     */
    public function generateMnemonicWords(int $entropySize): string
    {
        $bip39 = MnemonicFactory::bip39();
        return $bip39->create($entropySize);
    }

    /**
     * Get mnemonic words
     *
     * @return string|array
     */
    public function getMnemonicWords(bool $arrayFormat = false)
    {
        if ($this->mnemonicWords === null) {
            throw new Exception('Mnemonic words not found');
        }

        if ($arrayFormat) {
            return explode(' ', $this->mnemonicWords);
        }

        return $this->mnemonicWords;
    }

    /**
     * Set mnemonic words
     *
     * @param string $mnemonicWords
     * @return void
     */
    public function setMnemonicWords(string $mnemonicWords): void
    {
        $this->mnemonicWords = $mnemonicWords;
        // Get seed from mnemonic
        $this->seed = $this->bip39->getSeed($this->mnemonicWords);
        // Get master key from entropy
        $this->masterKey = $this->hdFactory->fromEntropy($this->seed);
        // get hardened key from derived path
        $this->rootChildKey = $this->masterKey->derivePath($this->path);
    }

    /**
     * Get seed
     *
     * @return string
     */
    public function getSeed(): string
    {
        if ($this->seed === null) {
            throw new Exception('Seed not found');
        }

        return $this->seed->getHex();
    }

    /**
     * Get master extended public key
     *
     * @return string
     */
    public function getMasterXpubKey(): string
    {
        return $this->masterKey->toExtendedPublicKey();
    }

    /**
     * Get master extended private key
     *
     * @return string
     */
    public function getMasterXprvKey(): string
    {
        return $this->masterKey->toExtendedPrivateKey();
    }

    /**
     * Get root child extended public key
     *
     * @return string
     */
    public function getRootChildXpubKey(): string
    {
        return $this->rootChildKey->toExtendedPublicKey();
    }

    /**
     * Get root child extended private key
     *
     * @return string
     */
    public function getRootChildXprvKey(): string
    {
        return $this->rootChildKey->toExtendedPrivateKey();
    }

    /**
     * Get address from extended public key
     *
     * @param string $key
     * @param integer $index
     * @return string
     */
    public function getAddressFromXpub(string $key, int $index): string
    {
        $childKey = $this->hdFactory->fromExtended($key);

        $rootChildKey = $childKey->derivePath($this->path);
        $publicKey = $rootChildKey->deriveChild($index)->getPublicKey();

        return $this->getAddressFromPublicKey($publicKey->getHex());
    }

    /**
     * Get wallet from extended private key
     *
     * @param string $key
     * @param integer $index
     * @return \App\Service\Crypto\Wallet
     */
    public function getWalletFromXprv(string $key, int $index): Wallet
    {
        // Get master key
        $masterKey = $this->hdFactory->fromExtended($key);
        // Get root child key from derived path
        $rootChildKey = $masterKey->derivePath($this->path);
        // Get child from root child
        $childKey = $rootChildKey->deriveChild($index);

        $privateKey = $childKey->getPrivateKey();
        $publicKey = $childKey->getPublicKey();

        $address = $this->util->publicKeyToAddress($this->util->privateKeyToPublicKey($privateKey->getHex()));

        return new Wallet($address, $publicKey->getHex(), $privateKey->getHex());
    }

    /**
     * Get wallet
     *
     * @param integer $index
     * @return Wallet
     */
    public function getWallet(int $index): Wallet
    {
        $childKey = $this->rootChildKey->deriveChild($index);

        $privateKey = $childKey->getPrivateKey();
        $publicKey = $childKey->getPublicKey();

        $address = $this->util->publicKeyToAddress($this->util->privateKeyToPublicKey($privateKey->getHex()));

        return new Wallet($address, $publicKey->getHex(), $privateKey->getHex());
    }

    /**
     * Get address from public key
     *
     * @param string $publicKey
     * @return string
     */
    private function getAddressFromPublicKey(string $publicKey): string
    {
        $secp256k1 = new EC('secp256k1');
        $keyPair = $secp256k1->keyFromPublic($publicKey, 'hex');

        return $this->util->publicKeyToAddress($keyPair->getPublic(false, 'hex'));
    }
}
