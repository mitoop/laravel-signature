<?php

namespace Mitoop\LaravelSignature\Key\Generators;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use phpseclib3\Crypt\EC;

class Ed25519KeyGenerator implements KeyGeneratorInterface
{
    /**
     * @throws RuntimeException
     */
    public function generate(): array
    {
        if (PHP_VERSION_ID >= 80400 && defined('OPENSSL_KEYTYPE_ED25519')) {
            return $this->generateWithOpenssl();
        }

        return $this->generateWithSodium();
    }

    /**
     * @throws RuntimeException
     */
    protected function generateWithOpenssl(): array
    {
        $config = [
            'private_key_type' => constant('OPENSSL_KEYTYPE_ED25519'),
        ];

        $keyResource = openssl_pkey_new($config);

        if ($keyResource === false) {
            $errors = [];
            while ($msg = openssl_error_string()) {
                $errors[] = $msg;
            }
            throw new RuntimeException(
                'Failed to generate Ed25519 keypair with OpenSSL: '.implode(' | ', $errors)
            );
        }

        openssl_pkey_export($keyResource, $privateKeyPem);

        $details = openssl_pkey_get_details($keyResource);

        return [$privateKeyPem, $details['key']];
    }

    protected function generateWithSodium(): array
    {
        $private = EC::createKey('Ed25519');
        $public = $private->getPublicKey();

        /** @var EC\PublicKey $public */
        $privatePem = str_replace("\r\n", "\n", $private->toString('PKCS8'));
        $publicPem = str_replace("\r\n", "\n", $public->toString('PKCS8'));

        $privatePem = rtrim($privatePem, "\n")."\n";
        $publicPem = rtrim($publicPem, "\n")."\n";

        return [
            $privatePem,
            $publicPem,
        ];
    }
}
