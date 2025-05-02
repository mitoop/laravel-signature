<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;

class SignatureHeaderBuilderFactory
{
    protected array $signers;

    public function __construct()
    {
        $this->signers = SignType::map();
    }

    public function make(string $signType): SignatureHeaderBuilder
    {
        return new SignatureHeaderBuilder($signType, $this->resolveSigner($signType));
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function resolveSigner(string $signType): SignerInterface
    {
        if (isset($this->signers[$signType])) {
            return new $this->signers[$signType];
        }

        throw new InvalidArgumentException("Invalid sign type: {$signType}");
    }
}
