<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

final class Pem
{
    /**
     * Strip PEM header/footer/whitespace and return raw DER bytes.
     */
    public static function parse(string $pem): string
    {
        if (preg_match('/-----BEGIN ([A-Z 0-9]+)-----[\s\S]*?-----END ([A-Z 0-9]+)-----/', $pem, $m) !== 1 || $m[1] !== $m[2]) {
            throw new \InvalidArgumentException('Invalid PEM input');
        }
        $stripped = preg_replace('/-----BEGIN [A-Z 0-9]+-----|-----END [A-Z 0-9]+-----|\s+/', '', $pem);
        if ($stripped === null || $stripped === '') {
            throw new \InvalidArgumentException('Invalid PEM input');
        }
        $der = base64_decode($stripped, true);
        if ($der === false) {
            throw new \InvalidArgumentException('Invalid base64 in PEM body');
        }
        return $der;
    }
}
