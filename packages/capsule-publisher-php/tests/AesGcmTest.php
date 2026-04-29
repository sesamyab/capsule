<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Crypto\Aes;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

final class AesGcmTest extends TestCase
{
    public function testRoundTripWithoutAad(): void
    {
        $key = random_bytes(32);
        $iv = random_bytes(12);
        $plaintext = 'Hello, world!';

        $ciphertext = Aes::gcmEncrypt($plaintext, $key, $iv);
        self::assertSame(strlen($plaintext) + 16, strlen($ciphertext), 'tag should be appended');

        $decrypted = Aes::gcmDecrypt($ciphertext, $key, $iv);
        self::assertSame($plaintext, $decrypted);
    }

    public function testRoundTripWithAad(): void
    {
        $key = random_bytes(32);
        $iv = random_bytes(12);
        $aad = 'domain.com|res-1|bodytext|premium';
        $plaintext = '<p>Premium body…</p>';

        $ciphertext = Aes::gcmEncrypt($plaintext, $key, $iv, $aad);
        $decrypted = Aes::gcmDecrypt($ciphertext, $key, $iv, $aad);
        self::assertSame($plaintext, $decrypted);
    }

    public function testWrongAadFailsDecryption(): void
    {
        $key = random_bytes(32);
        $iv = random_bytes(12);
        $ciphertext = Aes::gcmEncrypt('hi', $key, $iv, 'expected-aad');

        $this->expectException(PublisherException::class);
        Aes::gcmDecrypt($ciphertext, $key, $iv, 'tampered-aad');
    }

    public function testRejectsInvalidKeyLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Aes::gcmEncrypt('hi', str_repeat("\x00", 16), str_repeat("\x00", 12));
    }

    public function testRejectsInvalidIvLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Aes::gcmEncrypt('hi', str_repeat("\x00", 32), str_repeat("\x00", 11));
    }
}
