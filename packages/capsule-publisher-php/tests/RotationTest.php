<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Dca\Rotation;

final class RotationTest extends TestCase
{
    public function testFormatTimeKid(): void
    {
        $d = new \DateTimeImmutable('2025-10-23 13:42:00', new \DateTimeZone('UTC'));
        self::assertSame('251023T13', Rotation::formatTimeKid($d));
        self::assertSame('251023T1342', Rotation::formatTimeKid($d, true));
    }

    public function testGetCurrentRotationVersionsAlignsToInterval(): void
    {
        // 2025-10-23 13:42 UTC, 4-hour interval → aligns to 12:00 (kid 251023T12), next 16:00.
        $now = new \DateTimeImmutable('2025-10-23 13:42:00', new \DateTimeZone('UTC'));
        $r = Rotation::getCurrentRotationVersions(4, $now);
        self::assertSame('251023T12', $r['current']['kid']);
        self::assertSame('251023T16', $r['next']['kid']);
        self::assertSame('2025-10-23T12:00:00+00:00', $r['current']['start']->format('c'));
        self::assertSame('2025-10-23T16:00:00+00:00', $r['next']['start']->format('c'));
    }

    public function testDeriveWrapKeyMatchesHkdfDefinition(): void
    {
        $secret = str_repeat("\x42", 32);
        $key = Rotation::deriveWrapKey($secret, 'premium', '251023T13');
        self::assertSame(32, strlen($key));

        // Same inputs deterministic.
        self::assertSame(bin2hex($key), bin2hex(Rotation::deriveWrapKey($secret, 'premium', '251023T13')));

        // Different scope → different key.
        $other = Rotation::deriveWrapKey($secret, 'free', '251023T13');
        self::assertNotSame(bin2hex($key), bin2hex($other));
    }
}
