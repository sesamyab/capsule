<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Dca;

use Sesamy\Capsule\Publisher\Crypto\Hkdf;

/**
 * DCA wrapKey identifiers (kid) and HKDF derivation.
 *
 * Mirrors packages/capsule-server/src/dca-rotation.ts.
 */
final class Rotation
{
    /**
     * Format a UTC timestamp into a kid label.
     *
     * Example: 2025-10-23 13:42 UTC → "251023T13" (or "251023T1342" with $subHour=true).
     */
    public static function formatTimeKid(\DateTimeImmutable $utc, bool $subHour = false): string
    {
        $utc = $utc->setTimezone(new \DateTimeZone('UTC'));
        $base = $utc->format('ymd') . 'T' . $utc->format('H');
        if ($subHour) {
            $base .= $utc->format('i');
        }
        return $base;
    }

    /**
     * Get the current and next kid labels for time-based rotation.
     *
     * @return array{current: array{kid: string, start: \DateTimeImmutable}, next: array{kid: string, start: \DateTimeImmutable}}
     */
    public static function getCurrentRotationVersions(int $rotationIntervalHours = 1, ?\DateTimeImmutable $now = null): array
    {
        $now = ($now ?? new \DateTimeImmutable('now'))->setTimezone(new \DateTimeZone('UTC'));
        $intervalHours = max(1, $rotationIntervalHours);

        $hoursSinceEpoch = intdiv($now->getTimestamp(), 3600);
        $alignedHour = $hoursSinceEpoch - ($hoursSinceEpoch % $intervalHours);
        $alignedStart = (new \DateTimeImmutable('@' . ($alignedHour * 3600)))->setTimezone(new \DateTimeZone('UTC'));
        $nextStart = (new \DateTimeImmutable('@' . (($alignedHour + $intervalHours) * 3600)))->setTimezone(new \DateTimeZone('UTC'));

        return [
            'current' => ['kid' => self::formatTimeKid($alignedStart), 'start' => $alignedStart],
            'next' => ['kid' => self::formatTimeKid($nextStart), 'start' => $nextStart],
        ];
    }

    /**
     * Derive a 32-byte AES wrapKey using HKDF-SHA256.
     *
     * IKM  = rotationSecret
     * salt = scope (UTF-8 bytes)
     * info = "dca|" + kid (UTF-8 bytes)
     * len  = 32
     */
    public static function deriveWrapKey(string $rotationSecret, string $scope, string $kid): string
    {
        return Hkdf::sha256($rotationSecret, $scope, 'dca|' . $kid, 32);
    }
}
