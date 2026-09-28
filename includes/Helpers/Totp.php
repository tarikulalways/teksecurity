<?php
/**
 * RFC 4226 / RFC 6238 one-time passwords.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

defined( 'ABSPATH' ) || exit;

/**
 * Base32 secrets and time-based codes, with no external dependency.
 */
class Totp {

	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const PERIOD   = 30;
	const DIGITS   = 6;

	/**
	 * Generate a fresh base32 secret.
	 *
	 * @param int $length Characters in the secret.
	 * @return string
	 */
	public static function secret( $length = 32 ) {
		$bytes  = random_bytes( (int) ceil( $length * 5 / 8 ) );
		$secret = self::base32_encode( $bytes );

		return substr( $secret, 0, $length );
	}

	/**
	 * Verify a submitted code, allowing for clock drift.
	 *
	 * @param string $secret   Base32 secret.
	 * @param string $code     Submitted digits.
	 * @param int    $window   Steps of drift to accept either side.
	 * @return bool
	 */
	public static function verify( $secret, $code, $window = 1 ) {
		$code = preg_replace( '/\D/', '', (string) $code );

		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$counter = (int) floor( time() / self::PERIOD );

		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( self::code( $secret, $counter + $i ), $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The code for a counter value.
	 *
	 * @param string $secret  Base32 secret.
	 * @param int    $counter Time step.
	 * @return string
	 */
	public static function code( $secret, $counter ) {
		$key    = self::base32_decode( $secret );
		$binary = pack( 'N*', 0 ) . pack( 'N*', $counter );
		$hash   = hash_hmac( 'sha1', $binary, $key, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;

		$value = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * The otpauth:// URI an authenticator app scans.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Account label, usually the email address.
	 * @param string $issuer Site name.
	 * @return string
	 */
	public static function uri( $secret, $label, $issuer ) {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			rawurlencode( $issuer ),
			rawurlencode( $label ),
			$secret,
			rawurlencode( $issuer ),
			self::DIGITS,
			self::PERIOD
		);
	}

	/**
	 * Group a secret into readable blocks of four.
	 *
	 * @param string $secret Base32 secret.
	 * @return string
	 */
	public static function pretty( $secret ) {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}

	/**
	 * Encode bytes as base32.
	 *
	 * @param string $bytes Raw bytes.
	 * @return string
	 */
	public static function base32_encode( $bytes ) {
		$bits = '';
		foreach ( str_split( $bytes ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}

		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}

		return $out;
	}

	/**
	 * Decode a base32 string to bytes.
	 *
	 * @param string $secret Base32 string.
	 * @return string
	 */
	public static function base32_decode( $secret ) {
		$secret = strtoupper( preg_replace( '/[^A-Z2-7]/i', '', (string) $secret ) );
		$bits   = '';

		foreach ( str_split( $secret ) as $char ) {
			$index = strpos( self::ALPHABET, $char );
			if ( false === $index ) {
				continue;
			}
			$bits .= str_pad( decbin( $index ), 5, '0', STR_PAD_LEFT );
		}

		$out = '';
		foreach ( str_split( $bits, 8 ) as $chunk ) {
			if ( 8 === strlen( $chunk ) ) {
				$out .= chr( bindec( $chunk ) );
			}
		}

		return $out;
	}
}
