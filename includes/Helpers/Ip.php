<?php
/**
 * Visitor IP resolution and CIDR matching.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

use TekSecurity\Core\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Reads the real visitor IP according to the configured proxy source.
 */
class Ip {

	/**
	 * Resolved IP for this request.
	 *
	 * @var string|null
	 */
	protected static $current = null;

	/**
	 * Header to read for each proxy setting.
	 *
	 * @return array
	 */
	protected static function sources() {
		return array(
			'direct'     => 'REMOTE_ADDR',
			'cloudflare' => 'HTTP_CF_CONNECTING_IP',
			'proxy'      => 'HTTP_X_FORWARDED_FOR',
		);
	}

	/**
	 * The visitor IP for the current request.
	 *
	 * @return string
	 */
	public static function current() {
		if ( null !== self::$current ) {
			return self::$current;
		}

		$proxy   = Options::get( 'data.proxy', 'direct' );
		$sources = self::sources();
		$header  = isset( $sources[ $proxy ] ) ? $sources[ $proxy ] : 'REMOTE_ADDR';

		// Not sanitized on the way in on purpose: the value is validated as an
		// IP address below, which is stricter than any string sanitizer.
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$raw = isset( $_SERVER[ $header ] ) ? wp_unslash( $_SERVER[ $header ] ) : '';
		if ( '' === $raw && isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$raw = wp_unslash( $_SERVER['REMOTE_ADDR'] );
		}
		// phpcs:enable

		// X-Forwarded-For may be a chain; the left-most entry is the client.
		$candidate = trim( (string) strtok( (string) $raw, ',' ) );
		$valid     = filter_var( $candidate, FILTER_VALIDATE_IP );

		self::$current = $valid ? $valid : '0.0.0.0';

		return self::$current;
	}

	/**
	 * Validate an IPv4/IPv6 address or an IPv4 CIDR range.
	 *
	 * @param string $value Candidate.
	 * @return bool
	 */
	public static function is_valid( $value ) {
		$value = trim( (string) $value );

		if ( false !== strpos( $value, '/' ) ) {
			list( $network, $bits ) = array_pad( explode( '/', $value, 2 ), 2, '' );

			if ( ! filter_var( $network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return false;
			}

			return ctype_digit( $bits ) && (int) $bits >= 0 && (int) $bits <= 32;
		}

		return (bool) filter_var( $value, FILTER_VALIDATE_IP );
	}

	/**
	 * Whether an IP falls inside an address or CIDR range.
	 *
	 * @param string $ip    Address to test.
	 * @param string $range Address or CIDR range.
	 * @return bool
	 */
	public static function matches( $ip, $range ) {
		$ip    = trim( (string) $ip );
		$range = trim( (string) $range );

		if ( '' === $ip || '' === $range ) {
			return false;
		}

		if ( false === strpos( $range, '/' ) ) {
			return $ip === $range;
		}

		list( $network, $bits ) = array_pad( explode( '/', $range, 2 ), 2, '32' );

		$ip_long  = ip2long( $ip );
		$net_long = ip2long( $network );

		if ( false === $ip_long || false === $net_long ) {
			return false;
		}

		$bits = (int) $bits;
		if ( 0 === $bits ) {
			return true;
		}

		$mask = -1 << ( 32 - $bits );

		return ( $ip_long & $mask ) === ( $net_long & $mask );
	}

	/**
	 * Two-letter country code for an IP, when a geo provider is available.
	 *
	 * Core WordPress ships no geo database, so this returns an empty string
	 * unless a host or another plugin fills it through the filter.
	 *
	 * @param string $ip Address.
	 * @return string
	 */
	public static function country( $ip ) {
		$code = '';

		if ( isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			$code = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) );
		}

		/**
		 * Filter the resolved country code for an IP address.
		 *
		 * @param string $code Two-letter code, or an empty string.
		 * @param string $ip   Address.
		 */
		$code = apply_filters( 'teksecurity_ip_country', $code, $ip );

		return strtoupper( substr( (string) $code, 0, 2 ) );
	}

	/**
	 * The user agent string for the current request.
	 *
	 * @return string
	 */
	public static function user_agent() {
		if ( ! isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return '';
		}

		return substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 500 );
	}
}
