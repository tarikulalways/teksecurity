<?php
/**
 * The only place TekSecurity reads the raw request from.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

defined( 'ABSPATH' ) || exit;

/**
 * Bounded access to the request data the firewall has to inspect byte for byte.
 *
 * A firewall is the one kind of plugin that cannot sanitise its input before
 * looking at it. Its signatures hunt for exactly the characters a sanitiser
 * removes — angle brackets, quotes, control characters, path traversal, NUL
 * padding — so running `sanitize_text_field()` over a request before matching
 * it would delete the evidence and the rules would never fire. Scanning a value
 * that has already been cleaned is scanning the wrong value.
 *
 * So the raw, unsanitised read is contained here instead of being spread across
 * the modules,
 * and it is bounded rather than trusted. Every value this class hands out has
 * been unslashed, had NUL bytes removed and been cut to `MAX_LENGTH`, and it is
 * only ever used as the subject of `preg_match()`.
 *
 * Nothing here is trusted on the way out again. Both exits sanitise:
 *
 *   - stored   `Logger::record()` runs short fields through `sanitize_text_field()`,
 *              the path through `esc_url_raw()` and the matched payload through
 *              `Logger::evidence()`, which drops invalid UTF-8 and control
 *              characters and caps the length.
 *   - printed  every template escapes with `esc_html()` / `esc_attr()`, and the
 *              React admin receives the stored (already sanitised) value.
 *
 * Keys are a different matter: a key is only ever used as a label, never
 * matched, so keys are passed through `sanitize_key()` as they are read.
 */
class Input {

	/**
	 * Longest value the firewall will inspect, in bytes.
	 *
	 * Long enough for a real attack payload, short enough that a multi-megabyte
	 * POST body cannot be used to make the regular expressions expensive.
	 */
	const MAX_LENGTH = 2000;

	/**
	 * Deepest nesting the flattener will follow in an array parameter.
	 */
	const MAX_DEPTH = 4;

	/**
	 * Bound a single request value so it is safe to match against.
	 *
	 * Unslashes, drops NUL bytes and cuts the value to `MAX_LENGTH`. Control
	 * characters are deliberately kept: several signatures look for them, and
	 * they are removed again by `Logger::evidence()` before anything is stored.
	 *
	 * @param mixed $value Raw request value.
	 * @return string
	 */
	public static function inspectable( $value ) {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$value = str_replace( "\0", '', (string) wp_unslash( $value ) );

		return substr( $value, 0, self::MAX_LENGTH );
	}

	/**
	 * The request URI, bounded for inspection.
	 *
	 * @return string
	 */
	public static function uri() {
		// Bounded by self::inspectable(); see this class's documentation for why
		// the value cannot be sanitised before the signatures have seen it.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		return isset( $_SERVER['REQUEST_URI'] ) ? self::inspectable( $_SERVER['REQUEST_URI'] ) : '/';
	}

	/**
	 * The request path, without the query string.
	 *
	 * @return string
	 */
	public static function path() {
		return (string) strtok( self::uri(), '?' );
	}

	/**
	 * A sanitised server header.
	 *
	 * Unlike the values above, a header is never matched against a signature,
	 * so it is sanitised as it is read. $_SERVER is request data like any other
	 * — most of it is sent by the client and none of it is trusted here.
	 *
	 * @param string $key Key in $_SERVER, e.g. REMOTE_ADDR.
	 * @return string Empty string when the header was not sent.
	 */
	public static function server( $key ) {
		if ( ! isset( $_SERVER[ $key ] ) ) {
			return '';
		}

		return sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
	}

	/**
	 * The request method, as an upper-case token.
	 *
	 * @return string
	 */
	public static function method() {
		$method = strtoupper( self::server( 'REQUEST_METHOD' ) );

		return preg_match( '/^[A-Z]{3,10}$/', $method ) ? $method : 'GET';
	}

	/**
	 * Query parameters, flattened to `label => bounded value`.
	 *
	 * @return array
	 */
	public static function query() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return self::flatten_all( (array) $_GET, 'query' );
	}

	/**
	 * Body parameters, flattened to `label => bounded value`.
	 *
	 * @return array
	 */
	public static function body() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return self::flatten_all( (array) $_POST, 'body' );
	}

	/**
	 * Cookies, flattened to `label => bounded value`.
	 *
	 * WordPress's own auth and settings cookies are skipped: they are set by
	 * core, a logged-in visitor sends them on every request, and their hashed
	 * contents would otherwise be copied into the traffic log on any match.
	 *
	 * @return array
	 */
	public static function cookies() {
		$out = array();

		foreach ( (array) $_COOKIE as $key => $value ) {
			if ( 0 === strpos( (string) $key, 'wordpress_' ) || 0 === strpos( (string) $key, 'wp-settings' ) ) {
				continue;
			}

			self::flatten( $out, sanitize_key( (string) $key ) . ' (cookie)', $value );
		}

		return $out;
	}

	/**
	 * One query parameter, bounded, or null when it was not sent.
	 *
	 * @param string $key Parameter name.
	 * @return string|null
	 */
	public static function query_value( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET[ $key ] ) ) {
			return null;
		}

		// Bounded by self::inspectable(); see this class's documentation.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		return self::inspectable( $_GET[ $key ] );
	}

	/**
	 * One query or body parameter, bounded, or null when it was not sent.
	 *
	 * An array value is JSON encoded so a single pattern can be run over it.
	 *
	 * @param string $key Parameter name.
	 * @return string|null
	 */
	public static function request_value( $key ) {
		// phpcs:disable WordPress.Security.NonceVerification
		if ( isset( $_POST[ $key ] ) ) {
			$value = $_POST[ $key ]; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		} elseif ( isset( $_GET[ $key ] ) ) {
			$value = $_GET[ $key ]; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		} else {
			return null;
		}
		// phpcs:enable

		if ( ! is_scalar( $value ) ) {
			// Bounded below, after encoding, so a deep array cannot grow the subject.
			$value = (string) wp_json_encode( map_deep( wp_unslash( $value ), 'strval' ) );

			return substr( str_replace( "\0", '', $value ), 0, self::MAX_LENGTH );
		}

		return self::inspectable( $value );
	}

	/**
	 * Flatten one superglobal into `"key (scope)" => bounded value`.
	 *
	 * @param array  $source Request array.
	 * @param string $scope  Label suffix: query|body.
	 * @return array
	 */
	protected static function flatten_all( array $source, $scope ) {
		$out = array();

		foreach ( $source as $key => $value ) {
			self::flatten( $out, sanitize_key( (string) $key ) . ' (' . $scope . ')', $value );
		}

		return $out;
	}

	/**
	 * Flatten nested request data into label => bounded string pairs.
	 *
	 * @param array  $out   Accumulator, by reference.
	 * @param string $label Label for this value.
	 * @param mixed  $value Value.
	 * @param int    $depth Recursion guard.
	 * @return void
	 */
	protected static function flatten( array &$out, $label, $value, $depth = 0 ) {
		if ( $depth > self::MAX_DEPTH ) {
			return;
		}

		if ( is_array( $value ) ) {
			foreach ( $value as $key => $item ) {
				self::flatten( $out, $label . '[' . sanitize_key( (string) $key ) . ']', $item, $depth + 1 );
			}
			return;
		}

		if ( is_scalar( $value ) ) {
			$out[ $label ] = rawurldecode( self::inspectable( $value ) );
		}
	}
}
