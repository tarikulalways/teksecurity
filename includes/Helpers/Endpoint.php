<?php
/**
 * Locations of the WordPress endpoints the firewall has to recognise.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Helpers;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves WordPress endpoint paths from WordPress itself instead of hard-coding
 * them.
 *
 * TekSecurity never *calls* admin-ajax.php: the admin screen is a React app that
 * talks to this plugin's own REST routes under `teksecurity/v1`, and it is given
 * that endpoint through `wp_localize_script()` from `rest_url()` - see
 * Core\Admin. What the plugin does need is to *recognise* core's endpoints in an
 * incoming request, because the rate-limit rules and the virtual patches match
 * on their paths.
 *
 * Those paths are not fixed. WordPress can live in a subdirectory, `wp-admin/`
 * and `wp-content/` can be moved, wp-login.php can be relocated, the REST
 * prefix can be renamed, and `admin_url`, `login_url`, `plugins_url` and
 * `rest_url_prefix` are all filterable. So every path here is asked of the
 * matching WordPress function and reduced to the part a request URI actually
 * carries, with the stock path kept only as a fallback.
 */
class Endpoint {

	/**
	 * Path of the admin AJAX handler, relative to the host.
	 *
	 * `admin_url()` is the only source: a site in a subdirectory, one that has
	 * moved `wp-admin/`, or a filter on `admin_url` all show up here, and no
	 * stock location is assumed when WordPress cannot say where it is.
	 *
	 * @return string Leading-slash path, or an empty string when WordPress
	 *                gave no path to read.
	 */
	public static function admin_ajax_path() {
		return self::path_of( admin_url( 'admin-ajax.php' ) );
	}

	/**
	 * The same path as a regular expression, for matching a request URI.
	 *
	 * @return string Delimited, case-insensitive pattern.
	 */
	public static function admin_ajax_pattern() {
		return self::pattern( self::admin_ajax_path() );
	}

	/**
	 * Path of the login screen, relative to the host.
	 *
	 * Read through `wp_login_url()`, so a site that has moved or renamed
	 * wp-login.php is rate-limited where its login screen really is.
	 *
	 * @return string
	 */
	public static function login_path() {
		return self::path_of( wp_login_url(), '/wp-login.php' );
	}

	/**
	 * Path prefix of the REST API, relative to the host.
	 *
	 * The `wp-json` segment is only the default; `rest_url_prefix` renames it.
	 * The prefix is read from `rest_get_url_prefix()` rather than from
	 * `rest_url()`, because on a site without pretty permalinks `rest_url()`
	 * returns `/index.php?rest_route=...` - a path that every request on such a
	 * site carries, which as a rate-limit pattern would throttle the whole
	 * site at the REST API's limit.
	 *
	 * @return string Trailing-slash path, e.g. `/wp-json/`.
	 */
	public static function rest_path() {
		$prefix = function_exists( 'rest_get_url_prefix' ) ? (string) rest_get_url_prefix() : '';
		$prefix = trim( $prefix, '/' );

		if ( '' === $prefix ) {
			$prefix = 'wp-json';
		}

		// home_url(), not site_url(): the REST API hangs off the site's front
		// end, which in a subdirectory install may sit above WordPress itself.
		return trailingslashit( self::path_of( home_url( '/' ), '/' ) ) . $prefix . '/';
	}

	/**
	 * Path of xmlrpc.php, relative to the host.
	 *
	 * @return string
	 */
	public static function xmlrpc_path() {
		return self::path_of( site_url( 'xmlrpc.php' ), '/xmlrpc.php' );
	}

	/**
	 * Path of a file inside a plugin's own directory, relative to the host.
	 *
	 * `wp-content/` is a default, not a guarantee: `WP_CONTENT_DIR` and
	 * `WP_PLUGIN_DIR` can both be moved, so the location is asked of
	 * `plugins_url()`.
	 *
	 * @param string $relative Path within the plugins directory, e.g.
	 *                         `acme/lib/connector.php`.
	 * @return string
	 */
	public static function plugin_path( $relative ) {
		$relative = ltrim( (string) $relative, '/' );

		return self::path_of( plugins_url( $relative ), '/wp-content/plugins/' . $relative );
	}

	/**
	 * A path as a regular expression, for matching a request URI.
	 *
	 * @param string $path Host-relative path.
	 * @return string Delimited, case-insensitive pattern. An empty path gives a
	 *                pattern that matches nothing, never one that matches
	 *                every request.
	 */
	public static function pattern( $path ) {
		if ( '' === (string) $path ) {
			return '#(?!)#';
		}

		return '#' . preg_quote( $path, '#' ) . '#i';
	}

	/**
	 * The host-relative path of a WordPress-built URL.
	 *
	 * @param string $url      URL from admin_url(), rest_url() and friends.
	 * @param string $fallback Path to use when the URL carries none. Empty by
	 *                         default, so nothing is guessed on WordPress's
	 *                         behalf.
	 * @return string Leading-slash path, or $fallback.
	 */
	protected static function path_of( $url, $fallback = '' ) {
		$path = wp_parse_url( (string) $url, PHP_URL_PATH );

		if ( ! is_string( $path ) || '' === $path ) {
			return $fallback;
		}

		return '/' . ltrim( $path, '/' );
	}
}
