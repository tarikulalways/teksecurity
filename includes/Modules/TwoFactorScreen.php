<?php
/**
 * The second step of a two-factor sign-in.
 *
 * @package TekSecurity
 */

namespace TekSecurity\Modules;

use TekSecurity\Core\Options;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Renders the code screen and finishes the login.
 *
 * Every login route lands here: the password step redirects to
 * `wp-login.php?action=teksec_2fa` carrying a one-time token, this screen
 * collects the code, and only then is the auth cookie issued.
 */
class TwoFactorScreen {

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'login_form_teksec_2fa', array( $this, 'challenge' ) );
		add_action( 'login_form_teksec_enrol', array( $this, 'enrol' ) );
	}

	/* --------------------------------------------------------------------- *
	 * Screens
	 * --------------------------------------------------------------------- */

	/**
	 * Ask for the code from the user's app, email or backup list.
	 *
	 * @return void
	 */
	public function challenge() {
		list( $user, $entry ) = $this->require_token();
		$error                = '';

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['teksec_2fa_code'] ) ) {
			$error = $this->handle_code( $user, $entry );
		}

		if ( isset( $_GET['teksec_resend'] ) && 'email' === TwoFactor::method( $user->ID ) ) {
			check_admin_referer( 'teksec_resend_' . $user->ID );
			TwoFactor::resend_email_code( $user );
			$error = '';
		}

		$this->render(
			$user,
			$entry,
			'teksec_2fa',
			__( 'Two-factor sign-in', 'teksecurity' ),
			$error,
			function () use ( $user ) {
				$this->challenge_fields( $user );
			}
		);
	}

	/**
	 * Make a user set two-factor up before they get in.
	 *
	 * Reached once the grace period has run out.
	 *
	 * @return void
	 */
	public function enrol() {
		list( $user, $entry ) = $this->require_token();
		$error                = '';

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['teksec_2fa_code'] ) ) {
			check_admin_referer( 'teksec_2fa_' . $user->ID );

			$code   = sanitize_text_field( wp_unslash( $_POST['teksec_2fa_code'] ) );
			$result = TwoFactor::confirm_setup( $user->ID, $code );

			if ( is_wp_error( $result ) ) {
				$error = $result->get_error_message();

				if ( ! TwoFactor::register_failure( $user->ID ) ) {
					$this->give_up();
				}
			} else {
				// Sign them in, then show the codes once before letting go.
				$codes = TwoFactor::generate_backup_codes( $user->ID );
				$this->sign_in( $user );
				$this->show_backup_codes( $user, $entry, $codes );
			}
		}

		// false: keep the pending secret, so a wrong code does not swap the QR.
		$setup = TwoFactor::begin_setup( $user->ID, false );
		$this->enqueue_qr();

		$this->render(
			$user,
			$entry,
			'teksec_enrol',
			__( 'Set up two-factor sign-in', 'teksecurity' ),
			$error,
			function () use ( $setup ) {
				$this->enrol_fields( $setup );
			}
		);
	}

	/* --------------------------------------------------------------------- *
	 * Form bodies
	 * --------------------------------------------------------------------- */

	/**
	 * The code field, plus whatever help suits the user's method.
	 *
	 * @param WP_User $user The user signing in.
	 * @return void
	 */
	protected function challenge_fields( WP_User $user ) {
		$method = TwoFactor::method( $user->ID );

		printf(
			'<p class="teksec-2fa__lead">%s</p>',
			'email' === $method
				? esc_html__( 'We emailed a 6-digit code to the address on your account. It expires in 10 minutes.', 'teksecurity' )
				: esc_html__( 'Open your authenticator app and enter the 6-digit code it shows.', 'teksecurity' )
		);

		$this->code_field( __( '6-digit code', 'teksecurity' ) );

		if ( TwoFactor::backup_codes_left( $user->ID ) ) {
			printf(
				'<p class="teksec-2fa__note">%s</p>',
				esc_html__( 'Lost your phone? One of your backup codes works here too.', 'teksecurity' )
			);
		}

		if ( 'email' === $method ) {
			printf(
				'<p class="teksec-2fa__note"><a href="%1$s">%2$s</a></p>',
				esc_url( wp_nonce_url( add_query_arg( 'teksec_resend', '1' ), 'teksec_resend_' . $user->ID ) ),
				esc_html__( 'Send a new code', 'teksecurity' )
			);
		}

		$this->remember_field();
	}

	/**
	 * The QR code and the first code from the app.
	 *
	 * @param array $setup Payload from TwoFactor::begin_setup().
	 * @return void
	 */
	protected function enrol_fields( array $setup ) {
		printf(
			'<p class="teksec-2fa__lead">%s</p>',
			esc_html__( 'Two-factor sign-in is now required for your account. Scan this with your authenticator app, then enter the code it shows.', 'teksecurity' )
		);

		printf(
			'<div class="teksec-2fa__qr" data-teksec-otpauth="%1$s" role="img" aria-label="%2$s"></div>',
			esc_attr( $setup['uri'] ),
			esc_attr__( 'Two-factor QR code', 'teksecurity' )
		);

		printf(
			'<p class="teksec-2fa__note">%1$s<br /><code class="teksec-2fa__secret">%2$s</code></p>',
			esc_html__( 'Can’t scan it? Enter this key in the app instead.', 'teksecurity' ),
			esc_html( $setup['prettySecret'] )
		);

		$this->code_field( __( '6-digit code from your app', 'teksecurity' ) );
	}

	/**
	 * The code input itself.
	 *
	 * @param string $label Field label.
	 * @return void
	 */
	protected function code_field( $label ) {
		printf(
			'<p><label for="teksec_2fa_code">%1$s</label>
			<input type="text" name="teksec_2fa_code" id="teksec_2fa_code" class="input teksec-2fa__code"
				inputmode="numeric" autocomplete="one-time-code" autocapitalize="off" spellcheck="false"
				maxlength="20" size="20" autofocus /></p>',
			esc_html( $label )
		);
	}

	/**
	 * The trusted-device opt-in.
	 *
	 * @return void
	 */
	protected function remember_field() {
		$days = (int) Options::get( 'twofactor.remember', 30 );

		if ( 0 === $days ) {
			return;
		}

		printf(
			'<p class="teksec-2fa__remember"><label for="teksec_2fa_remember">
				<input type="checkbox" name="teksec_2fa_remember" id="teksec_2fa_remember" value="1" /> %s
			</label></p>',
			esc_html(
				sprintf(
					/* translators: %d: number of days. */
					_n(
						'Don’t ask on this device for %d day',
						'Don’t ask on this device for %d days',
						$days,
						'teksecurity'
					),
					$days
				)
			)
		);
	}

	/* --------------------------------------------------------------------- *
	 * Plumbing
	 * --------------------------------------------------------------------- */

	/**
	 * Check the submitted code and finish the login when it is right.
	 *
	 * @param WP_User $user  The user signing in.
	 * @param array   $entry The stored login token.
	 * @return string An error message, or an empty string.
	 */
	protected function handle_code( WP_User $user, array $entry ) {
		check_admin_referer( 'teksec_2fa_' . $user->ID );

		$code = isset( $_POST['teksec_2fa_code'] )
			? sanitize_text_field( wp_unslash( $_POST['teksec_2fa_code'] ) )
			: '';

		if ( TwoFactor::verify_code( $user->ID, $code ) ) {
			$this->finish( $user, $entry );
		}

		$left = TwoFactor::register_failure( $user->ID );

		if ( ! $left ) {
			$this->give_up();
		}

		return sprintf(
			/* translators: %d: number of attempts left. */
			_n(
				'That code didn’t match. %d attempt left.',
				'That code didn’t match. %d attempts left.',
				$left,
				'teksecurity'
			),
			$left
		);
	}

	/**
	 * Spend the token, sign the user in and send them on their way.
	 *
	 * @param WP_User $user  The user signing in.
	 * @param array   $entry The stored login token.
	 * @return void
	 */
	protected function finish( WP_User $user, array $entry ) {
		$this->sign_in( $user );

		$redirect = ! empty( $entry['redirect'] ) ? $entry['redirect'] : admin_url();

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Issue the auth cookie. The second factor has passed by this point.
	 *
	 * @param WP_User $user The user signing in.
	 * @return void
	 */
	protected function sign_in( WP_User $user ) {
		TwoFactor::consume_login_token( $user->ID );

		// The nonce for this form was verified by the caller before sign-in.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$remember = ! empty( $_POST['teksec_2fa_remember'] );

		if ( $remember ) {
			TwoFactor::trust_device( $user->ID );
		}

		wp_set_auth_cookie( $user->ID, $remember );

		/**
		 * Core's own action, fired here because the sign-in really has just
		 * completed — anything else listening for a login must still hear it.
		 *
		 * This action is documented in wp-includes/user.php
		 */
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		do_action( 'wp_login', $user->user_login, $user );
	}

	/**
	 * Show the backup codes once, on the way in.
	 *
	 * They are hashed the moment they are made, so this is the only chance the
	 * user gets to write them down.
	 *
	 * @param WP_User $user  The user who just enrolled.
	 * @param array   $entry The stored login token.
	 * @param array   $codes The plain codes.
	 * @return void
	 */
	protected function show_backup_codes( WP_User $user, array $entry, array $codes ) {
		$redirect = ! empty( $entry['redirect'] ) ? $entry['redirect'] : admin_url();

		$this->styles();
		login_header( __( 'Save your backup codes', 'teksecurity' ) );
		?>
		<div id="loginform" class="teksec-2fa__panel">
			<p class="teksec-2fa__lead">
				<?php
				esc_html_e(
					'Two-factor sign-in is on. Keep these codes somewhere safe — each one signs you in once if you lose your phone. They are not shown again.',
					'teksecurity'
				);
				?>
			</p>

			<ul class="teksec-2fa__codes">
				<?php foreach ( $codes as $code ) : ?>
					<li><code><?php echo esc_html( $code ); ?></code></li>
				<?php endforeach; ?>
			</ul>

			<p class="submit">
				<a class="button button-primary button-large" href="<?php echo esc_url( $redirect ); ?>">
					<?php esc_html_e( 'I’ve saved them — continue', 'teksecurity' ); ?>
				</a>
			</p>
		</div>
		<?php
		login_footer();
		exit;
	}

	/**
	 * The token is gone or spent — send them back to the password step.
	 *
	 * @param string $reason Query flag explaining why.
	 * @return void
	 */
	protected function give_up( $reason = 'teksec_expired' ) {
		wp_safe_redirect( add_query_arg( $reason, '1', wp_login_url() ) );
		exit;
	}

	/**
	 * Load the user named in the URL, or bail out.
	 *
	 * @return array{0: WP_User, 1: array}
	 */
	protected function require_token() {
		// phpcs:disable WordPress.Security.NonceVerification
		$user_id = isset( $_REQUEST['teksec_user'] ) ? absint( $_REQUEST['teksec_user'] ) : 0;
		$token   = isset( $_REQUEST['teksec_token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['teksec_token'] ) ) : '';
		// phpcs:enable

		$user  = $user_id ? get_userdata( $user_id ) : false;
		$entry = $user ? TwoFactor::check_login_token( $user_id, $token ) : null;

		if ( ! $user || null === $entry ) {
			$this->give_up();
		}

		return array( $user, $entry );
	}

	/**
	 * Draw the screen inside the site's own login chrome.
	 *
	 * @param WP_User  $user   The user signing in.
	 * @param array    $entry  The stored login token.
	 * @param string   $action Form action value.
	 * @param string   $title  Screen title.
	 * @param string   $error  Error to show, if any.
	 * @param callable $body   Prints the fields.
	 * @return void
	 */
	protected function render( WP_User $user, array $entry, $action, $title, $error, callable $body ) {
		// phpcs:ignore WordPress.Security.NonceVerification
		$token = isset( $_REQUEST['teksec_token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['teksec_token'] ) ) : '';

		$this->styles();

		login_header( $title, '', $error ? new \WP_Error( 'teksec_2fa', $error ) : null );
		?>
		<form name="teksec_2fa_form" id="loginform" method="post"
			action="<?php echo esc_url( add_query_arg( 'action', $action, wp_login_url() ) ); ?>">

			<?php $body(); ?>

			<input type="hidden" name="teksec_user" value="<?php echo esc_attr( $user->ID ); ?>" />
			<input type="hidden" name="teksec_token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $entry['redirect'] ); ?>" />
			<?php wp_nonce_field( 'teksec_2fa_' . $user->ID ); ?>

			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
					value="<?php esc_attr_e( 'Continue', 'teksecurity' ); ?>" />
			</p>
		</form>

		<p id="nav">
			<a href="<?php echo esc_url( wp_login_url() ); ?>">
				<?php esc_html_e( '← Start again', 'teksecurity' ); ?>
			</a>
		</p>
		<?php
		login_footer( 'teksec_2fa_code' );
		exit;
	}

	/**
	 * A little styling so the screen sits comfortably in the login page.
	 *
	 * Queued on `login_enqueue_scripts`, which `login_header()` fires, so this
	 * has to be called before the header is printed.
	 *
	 * @return void
	 */
	protected function styles() {
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_styles' ) );
	}

	/**
	 * Enqueue the login stylesheet.
	 *
	 * @return void
	 */
	public function enqueue_styles() {
		wp_enqueue_style(
			'teksecurity-login-2fa',
			TEKSEC_URL . 'assets/css/login-2fa.css',
			array( 'login' ),
			TEKSEC_VERSION
		);
	}

	/**
	 * Load the script that draws the QR code.
	 *
	 * The shared secret never leaves the site: the code is rendered in the
	 * browser from the bundled encoder rather than fetched from a third party.
	 *
	 * @return void
	 */
	protected function enqueue_qr() {
		$asset_file = TEKSEC_PATH . 'build/login.asset.php';

		if ( ! file_exists( $asset_file ) ) {
			return;
		}

		$asset = require $asset_file;

		wp_enqueue_script(
			'teksecurity-login',
			TEKSEC_URL . 'build/login.js',
			$asset['dependencies'],
			$asset['version'],
			true
		);
	}
}
