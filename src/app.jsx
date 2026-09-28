/**
 * The TekSecurity admin shell: routing, theme, view mode and overlays.
 */

import { useCallback, useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

import { api, boot } from './lib/api';
import { Segmented } from './components/primitives';
import EventDrawer from './components/EventDrawer';
import Wizard from './components/Wizard';

import Overview from './pages/Overview';
import Firewall from './pages/Firewall';
import Traffic from './pages/Traffic';
import LoginProtection from './pages/LoginProtection';
import TwoFactor from './pages/TwoFactor';
import RateLimit from './pages/RateLimit';
import Uploads from './pages/Uploads';
import Plugins from './pages/Plugins';
import Ips from './pages/Ips';
import Settings from './pages/Settings';
import Icon from './components/Icon';

const THEME_KEY = 'teksecurity-theme';

const SUBTITLES = {
	overview: __(
		'What TekSecurity blocked on this site and which protections are running.',
		'teksecurity'
	),
	firewall: __(
		'The firewall inspects every request before WordPress loads and stops the ones that match an attack pattern.',
		'teksecurity'
	),
	traffic: __(
		'Every request the firewall blocked or logged. Select a row to see what was sent and why it was stopped.',
		'teksecurity'
	),
	login: __(
		'Locks out IPs that keep guessing passwords on wp-login.php and XML-RPC.',
		'teksecurity'
	),
	twofa: __(
		'Asks for a one-time code after the password, so a stolen password alone can’t open an account.',
		'teksecurity'
	),
	ratelimit: __(
		'Slows down bots that send more requests than a real visitor would.',
		'teksecurity'
	),
	uploads: __(
		'Rejects files that could run code on your server, from the media library, forms and plugins.',
		'teksecurity'
	),
	plugins: __(
		'Virtual patches block known exploits for your installed plugins until you can update them.',
		'teksecurity'
	),
	ips: __(
		'Blocked IPs can’t reach your site. Allowed IPs skip every firewall check, so add only addresses you control.',
		'teksecurity'
	),
	settings: __(
		'Alerts, log retention and how TekSecurity reads visitor IPs.',
		'teksecurity'
	),
};

/**
 * Read the screen key out of the URL hash.
 *
 * @return {string} Screen key.
 */
function readHash() {
	const key = window.location.hash.replace( /^#\/?/, '' ).split( '?' )[ 0 ];

	return boot.pages.some( ( page ) => page.key === key ) ? key : 'overview';
}

/**
 * The admin application.
 *
 * @return {JSX.Element} The shell.
 */
export default function App() {
	const [ page, setPage ] = useState( readHash );
	const [ filters, setFilters ] = useState( {} );
	const [ mode, setMode ] = useState( boot.mode );
	const [ theme, setTheme ] = useState( () => {
		try {
			return window.localStorage.getItem( THEME_KEY ) || 'light';
		} catch ( error ) {
			return 'light';
		}
	} );
	const [ toast, setToast ] = useState( null );
	const [ drawerId, setDrawerId ] = useState( null );
	const [ wizard, setWizard ] = useState( ! boot.onboarded );
	const [ nonce, setNonce ] = useState( 0 );

	/* Routing ----------------------------------------------------------- */

	useEffect( () => {
		const onHash = () => {
			setPage( readHash() );
			setDrawerId( null );
		};

		window.addEventListener( 'hashchange', onHash );
		return () => window.removeEventListener( 'hashchange', onHash );
	}, [] );

	// Keep the WordPress submenu highlight in step with the hash.
	useEffect( () => {
		const menu = document.querySelector( '#toplevel_page_teksecurity' );

		if ( ! menu ) {
			return;
		}

		menu.querySelectorAll( 'li' ).forEach( ( item ) => {
			const link = item.querySelector( 'a' );

			if ( ! link ) {
				return;
			}

			const href = link.getAttribute( 'href' ) || '';
			const target =
				page === 'overview'
					? href.endsWith( 'page=teksecurity' )
					: href.endsWith( `#/${ page }` );

			item.classList.toggle( 'current', target );
			link.classList.toggle( 'current', target );
		} );
	}, [ page ] );

	const go = useCallback( ( key, nextFilters = {} ) => {
		setFilters( nextFilters );
		setDrawerId( null );
		window.location.hash = `#/${ key }`;
		setPage( key );
		window.scrollTo( 0, 0 );
	}, [] );

	/* Theme ------------------------------------------------------------- */

	useEffect( () => {
		try {
			window.localStorage.setItem( THEME_KEY, theme );
		} catch ( error ) {
			// A private window can refuse storage; the theme still applies.
		}
	}, [ theme ] );

	/* Toast ------------------------------------------------------------- */

	const notify = useCallback( ( message, kind = 'success' ) => {
		setToast( { message, kind, id: Date.now() } );
	}, [] );

	useEffect( () => {
		if ( ! toast ) {
			return;
		}

		const timer = setTimeout( () => setToast( null ), 2800 );
		return () => clearTimeout( timer );
	}, [ toast ] );

	/* View mode --------------------------------------------------------- */

	const changeMode = async ( next ) => {
		setMode( next );

		try {
			await api.post( '/settings', { mode: next } );
		} catch ( error ) {
			notify( error.message, 'error' );
		}
	};

	const refresh = useCallback( () => setNonce( ( value ) => value + 1 ), [] );

	const isAdv = mode === 'advanced';
	const shared = {
		isAdv,
		toast: notify,
		refresh,
		go,
		openEvent: setDrawerId,
	};

	const screens = {
		overview: <Overview key={ nonce } { ...shared } />,
		firewall: <Firewall { ...shared } />,
		traffic: (
			<Traffic
				{ ...shared }
				filters={ filters }
				openId={ drawerId }
			/>
		),
		login: <LoginProtection { ...shared } />,
		twofa: <TwoFactor { ...shared } />,
		ratelimit: <RateLimit { ...shared } />,
		uploads: <Uploads { ...shared } />,
		plugins: <Plugins { ...shared } />,
		ips: <Ips { ...shared } />,
		settings: (
			<Settings { ...shared } openWizard={ () => setWizard( true ) } />
		),
	};

	const title =
		boot.pages.find( ( item ) => item.key === page )?.label ||
		__( 'TekSecurity', 'teksecurity' );

	return (
		<div className="teksecurity-root" data-teksec-theme={ theme }>
			<header className="ts-header">
				<div className="ts-brand">
					<span className="ts-brand__mark">
						<Icon name="shield-check" weight="fill" />
					</span>
					<span className="ts-brand__name">TekSecurity</span>
				</div>

				<div className="ts-header__tools">
					<span className="ts-header__label">
						{ __( 'View', 'teksecurity' ) }
					</span>
					<Segmented
						label={ __( 'View mode', 'teksecurity' ) }
						value={ mode }
						options={ [
							[ 'simple', __( 'Simple', 'teksecurity' ) ],
							[ 'advanced', __( 'Advanced', 'teksecurity' ) ],
						] }
						onChange={ changeMode }
					/>
					<button
						type="button"
						className="ts-icon-button"
						title={
							theme === 'dark'
								? __( 'Switch to light mode', 'teksecurity' )
								: __( 'Switch to dark mode', 'teksecurity' )
						}
						aria-label={
							theme === 'dark'
								? __( 'Switch to light mode', 'teksecurity' )
								: __( 'Switch to dark mode', 'teksecurity' )
						}
						onClick={ () =>
							setTheme( theme === 'dark' ? 'light' : 'dark' )
						}
					>
						<Icon name={ theme === 'dark' ? 'moon' : 'sun' } />
					</button>
				</div>
			</header>

			<div className="ts-body">
				<h1 className="ts-page-title">{ title }</h1>
				<p className="ts-page-sub">{ SUBTITLES[ page ] }</p>
				{ screens[ page ] }
			</div>

			{ drawerId && (
				<EventDrawer
					eventId={ drawerId }
					isAdv={ isAdv }
					toast={ notify }
					onClose={ () => setDrawerId( null ) }
					onViewIp={ ( ip ) => go( 'traffic', { search: ip } ) }
				/>
			) }

			{ wizard && (
				<Wizard
					toast={ notify }
					initial={ {
						mode,
						email: boot.user.email,
					} }
					onFinish={ ( settings ) => {
						setWizard( false );
						setMode( settings.mode );
						go( 'overview' );
						refresh();
					} }
				/>
			) }

			{ toast && (
				<div
					className={ `ts-toast${
						toast.kind === 'error' ? ' ts-toast--error' : ''
					}` }
					role="status"
				>
					<Icon weight="fill" name={ toast.kind === 'error' ? 'warning-circle' : 'check-circle' } />
					{ toast.message }
				</div>
			) }
		</div>
	);
}
