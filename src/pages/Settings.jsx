/**
 * Settings screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { timeAgo } from '../lib/format';
import {
	Card,
	EmptyState,
	Loading,
	Segmented,
	SelectField,
	SettingRow,
	Switch,
	TextField,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * The sections in the rail, in order.
 *
 * `group` names the slice of the draft a section edits, so the rail can mark
 * which sections are holding unsaved changes. Sections that only run actions
 * have no group.
 *
 * @return {Array} Section descriptors.
 */
function sections() {
	return [
		{
			key: 'alerts',
			group: 'alerts',
			icon: 'envelope-simple',
			label: __( 'Alerts', 'teksecurity' ),
			desc: __(
				'Who hears about an attack, and how often.',
				'teksecurity'
			),
		},
		{
			key: 'data',
			group: 'data',
			icon: 'database',
			label: __( 'Data', 'teksecurity' ),
			desc: __(
				'How long the log is kept and how visitor IPs are read.',
				'teksecurity'
			),
		},
		{
			key: 'scans',
			icon: 'magnifying-glass',
			label: __( 'Scans', 'teksecurity' ),
			desc: __(
				'Core file integrity and plugin vulnerability checks.',
				'teksecurity'
			),
		},
		{
			key: 'shortcodes',
			icon: 'code',
			label: __( 'Shortcodes', 'teksecurity' ),
			desc: __(
				'Drop TekSecurity screens into your own pages.',
				'teksecurity'
			),
		},
	];
}

/**
 * Alerts, data retention, scans and shortcodes.
 *
 * @param {Object}   props            Component props.
 * @param {boolean}  props.isAdv      Whether advanced view is on.
 * @param {Function} props.toast      Show a toast.
 * @param {Function} props.openWizard Re-run the setup wizard.
 * @return {JSX.Element} The screen.
 */
export default function Settings( { isAdv, toast, openWizard } ) {
	const [ saved, setSaved ] = useState( null );
	const [ draft, setDraft ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ tab, setTab ] = useState( 'alerts' );

	useEffect( () => {
		api.get( '/settings' )
			.then( ( data ) => {
				setSaved( data );
				setDraft( data );
			} )
			.catch( ( error ) => toast( error.message, 'error' ) );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	if ( ! draft ) {
		return <Loading />;
	}

	const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test( draft.alerts.email );
	const emailBad = ! emailValid && draft.alerts.level !== 'off';
	const dirty = JSON.stringify( draft ) !== JSON.stringify( saved );

	/**
	 * Whether one section is holding unsaved changes.
	 *
	 * @param {string} group Draft key the section edits.
	 * @return {boolean} Whether it differs from what is saved.
	 */
	const groupDirty = ( group ) =>
		!! group &&
		JSON.stringify( draft[ group ] ) !== JSON.stringify( saved[ group ] );

	const patch = ( group, values ) =>
		setDraft( { ...draft, [ group ]: { ...draft[ group ], ...values } } );

	const save = async () => {
		try {
			const next = await api.post( '/settings', draft );
			setSaved( next );
			setDraft( next );
			toast( __( 'Settings saved', 'teksecurity' ) );
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const runScan = async ( job, message ) => {
		setBusy( job );

		try {
			await api.post( `/scan/${ job }` );
			const next = await api.get( '/settings' );
			setSaved( next );
			setDraft( { ...next, alerts: draft.alerts, data: draft.data } );
			toast( message );
		} catch ( error ) {
			toast( error.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const panels = {
		alerts: (
			<Card title={ __( 'Alerts', 'teksecurity' ) } flush>
				<div className="ts-card__body">
					<TextField
						narrow
						type="email"
						label={ __( 'Alert email', 'teksecurity' ) }
						value={ draft.alerts.email }
						onChange={ ( email ) => patch( 'alerts', { email } ) }
						hint={ __(
							'Alerts are sent from this site’s address.',
							'teksecurity'
						) }
						error={
							emailBad
								? __(
										'Enter a valid email address, or choose Nothing below.',
										'teksecurity'
								  )
								: ''
						}
					/>
				</div>

				<SettingRow title={ __( 'Send an email for', 'teksecurity' ) }>
					<Segmented
						label={ __( 'Alert level', 'teksecurity' ) }
						value={ draft.alerts.level }
						options={ [
							[
								'critical',
								__( 'Critical attacks', 'teksecurity' ),
							],
							[ 'all', __( 'Every block', 'teksecurity' ) ],
							[ 'off', __( 'Nothing', 'teksecurity' ) ],
						] }
						onChange={ ( level ) => patch( 'alerts', { level } ) }
					/>
				</SettingRow>

				<SettingRow
					title={ __( 'Weekly summary', 'teksecurity' ) }
					desc={ __(
						'Attacks blocked, plugin issues and lockouts, once a week.',
						'teksecurity'
					) }
				>
					<Switch
						label={ __( 'Weekly summary', 'teksecurity' ) }
						checked={ draft.alerts.weekly }
						onChange={ ( weekly ) => patch( 'alerts', { weekly } ) }
					/>
				</SettingRow>
			</Card>
		),

		data: (
			<Card title={ __( 'Data', 'teksecurity' ) }>
				<div className="ts-field-grid">
					<SelectField
						label={ __( 'Keep traffic log for', 'teksecurity' ) }
						value={ draft.data.retention }
						onChange={ ( retention ) =>
							patch( 'data', { retention } )
						}
						options={ [
							[ '7', __( '7 days', 'teksecurity' ) ],
							[ '30', __( '30 days', 'teksecurity' ) ],
							[ '90', __( '90 days', 'teksecurity' ) ],
						] }
					/>

					{ isAdv && (
						<SelectField
							label={ __( 'Visitor IP source', 'teksecurity' ) }
							value={ draft.data.proxy }
							onChange={ ( proxy ) => patch( 'data', { proxy } ) }
							hint={ __(
								'Wrong source makes every visitor look like one IP.',
								'teksecurity'
							) }
							options={ [
								[
									'direct',
									__( 'REMOTE_ADDR (direct)', 'teksecurity' ),
								],
								[
									'cloudflare',
									__(
										'CF-Connecting-IP (Cloudflare)',
										'teksecurity'
									),
								],
								[
									'proxy',
									__(
										'X-Forwarded-For (other proxy)',
										'teksecurity'
									),
								],
							] }
						/>
					) }
				</div>
			</Card>
		),

		scans: (
			<Card title={ __( 'Scans', 'teksecurity' ) } flush>
				<SettingRow
					title={ __( 'Core file integrity', 'teksecurity' ) }
					desc={
						saved.integrity.lastScanAt
							? sprintf(
									/* translators: 1: relative time, 2: files compared, 3: problems found. */
									__(
										'Last run %1$s · %2$d files compared · %3$d problems',
										'teksecurity'
									),
									timeAgo( saved.integrity.lastScanAt ),
									saved.integrity.checked,
									saved.integrity.issues
							  )
							: __( 'Has not run yet.', 'teksecurity' )
					}
				>
					<button
						type="button"
						className="ts-button ts-button--small"
						disabled={ busy === 'integrity' }
						onClick={ () =>
							runScan(
								'integrity',
								__( 'Integrity scan finished', 'teksecurity' )
							)
						}
					>
						{ busy === 'integrity'
							? __( 'Scanning…', 'teksecurity' )
							: __( 'Scan now', 'teksecurity' ) }
					</button>
				</SettingRow>

				<SettingRow
					title={ __( 'Plugin vulnerabilities', 'teksecurity' ) }
					desc={ __(
						'Matches your installed plugins against the advisory feed.',
						'teksecurity'
					) }
				>
					<button
						type="button"
						className="ts-button ts-button--small"
						disabled={ busy === 'vulnerability' }
						onClick={ () =>
							runScan(
								'vulnerability',
								__(
									'Vulnerability scan finished',
									'teksecurity'
								)
							)
						}
					>
						{ busy === 'vulnerability'
							? __( 'Scanning…', 'teksecurity' )
							: __( 'Scan now', 'teksecurity' ) }
					</button>
				</SettingRow>
			</Card>
		),

		shortcodes: (
			<EmptyState
				icon="code"
				title={ __( 'No shortcodes yet', 'teksecurity' ) }
				desc={ __(
					'TekSecurity does not add any shortcodes at the moment. When the two-factor sign-in screen can be placed on your own page, its shortcode will be listed here to copy.',
					'teksecurity'
				) }
			/>
		),
	};

	return (
		<div className="ts-settings">
			<nav
				className="ts-settingsnav"
				aria-label={ __( 'Settings sections', 'teksecurity' ) }
			>
				{ sections().map( ( section ) => (
					<button
						key={ section.key }
						type="button"
						aria-current={
							tab === section.key ? 'page' : undefined
						}
						className={ `ts-settingsnav__item${
							tab === section.key ? ' is-active' : ''
						}` }
						onClick={ () => setTab( section.key ) }
					>
						<Icon name={ section.icon } size={ 17 } />
						<span className="ts-settingsnav__text">
							<span className="ts-settingsnav__label">
								{ section.label }
							</span>
							<span className="ts-settingsnav__desc">
								{ section.desc }
							</span>
						</span>
						{ groupDirty( section.group ) && (
							<span
								className="ts-settingsnav__dot"
								title={ __( 'Unsaved changes', 'teksecurity' ) }
							/>
						) }
					</button>
				) ) }
			</nav>

			<div className="ts-settings__panel">
				{ panels[ tab ] }

				<div className="ts-footer-bar">
					<button
						type="button"
						className="ts-button"
						onClick={ openWizard }
					>
						<Icon name="magic-wand" />
						{ __( 'Run setup again', 'teksecurity' ) }
					</button>

					<div className="ts-actions">
						{ dirty && (
							<button
								type="button"
								className="ts-button"
								onClick={ () => setDraft( saved ) }
							>
								{ __( 'Discard', 'teksecurity' ) }
							</button>
						) }
						<button
							type="button"
							className="ts-button ts-button--primary"
							disabled={ ! dirty || emailBad }
							onClick={ save }
						>
							{ __( 'Save settings', 'teksecurity' ) }
						</button>
					</div>
				</div>
			</div>
		</div>
	);
}
