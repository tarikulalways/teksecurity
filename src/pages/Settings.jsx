/**
 * Settings screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { timeAgo } from '../lib/format';
import {
	Card,
	Loading,
	Segmented,
	SettingRow,
	Switch,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * Alerts, data retention and the integrity scan.
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

	return (
		<div className="ts-stack">
			<Card title={ __( 'Alerts', 'teksecurity' ) } flush>
				<div className="ts-card__body">
					<label className="ts-field" style={ { maxWidth: 380 } }>
						{ __( 'Alert email', 'teksecurity' ) }
						<input
							type="email"
							className={ `ts-input${
								emailBad ? ' ts-input--error' : ''
							}` }
							value={ draft.alerts.email }
							onChange={ ( event ) =>
								patch( 'alerts', { email: event.target.value } )
							}
						/>
						<span
							className={ `ts-hint${
								emailBad ? ' ts-hint--error' : ''
							}` }
						>
							{ emailBad
								? __(
										'Enter a valid email address, or choose Nothing below.',
										'teksecurity'
								  )
								: __(
										'Alerts are sent from this site’s address.',
										'teksecurity'
								  ) }
						</span>
					</label>
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

			<Card title={ __( 'Data', 'teksecurity' ) }>
				<div className="ts-field-grid">
					<label className="ts-field">
						{ __( 'Keep traffic log for', 'teksecurity' ) }
						<select
							className="ts-select"
							value={ draft.data.retention }
							onChange={ ( event ) =>
								patch( 'data', {
									retention: event.target.value,
								} )
							}
						>
							<option value="7">
								{ __( '7 days', 'teksecurity' ) }
							</option>
							<option value="30">
								{ __( '30 days', 'teksecurity' ) }
							</option>
							<option value="90">
								{ __( '90 days', 'teksecurity' ) }
							</option>
						</select>
					</label>

					{ isAdv && (
						<label className="ts-field">
							{ __( 'Visitor IP source', 'teksecurity' ) }
							<select
								className="ts-select"
								value={ draft.data.proxy }
								onChange={ ( event ) =>
									patch( 'data', {
										proxy: event.target.value,
									} )
								}
							>
								<option value="direct">
									{ __(
										'REMOTE_ADDR (direct)',
										'teksecurity'
									) }
								</option>
								<option value="cloudflare">
									{ __(
										'CF-Connecting-IP (Cloudflare)',
										'teksecurity'
									) }
								</option>
								<option value="proxy">
									{ __(
										'X-Forwarded-For (other proxy)',
										'teksecurity'
									) }
								</option>
							</select>
							<span className="ts-hint">
								{ __(
									'Wrong source makes every visitor look like one IP.',
									'teksecurity'
								) }
							</span>
						</label>
					) }
				</div>
			</Card>

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

			<div
				style={ {
					display: 'flex',
					justifyContent: 'space-between',
					gap: 12,
					flexWrap: 'wrap',
				} }
			>
				<button
					type="button"
					className="ts-button"
					onClick={ openWizard }
				>
					<Icon name="magic-wand" />
					{ __( 'Run setup again', 'teksecurity' ) }
				</button>

				<div style={ { display: 'flex', gap: 8 } }>
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
	);
}
