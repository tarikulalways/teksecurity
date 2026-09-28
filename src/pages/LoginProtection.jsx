/**
 * Login protection screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import {
	Card,
	Loading,
	ModuleHeader,
	SettingRow,
	Switch,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * Brute-force rules and the current lockouts.
 *
 * @param {Object}   props         Component props.
 * @param {boolean}  props.isAdv   Whether advanced view is on.
 * @param {Function} props.toast   Show a toast.
 * @param {Function} props.refresh Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function LoginProtection( { isAdv, toast, refresh } ) {
	const [ data, setData ] = useState( null );

	useEffect( () => {
		api.get( '/login' )
			.then( setData )
			.catch( ( error ) => toast( error.message, 'error' ) );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	if ( ! data ) {
		return <Loading />;
	}

	const save = async ( payload, message ) => {
		try {
			setData( await api.post( '/login', payload ) );
			refresh();

			if ( message ) {
				toast( message );
			}
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const unlock = async ( row ) => {
		try {
			const next = await api.del( `/login/lockouts/${ row.id }` );
			setData( { ...data, lockouts: next.lockouts } );
			refresh();
			toast(
				sprintf(
					/* translators: %s: IP address. */
					__( '%s unlocked', 'teksecurity' ),
					row.ip
				)
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	return (
		<div className="ts-stack">
			<ModuleHeader
				icon="ph-lock-key"
				name={ __( 'Brute-force protection', 'teksecurity' ) }
				status={
					data.enabled
						? __( 'Active', 'teksecurity' )
						: __( 'Off', 'teksecurity' )
				}
				tone={ data.enabled ? 'ok' : 'bad' }
				stopped={ data.stopped }
				enabled={ data.enabled }
				onToggle={ ( enabled ) =>
					save(
						{ enabled },
						enabled
							? __(
									'Brute-force protection turned on',
									'teksecurity'
							  )
							: __(
									'Brute-force protection turned off',
									'teksecurity'
							  )
					)
				}
			/>

			<Card title={ __( 'Lockout rules', 'teksecurity' ) } flush>
				<SettingRow
					title={ __(
						'Failed attempts before lockout',
						'teksecurity'
					) }
					desc={ __( 'Counted per IP address.', 'teksecurity' ) }
				>
					<div className="ts-stepper">
						<button
							type="button"
							aria-label={ __( 'Fewer attempts', 'teksecurity' ) }
							disabled={ data.attempts <= 2 }
							onClick={ () =>
								save( { attempts: data.attempts - 1 } )
							}
						>
							<Icon name="minus" />
						</button>
						<span className="ts-stepper__value">
							{ data.attempts }
						</span>
						<button
							type="button"
							aria-label={ __( 'More attempts', 'teksecurity' ) }
							disabled={ data.attempts >= 20 }
							onClick={ () =>
								save( { attempts: data.attempts + 1 } )
							}
						>
							<Icon name="plus" />
						</button>
					</div>
				</SettingRow>

				<div className="ts-row">
					<div className="ts-field-grid ts-row__grow">
						<label className="ts-field">
							{ __( 'Lockout duration', 'teksecurity' ) }
							<select
								className="ts-select"
								value={ data.lockout }
								onChange={ ( event ) =>
									save( { lockout: event.target.value } )
								}
							>
								<option value="15">
									{ __( '15 minutes', 'teksecurity' ) }
								</option>
								<option value="30">
									{ __( '30 minutes', 'teksecurity' ) }
								</option>
								<option value="60">
									{ __( '1 hour', 'teksecurity' ) }
								</option>
								<option value="1440">
									{ __( '24 hours', 'teksecurity' ) }
								</option>
							</select>
						</label>

						{ isAdv && (
							<label className="ts-field">
								{ __( 'Counting window', 'teksecurity' ) }
								<select
									className="ts-select"
									value={ data.window }
									onChange={ ( event ) =>
										save( { window: event.target.value } )
									}
								>
									<option value="5">
										{ __( '5 minutes', 'teksecurity' ) }
									</option>
									<option value="15">
										{ __( '15 minutes', 'teksecurity' ) }
									</option>
									<option value="60">
										{ __( '1 hour', 'teksecurity' ) }
									</option>
								</select>
							</label>
						) }
					</div>
				</div>

				<SettingRow
					title={ __( 'Block logins as “admin”', 'teksecurity' ) }
					desc={
						data.adminUserExists
							? __(
									'Anyone trying the username “admin” is locked out at once — except on this site, where “admin” is a real account, so it is left alone. Rename that account to make the rule count.',
									'teksecurity'
							  )
							: __(
									'Anyone trying the username “admin” is locked out at once. Most sites don’t use it.',
									'teksecurity'
							  )
					}
				>
					<Switch
						label={ __( 'Block logins as admin', 'teksecurity' ) }
						checked={ data.blockAdmin }
						onChange={ ( blockAdmin ) => save( { blockAdmin } ) }
					/>
				</SettingRow>

				<SettingRow
					title={ __( 'Block XML-RPC logins', 'teksecurity' ) }
					desc={ __(
						'Stops password guessing through xmlrpc.php. Turn off if you use the Jetpack app.',
						'teksecurity'
					) }
				>
					<Switch
						label={ __( 'Block XML-RPC logins', 'teksecurity' ) }
						checked={ data.xmlrpc }
						onChange={ ( xmlrpc ) => save( { xmlrpc } ) }
					/>
				</SettingRow>
			</Card>

			<Card
				title={ __( 'Locked out now', 'teksecurity' ) }
				meta={ sprintf(
					/* translators: %d: number of locked out addresses. */
					_n( '%d IP', '%d IPs', data.lockouts.length, 'teksecurity' ),
					data.lockouts.length
				) }
				flush
			>
				{ data.lockouts.length ? (
					data.lockouts.map( ( row ) => (
						<div className="ts-row" key={ row.id }>
							<div className="ts-row__grow">
								<div className="ts-row__title ts-mono">
									{ row.ip }{ ' ' }
									{ row.country && (
										<span className="ts-cell-cc">
											{ row.country }
										</span>
									) }
								</div>
								<div className="ts-row__desc">
									{ sprintf(
										/* translators: 1: attempt count, 2: username, 3: clock time. */
										__(
											'%1$d failed logins as “%2$s” · until %3$s',
											'teksecurity'
										),
										row.tries,
										row.username,
										row.until
									) }
								</div>
							</div>
							<button
								type="button"
								className="ts-button ts-button--small"
								onClick={ () => unlock( row ) }
							>
								{ __( 'Unlock', 'teksecurity' ) }
							</button>
						</div>
					) )
				) : (
					<div className="ts-inline-empty">
						{ __(
							'No IPs are locked out right now.',
							'teksecurity'
						) }
					</div>
				) }
			</Card>
		</div>
	);
}
