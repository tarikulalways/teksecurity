/**
 * Login protection screen.
 */

import { __, _n, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { clockTime } from '../lib/format';
import { useResource } from '../lib/useResource';
import {
	Card,
	Loading,
	ModuleHeader,
	SelectField,
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
	const { data, save, mutate } = useResource( '/login', { toast, refresh } );

	if ( ! data ) {
		return <Loading />;
	}

	const unlock = ( row ) =>
		mutate( () => api.del( `/login/lockouts/${ row.id }` ), {
			merge: true,
			message: sprintf(
				/* translators: %s: IP address. */
				__( '%s unlocked', 'teksecurity' ),
				row.ip
			),
		} );

	return (
		<div className="ts-stack">
			<ModuleHeader
				icon="lock-key"
				name={ __( 'Brute-force protection', 'teksecurity' ) }
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
						<SelectField
							label={ __( 'Lockout duration', 'teksecurity' ) }
							value={ data.lockout }
							onChange={ ( lockout ) => save( { lockout } ) }
							options={ [
								[ '15', __( '15 minutes', 'teksecurity' ) ],
								[ '30', __( '30 minutes', 'teksecurity' ) ],
								[ '60', __( '1 hour', 'teksecurity' ) ],
								[ '1440', __( '24 hours', 'teksecurity' ) ],
							] }
						/>

						{ isAdv && (
							<SelectField
								label={ __( 'Counting window', 'teksecurity' ) }
								value={ data.window }
								onChange={ ( window ) => save( { window } ) }
								options={ [
									[ '5', __( '5 minutes', 'teksecurity' ) ],
									[ '15', __( '15 minutes', 'teksecurity' ) ],
									[ '60', __( '1 hour', 'teksecurity' ) ],
								] }
							/>
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
					_n(
						'%d IP',
						'%d IPs',
						data.lockouts.length,
						'teksecurity'
					),
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
										_n(
											'%1$d failed login as “%2$s” · until %3$s',
											'%1$d failed logins as “%2$s” · until %3$s',
											row.tries,
											'teksecurity'
										),
										row.tries,
										row.username,
										clockTime( row.expiresAt )
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
