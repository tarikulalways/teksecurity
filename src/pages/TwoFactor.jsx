/**
 * Two-factor authentication screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import {
	Card,
	Chips,
	Loading,
	StatusPill,
	Switch,
} from '../components/primitives';
import TwoFactorModal from '../components/TwoFactorModal';
import Icon from '../components/Icon';

/**
 * Who must use two-factor, how they sign in and where each of them stands.
 *
 * @param {Object}   props         Component props.
 * @param {boolean}  props.isAdv   Whether advanced view is on.
 * @param {Function} props.toast   Show a toast.
 * @param {Function} props.refresh Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function TwoFactor( { isAdv, toast, refresh } ) {
	const [ data, setData ] = useState( null );
	const [ roles, setRoles ] = useState( [] );
	const [ role, setRole ] = useState( '' );
	const [ available, setAvailable ] = useState( [] );
	const [ pick, setPick ] = useState( '' );
	const [ filter, setFilter ] = useState( 'all' );
	const [ setup, setSetup ] = useState( null );

	const load = () => api.get( '/twofa' ).then( setData );

	useEffect( () => {
		Promise.all( [ load(), api.get( '/twofa/roles' ).then( setRoles ) ] ).catch(
			( error ) => toast( error.message, 'error' )
		);
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	useEffect( () => {
		if ( ! role ) {
			setAvailable( [] );
			setPick( '' );
			return;
		}

		api.get( `/twofa/roles/${ role }/users` )
			.then( ( users ) => {
				setAvailable( users );
				setPick( '' );
			} )
			.catch( ( error ) => toast( error.message, 'error' ) );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ role, data ] );

	if ( ! data ) {
		return <Loading />;
	}

	const save = async ( payload, message ) => {
		try {
			setData( await api.post( '/twofa', payload ) );
			refresh();

			if ( message ) {
				toast( message );
			}
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const addUsers = async () => {
		const ids =
			pick === 'all' ? available.map( ( user ) => user.id ) : [ Number( pick ) ];

		try {
			setData( await api.post( '/twofa/users', { userIds: ids } ) );
			refresh();
			setPick( '' );
			setFilter( 'all' );
			toast(
				ids.length > 1
					? sprintf(
							/* translators: %d: number of users added. */
							__( '%d users added', 'teksecurity' ),
							ids.length
					  )
					: sprintf(
							/* translators: %s: user name. */
							__( '%s must now use two-factor', 'teksecurity' ),
							available.find( ( user ) => user.id === ids[ 0 ] )
								?.name || ''
					  )
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const userAction = async ( path, message ) => {
		try {
			setData( await api.post( path ) );
			refresh();
			toast( message );
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const removeUser = async ( user ) => {
		try {
			setData( await api.del( `/twofa/users/${ user.id }` ) );
			refresh();
			toast(
				sprintf(
					/* translators: %s: user name. */
					__( '%s no longer needs two-factor', 'teksecurity' ),
					user.name
				)
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const beginSetup = async () => {
		try {
			const result = await api.post( '/twofa/setup' );

			if ( result.done ) {
				await load();
				refresh();
				toast(
					__( 'Email codes are on for your account', 'teksecurity' )
				);
				return;
			}

			setSetup( result );
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const required = data.users;
	const rows = required.filter(
		( user ) => filter === 'all' || user.status === 'none'
	);

	const summary = ! data.enabled
		? __( 'Accounts sign in with a password only.', 'teksecurity' )
		: ! required.length
		? __(
				'No users added yet. Add users to require two-factor for them.',
				'teksecurity'
		  )
		: data.missing
		? sprintf(
				/* translators: 1: total required users, 2: how many have not set up. */
				_n(
					'%1$d user must use two-factor. %2$d hasn’t set it up yet.',
					'%1$d users must use two-factor. %2$d haven’t set it up yet.',
					required.length,
					'teksecurity'
				),
				required.length,
				data.missing
		  )
		: sprintf(
				/* translators: %d: total required users. */
				_n(
					'%d user must use two-factor, and they have set it up.',
					'%d users must use two-factor, and all of them have set it up.',
					required.length,
					'teksecurity'
				),
				required.length
		  );

	const pickOptions = ! role
		? [ [ '', __( 'Select a role first', 'teksecurity' ) ] ]
		: ! available.length
		? [ [ '', __( 'Everyone in this role is added', 'teksecurity' ) ] ]
		: [
				[ '', __( 'Select a user', 'teksecurity' ) ],
				...( available.length > 1
					? [
							[
								'all',
								sprintf(
									/* translators: %d: number of users in the role. */
									__(
										'Everyone in this role (%d)',
										'teksecurity'
									),
									available.length
								),
							],
					  ]
					: [] ),
				...available.map( ( user ) => [
					String( user.id ),
					`${ user.name } · ${ user.email }`,
				] ),
		  ];

	return (
		<div className="ts-stack">
			<section className="ts-card">
				<div className="ts-row">
					<div className="ts-row__icon">
						<Icon name="device-mobile" />
					</div>
					<div className="ts-row__grow">
						<div
							style={ {
								display: 'flex',
								alignItems: 'center',
								gap: 8,
								flexWrap: 'wrap',
							} }
						>
							<span className="ts-row__title">
								{ __(
									'Two-factor authentication',
									'teksecurity'
								) }
							</span>
							<StatusPill
								tone={ data.enabled ? 'ok' : 'bad' }
								label={
									data.enabled
										? __( 'Active', 'teksecurity' )
										: __( 'Off', 'teksecurity' )
								}
							/>
						</div>
						<div className="ts-row__desc">{ summary }</div>
					</div>
					<Switch
						label={ __(
							'Turn two-factor on or off',
							'teksecurity'
						) }
						checked={ data.enabled }
						onChange={ ( enabled ) =>
							save(
								{ enabled },
								enabled
									? __(
											'Two-factor turned on',
											'teksecurity'
									  )
									: __(
											'Two-factor turned off',
											'teksecurity'
									  )
							)
						}
					/>
				</div>
			</section>

			<div
				className="ts-split"
				style={ { opacity: data.enabled ? 1 : 0.5 } }
			>
				<div className="ts-stack">
					<Card title={ __( 'Add users', 'teksecurity' ) }>
						<p className="ts-row__desc" style={ { marginTop: 0 } }>
							{ __(
								'Choose a role to load its users, then pick who must use two-factor.',
								'teksecurity'
							) }
						</p>
						<div
							className="ts-field-grid"
							style={ { marginTop: 12 } }
						>
							<label className="ts-field">
								{ __( 'Role', 'teksecurity' ) }
								<select
									className="ts-select"
									value={ role }
									onChange={ ( event ) =>
										setRole( event.target.value )
									}
								>
									<option value="">
										{ __( 'Select a role', 'teksecurity' ) }
									</option>
									{ roles.map( ( item ) => (
										<option key={ item.key } value={ item.key }>
											{ sprintf(
												/* translators: 1: role name, 2: number of users. */
												_n(
													'%1$s · %2$d user',
													'%1$s · %2$d users',
													item.users,
													'teksecurity'
												),
												item.name,
												item.users
											) }
										</option>
									) ) }
								</select>
							</label>

							<label className="ts-field">
								{ __( 'User', 'teksecurity' ) }
								<select
									className="ts-select"
									value={ pick }
									disabled={ ! available.length }
									onChange={ ( event ) =>
										setPick( event.target.value )
									}
								>
									{ pickOptions.map( ( [ key, label ] ) => (
										<option key={ key } value={ key }>
											{ label }
										</option>
									) ) }
								</select>
							</label>
						</div>

						<button
							type="button"
							className="ts-button ts-button--primary"
							style={ { marginTop: 14 } }
							disabled={ ! pick || ! available.length }
							onClick={ addUsers }
						>
							<Icon name="user-plus" />
							{ pick === 'all'
								? sprintf(
										/* translators: %d: number of users. */
										__( 'Add %d users', 'teksecurity' ),
										available.length
								  )
								: __( 'Add user', 'teksecurity' ) }
						</button>
					</Card>

					<Card title={ __( 'Sign-in methods', 'teksecurity' ) } flush>
						{ [
							[
								'app',
								__( 'Authenticator app', 'teksecurity' ),
								__(
									'Google Authenticator, 1Password, Authy and similar apps.',
									'teksecurity'
								),
								'ph-device-mobile',
							],
							[
								'email',
								__( 'Email code', 'teksecurity' ),
								__(
									'Sends a code to the account’s email address.',
									'teksecurity'
								),
								'ph-envelope-simple',
							],
							[
								'backup',
								__( 'Backup codes', 'teksecurity' ),
								__(
									'Ten one-time codes for when the phone isn’t available.',
									'teksecurity'
								),
								'ph-list-numbers',
							],
						].map( ( [ key, name, desc, icon ] ) => (
							<div className="ts-row" key={ key }>
								<Icon name={ icon.replace( 'ph-', '' ) } size={ 18 } />
								<div className="ts-row__grow">
									<div className="ts-row__title">{ name }</div>
									<div className="ts-row__desc">{ desc }</div>
								</div>
								<Switch
									label={ name }
									checked={ !! data.methods[ key ] }
									onChange={ ( value ) =>
										save( {
											methods: { [ key ]: value },
										} )
									}
								/>
							</div>
						) ) }

						<div className="ts-row">
							<div className="ts-field-grid ts-row__grow">
								<label className="ts-field">
									{ __( 'Time to set it up', 'teksecurity' ) }
									<select
										className="ts-select"
										value={ data.grace }
										onChange={ ( event ) =>
											save( {
												grace: event.target.value,
											} )
										}
									>
										<option value="0">
											{ __(
												'None, required at next sign-in',
												'teksecurity'
											) }
										</option>
										<option value="3">
											{ __( '3 days', 'teksecurity' ) }
										</option>
										<option value="7">
											{ __( '7 days', 'teksecurity' ) }
										</option>
										<option value="14">
											{ __( '14 days', 'teksecurity' ) }
										</option>
									</select>
								</label>

								{ isAdv && (
									<label className="ts-field">
										{ __(
											'Remember trusted devices',
											'teksecurity'
										) }
										<select
											className="ts-select"
											value={ data.remember }
											onChange={ ( event ) =>
												save( {
													remember:
														event.target.value,
												} )
											}
										>
											<option value="0">
												{ __(
													'Never, ask every time',
													'teksecurity'
												) }
											</option>
											<option value="7">
												{ __(
													'7 days',
													'teksecurity'
												) }
											</option>
											<option value="30">
												{ __(
													'30 days',
													'teksecurity'
												) }
											</option>
										</select>
									</label>
								) }
							</div>
						</div>
					</Card>
				</div>

				<Card
					title={ __( 'Users with two-factor', 'teksecurity' ) }
					action={
						<Chips
							value={ filter }
							onChange={ setFilter }
							options={ [
								[
									'all',
									sprintf(
										/* translators: %d: number of users. */
										__( 'All (%d)', 'teksecurity' ),
										required.length
									),
								],
								[
									'missing',
									sprintf(
										/* translators: %d: number of users. */
										__( 'Not set up (%d)', 'teksecurity' ),
										data.missing
									),
								],
							] }
						/>
					}
					flush
				>
					{ rows.length ? (
						rows.map( ( user ) => {
							const configured = user.status !== 'none';
							const methodLabel =
								user.status === 'app'
									? __( 'Authenticator app', 'teksecurity' )
									: __( 'Email code', 'teksecurity' );

							const note = configured
								? __( 'Set up', 'teksecurity' )
								: user.dueAt
								? sprintf(
										/* translators: %s: formatted date. */
										__(
											'Must set up by %s',
											'teksecurity'
										),
										new Date(
											user.dueAt
										).toLocaleDateString( undefined, {
											month: 'short',
											day: 'numeric',
										} )
								  )
								: __(
										'Can’t sign in until set up',
										'teksecurity'
								  );

							return (
								<div className="ts-row" key={ user.id }>
									<span className="ts-avatar">
										{ user.initials }
									</span>
									<div className="ts-row__grow">
										<div className="ts-row__title">
											{ user.name }
											{ user.self && (
												<span
													style={ {
														color: 'var(--ts-t3)',
														fontWeight: 400,
													} }
												>
													{ ' ' }
													{ __(
														'(you)',
														'teksecurity'
													) }
												</span>
											) }
										</div>
										<div className="ts-row__desc">
											{ user.roleName } · { note }
										</div>
									</div>

									<StatusPill
										tone={ configured ? 'ok' : 'warn' }
										label={
											configured
												? methodLabel
												: __(
														'Not set up',
														'teksecurity'
												  )
										}
									/>

									{ ! configured && user.self && (
										<button
											type="button"
											className="ts-button ts-button--primary ts-button--small"
											onClick={ beginSetup }
										>
											{ __( 'Set up', 'teksecurity' ) }
										</button>
									) }

									{ ! configured && ! user.self && (
										<button
											type="button"
											className="ts-button ts-button--small"
											disabled={ user.reminded }
											onClick={ () =>
												userAction(
													`/twofa/users/${ user.id }/remind`,
													sprintf(
														/* translators: %s: email address. */
														__(
															'Reminder sent to %s',
															'teksecurity'
														),
														user.email
													)
												)
											}
										>
											{ user.reminded
												? __(
														'Reminder sent',
														'teksecurity'
												  )
												: __(
														'Send reminder',
														'teksecurity'
												  ) }
										</button>
									) }

									{ configured && isAdv && (
										<button
											type="button"
											className="ts-button ts-button--small ts-button--danger"
											onClick={ () =>
												userAction(
													`/twofa/users/${ user.id }/reset`,
													sprintf(
														/* translators: %s: first name. */
														__(
															'Two-factor reset for %s',
															'teksecurity'
														),
														user.name.split(
															' '
														)[ 0 ]
													)
												)
											}
										>
											{ __( 'Reset', 'teksecurity' ) }
										</button>
									) }

									<button
										type="button"
										className="ts-icon-button"
										title={ __(
											'Remove from two-factor',
											'teksecurity'
										) }
										aria-label={ sprintf(
											/* translators: %s: user name. */
											__(
												'Remove %s from two-factor',
												'teksecurity'
											),
											user.name
										) }
										onClick={ () => removeUser( user ) }
									>
										<Icon name="x" />
									</button>
								</div>
							);
						} )
					) : (
						<div className="ts-inline-empty">
							{ ! required.length
								? __(
										'No users added yet. Pick a role and a user to get started.',
										'teksecurity'
								  )
								: __(
										'Everyone added has set up two-factor.',
										'teksecurity'
								  ) }
						</div>
					) }
				</Card>
			</div>

			{ setup && (
				<TwoFactorModal
					setup={ setup }
					toast={ toast }
					onClose={ () => setSetup( null ) }
					onDone={ async () => {
						setSetup( null );
						await load();
						refresh();
						toast(
							__(
								'Two-factor is on for your account',
								'teksecurity'
							)
						);
					} }
				/>
			) }
		</div>
	);
}
