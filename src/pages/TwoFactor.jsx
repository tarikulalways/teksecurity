/**
 * Two-factor authentication screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { useResource } from '../lib/useResource';
import {
	Card,
	Chips,
	Loading,
	ModuleHeader,
	SelectField,
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
	const { data, setData, reload, save, mutate } = useResource( '/twofa', {
		toast,
		refresh,
	} );
	const [ roles, setRoles ] = useState( [] );
	const [ role, setRole ] = useState( '' );
	const [ available, setAvailable ] = useState( [] );
	const [ pick, setPick ] = useState( '' );
	const [ filter, setFilter ] = useState( 'all' );
	const [ setup, setSetup ] = useState( null );

	useEffect( () => {
		api.get( '/twofa/roles' )
			.then( setRoles )
			.catch( ( error ) => toast( error.message, 'error' ) );
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

	const addUsers = async () => {
		const ids =
			pick === 'all'
				? available.map( ( user ) => user.id )
				: [ Number( pick ) ];

		const done = await mutate(
			() => api.post( '/twofa/users', { userIds: ids } ),
			{
				message:
					ids.length > 1
						? sprintf(
								/* translators: %d: number of users added. */
								__( '%d users added', 'teksecurity' ),
								ids.length
						  )
						: sprintf(
								/* translators: %s: user name. */
								__(
									'%s must now use two-factor',
									'teksecurity'
								),
								available.find(
									( user ) => user.id === ids[ 0 ]
								)?.name || ''
						  ),
			}
		);

		if ( done ) {
			setPick( '' );
			setFilter( 'all' );
		}
	};

	const userAction = ( path, message ) =>
		mutate( () => api.post( path ), { message } );

	const removeUser = ( user ) =>
		mutate( () => api.del( `/twofa/users/${ user.id }` ), {
			message: sprintf(
				/* translators: %s: user name. */
				__( '%s no longer needs two-factor', 'teksecurity' ),
				user.name
			),
		} );

	const beginSetup = async () => {
		try {
			const result = await api.post( '/twofa/setup' );

			if ( result.done ) {
				await reload();
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
			<ModuleHeader
				icon="device-mobile"
				name={ __( 'Two-factor authentication', 'teksecurity' ) }
				desc={ summary }
				enabled={ data.enabled }
				toggleLabel={ __( 'Turn two-factor on or off', 'teksecurity' ) }
				onToggle={ ( enabled ) =>
					save(
						{ enabled },
						enabled
							? __( 'Two-factor turned on', 'teksecurity' )
							: __( 'Two-factor turned off', 'teksecurity' )
					)
				}
			/>

			<div className={ `ts-split${ data.enabled ? '' : ' ts-dim' }` }>
				<div className="ts-stack">
					<Card title={ __( 'Add users', 'teksecurity' ) }>
						<div className="ts-stack">
							<p className="ts-row__desc ts-flush">
								{ __(
									'Choose a role to load its users, then pick who must use two-factor.',
									'teksecurity'
								) }
							</p>
							<div className="ts-field-grid">
								<SelectField
									label={ __( 'Role', 'teksecurity' ) }
									value={ role }
									onChange={ setRole }
									options={ [
										[
											'',
											__(
												'Select a role',
												'teksecurity'
											),
										],
										...roles.map( ( item ) => [
											item.key,
											sprintf(
												/* translators: 1: role name, 2: number of users. */
												_n(
													'%1$s · %2$d user',
													'%1$s · %2$d users',
													item.users,
													'teksecurity'
												),
												item.name,
												item.users
											),
										] ),
									] }
								/>

								<SelectField
									label={ __( 'User', 'teksecurity' ) }
									value={ pick }
									onChange={ setPick }
									disabled={ ! available.length }
									options={ pickOptions }
								/>
							</div>

							<button
								type="button"
								className="ts-button ts-button--primary ts-self-start"
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
						</div>
					</Card>

					<Card
						title={ __( 'Sign-in methods', 'teksecurity' ) }
						flush
					>
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
								<Icon
									name={ icon.replace( 'ph-', '' ) }
									size={ 18 }
								/>
								<div className="ts-row__grow">
									<div className="ts-row__title">
										{ name }
									</div>
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
								<SelectField
									label={ __(
										'Time to set it up',
										'teksecurity'
									) }
									value={ data.grace }
									onChange={ ( grace ) => save( { grace } ) }
									options={ [
										[
											'0',
											__(
												'None, required at next sign-in',
												'teksecurity'
											),
										],
										[ '3', __( '3 days', 'teksecurity' ) ],
										[ '7', __( '7 days', 'teksecurity' ) ],
										[
											'14',
											__( '14 days', 'teksecurity' ),
										],
									] }
								/>

								{ isAdv && (
									<SelectField
										label={ __(
											'Remember trusted devices',
											'teksecurity'
										) }
										value={ data.remember }
										onChange={ ( remember ) =>
											save( { remember } )
										}
										options={ [
											[
												'0',
												__(
													'Never, ask every time',
													'teksecurity'
												),
											],
											[
												'7',
												__( '7 days', 'teksecurity' ),
											],
											[
												'30',
												__( '30 days', 'teksecurity' ),
											],
										] }
									/>
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
												<span className="ts-muted">
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
						await reload();
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
