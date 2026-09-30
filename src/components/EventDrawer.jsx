/**
 * The request drawer opened from any log row.
 */

import { Fragment, useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api } from '../lib/api';
import { fullTime } from '../lib/format';
import { AttackTag, Loading, StatusPill } from './primitives';
import Icon from './Icon';

/**
 * Everything known about one blocked or logged request.
 *
 * @param {Object}   props           Component props.
 * @param {number}   props.eventId   Event id.
 * @param {boolean}  props.isAdv     Whether advanced view is on.
 * @param {Function} props.onClose   Close the drawer.
 * @param {Function} props.onViewIp  Filter the log by this IP.
 * @param {Function} props.toast     Show a toast.
 * @return {JSX.Element} The drawer.
 */
export default function EventDrawer( {
	eventId,
	isAdv,
	onClose,
	onViewIp,
	toast,
} ) {
	const [ event, setEvent ] = useState( null );
	const [ blocked, setBlocked ] = useState( false );
	const [ excluded, setExcluded ] = useState( false );

	useEffect( () => {
		setEvent( null );
		setBlocked( false );
		setExcluded( false );

		api.get( `/traffic/${ eventId }` )
			.then( setEvent )
			.catch( ( error ) => {
				toast( error.message, 'error' );
				onClose();
			} );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ eventId ] );

	useEffect( () => {
		const onKey = ( keyEvent ) => {
			if ( keyEvent.key === 'Escape' ) {
				onClose();
			}
		};

		window.addEventListener( 'keydown', onKey );
		return () => window.removeEventListener( 'keydown', onKey );
	}, [ onClose ] );

	const blockIp = async () => {
		try {
			await api.post( '/ips', {
				list: 'block',
				ip: event.ip,
				note: sprintf(
					/* translators: %s: attack type label. */
					__( '%s, from traffic log', 'teksecurity' ),
					event.typeLabel
				),
			} );
			setBlocked( true );
			toast(
				sprintf(
					/* translators: %s: IP address. */
					__( '%s added to blocklist', 'teksecurity' ),
					event.ip
				)
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const excludeRule = async () => {
		try {
			await api.post( '/firewall/exclusions', {
				ruleId: event.ruleId,
				path: event.path.split( '?' )[ 0 ],
			} );
			setExcluded( true );
			toast(
				sprintf(
					/* translators: %s: rule identifier. */
					__( '%s skipped on this path', 'teksecurity' ),
					event.ruleId
				)
			);
		} catch ( error ) {
			toast( error.message, 'error' );
		}
	};

	const facts = event
		? [
				[
					__( 'IP address', 'teksecurity' ),
					event.country
						? `${ event.ip } (${ event.country })`
						: event.ip,
				],
				[ __( 'Page', 'teksecurity' ), event.path.split( '?' )[ 0 ] ],
				[ __( 'Protection', 'teksecurity' ), event.moduleName ],
				[
					__( 'Result', 'teksecurity' ),
					event.action === 'blocked'
						? __( 'Blocked with 403', 'teksecurity' )
						: __( 'Allowed, logged for review', 'teksecurity' ),
				],
		  ]
		: [];

	const technical = event
		? [
				[
					__( 'Method and URL', 'teksecurity' ),
					`${ event.method } ${ event.path }`,
				],
				[ __( 'Matched in', 'teksecurity' ), event.matchedIn ],
				[ __( 'Payload', 'teksecurity' ), event.payload ],
				[
					__( 'Rule', 'teksecurity' ),
					`${ event.ruleId } · ${ event.ruleName }`,
				],
				[ __( 'User agent', 'teksecurity' ), event.userAgent ],
		  ]
		: [];

	return (
		<div className="ts-overlay">
			<button
				type="button"
				className="ts-overlay__scrim"
				aria-label={ __( 'Close', 'teksecurity' ) }
				onClick={ onClose }
			/>
			<aside
				className="ts-drawer"
				role="dialog"
				aria-modal="true"
				aria-label={ __( 'Request details', 'teksecurity' ) }
			>
				{ ! event ? (
					<Loading />
				) : (
					<>
						<header className="ts-drawer__head">
							<div className="ts-row__grow">
								<div className="ts-drawer__badges">
									<AttackTag
										type={ event.type }
										label={ event.typeLabel }
									/>
									<StatusPill
										tone={
											event.action === 'blocked'
												? 'bad'
												: 'warn'
										}
										label={
											event.action === 'blocked'
												? __( 'Blocked', 'teksecurity' )
												: __( 'Logged', 'teksecurity' )
										}
									/>
								</div>
								<div className="ts-drawer__rule">
									{ event.ruleName }
								</div>
								<div className="ts-drawer__time">
									{ fullTime( event.createdAt ) }
								</div>
							</div>
							<button
								type="button"
								className="ts-icon-button"
								aria-label={ __( 'Close', 'teksecurity' ) }
								onClick={ onClose }
							>
								<Icon name="x" />
							</button>
						</header>

						<div className="ts-drawer__body">
							<p className="ts-drawer__explain">
								{ event.explain }
							</p>

							<dl className="ts-kv">
								{ facts.map( ( [ key, value ] ) => (
									<Fragment key={ key }>
										<dt>{ key }</dt>
										<dd>{ value }</dd>
									</Fragment>
								) ) }
							</dl>

							{ isAdv && (
								<div className="ts-tech">
									<div className="ts-tech__title">
										{ __( 'Request', 'teksecurity' ) }
									</div>
									{ technical.map( ( [ key, value ] ) => (
										<div
											className="ts-tech__row"
											key={ key }
										>
											<div className="ts-tech__key">
												{ key }
											</div>
											<div className="ts-tech__value">
												{ value || '—' }
											</div>
										</div>
									) ) }
								</div>
							) }
						</div>

						<footer className="ts-drawer__foot">
							<button
								type="button"
								className="ts-button"
								onClick={ () => onViewIp( event.ip ) }
							>
								{ __( 'All from this IP', 'teksecurity' ) }
							</button>

							{ isAdv && (
								<button
									type="button"
									className="ts-button"
									disabled={ excluded }
									onClick={ excludeRule }
								>
									{ excluded
										? __( 'Rule excluded', 'teksecurity' )
										: __(
												'Exclude rule here',
												'teksecurity'
										  ) }
								</button>
							) }

							<button
								type="button"
								className="ts-button ts-button--primary"
								disabled={ blocked }
								onClick={ blockIp }
							>
								{ blocked
									? __( 'IP is on blocklist', 'teksecurity' )
									: __( 'Block this IP', 'teksecurity' ) }
							</button>
						</footer>
					</>
				) }
			</aside>
		</div>
	);
}
