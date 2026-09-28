/**
 * Traffic log screen.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import { api, boot } from '../lib/api';
import { logTime } from '../lib/format';
import {
	Chips,
	EmptyState,
	Loading,
	StatusPill,
} from '../components/primitives';
import Icon from '../components/Icon';

const PER_PAGE = 12;

/**
 * The searchable log of every blocked or logged request.
 *
 * @param {Object}   props           Component props.
 * @param {boolean}  props.isAdv     Whether advanced view is on.
 * @param {Object}   props.filters   Initial filters from the route.
 * @param {number}   props.openId    Event id the drawer is showing.
 * @param {Function} props.openEvent Open the drawer.
 * @param {Function} props.toast     Show a toast.
 * @return {JSX.Element} The screen.
 */
export default function Traffic( {
	isAdv,
	filters,
	openId,
	openEvent,
	toast,
} ) {
	const [ search, setSearch ] = useState( filters.search || '' );
	const [ action, setAction ] = useState( filters.action || 'all' );
	const [ type, setType ] = useState( filters.type || 'all' );
	const [ page, setPage ] = useState( 0 );
	const [ data, setData ] = useState( null );
	const [ debounced, setDebounced ] = useState( search );

	useEffect( () => {
		const timer = setTimeout( () => setDebounced( search ), 250 );
		return () => clearTimeout( timer );
	}, [ search ] );

	useEffect( () => {
		let cancelled = false;

		api.get( '/traffic', {
			search: debounced,
			action,
			type,
			page,
			per_page: PER_PAGE,
		} )
			.then( ( next ) => {
				if ( ! cancelled ) {
					setData( next );
				}
			} )
			.catch( ( error ) => toast( error.message, 'error' ) );

		return () => {
			cancelled = true;
		};
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ debounced, action, type, page ] );

	const reset = () => {
		setSearch( '' );
		setAction( 'all' );
		setType( 'all' );
		setPage( 0 );
	};

	const isFiltered = search !== '' || action !== 'all' || type !== 'all';

	const columns = isAdv
		? '112px minmax(220px, 2fr) 150px 160px 110px 92px'
		: '120px minmax(240px, 2fr) 160px 180px 92px';

	const typeOptions = [
		[ 'all', __( 'All attack types', 'teksecurity' ) ],
		...Object.entries( boot.types ).map( ( [ key, value ] ) => [
			key,
			value.label,
		] ),
	];

	return (
		<div className="ts-stack">
			<div className="ts-filters">
				<div className="ts-search">
					<Icon name="magnifying-glass" />
					<input
						type="search"
						className="ts-input"
						value={ search }
						placeholder={ __(
							'Search IP, path or attack',
							'teksecurity'
						) }
						aria-label={ __(
							'Search the traffic log',
							'teksecurity'
						) }
						onChange={ ( event ) => {
							setSearch( event.target.value );
							setPage( 0 );
						} }
					/>
					{ search && (
						<button
							type="button"
							className="ts-search__clear"
							aria-label={ __( 'Clear search', 'teksecurity' ) }
							onClick={ () => {
								setSearch( '' );
								setPage( 0 );
							} }
						>
							<Icon name="x" weight="bold" />
						</button>
					) }
				</div>

				<Chips
					value={ action }
					onChange={ ( next ) => {
						setAction( next );
						setPage( 0 );
					} }
					options={ [
						[ 'all', __( 'All', 'teksecurity' ) ],
						[ 'blocked', __( 'Blocked', 'teksecurity' ) ],
						[ 'logged', __( 'Logged', 'teksecurity' ) ],
					] }
				/>

				<select
					className="ts-select"
					style={ { width: 'auto' } }
					value={ type }
					aria-label={ __( 'Filter by attack type', 'teksecurity' ) }
					onChange={ ( event ) => {
						setType( event.target.value );
						setPage( 0 );
					} }
				>
					{ typeOptions.map( ( [ key, label ] ) => (
						<option key={ key } value={ key }>
							{ label }
						</option>
					) ) }
				</select>

				{ isFiltered && (
					<button
						type="button"
						className="ts-link-button"
						onClick={ reset }
					>
						{ __( 'Clear all', 'teksecurity' ) }
					</button>
				) }
			</div>

			{ ! data && <Loading /> }

			{ data && data.rows.length > 0 && (
				<div className="ts-table">
					<div className="ts-table__grid">
						<div
							className="ts-table__head"
							style={ { gridTemplateColumns: columns } }
						>
							<span>{ __( 'Time', 'teksecurity' ) }</span>
							<span>{ __( 'Request', 'teksecurity' ) }</span>
							<span>{ __( 'Attack', 'teksecurity' ) }</span>
							<span>{ __( 'Source', 'teksecurity' ) }</span>
							{ isAdv && (
								<span>{ __( 'Rule', 'teksecurity' ) }</span>
							) }
							<span>{ __( 'Action', 'teksecurity' ) }</span>
						</div>

						{ data.rows.map( ( row ) => (
							<button
								type="button"
								key={ row.id }
								className={ `ts-table__row${
									openId === row.id
										? ' ts-table__row--active'
										: ''
								}` }
								style={ { gridTemplateColumns: columns } }
								onClick={ () => openEvent( row.id ) }
							>
								<span className="ts-cell-time">
									{ logTime( row.createdAt ) }
								</span>
								<span className="ts-cell-path">
									<b>{ row.method }</b> { row.path }
								</span>
								<span>
									<span
										className="ts-tag"
										style={ {
											background: 'var(--ts-dv)',
											color: 'var(--ts-t2)',
										} }
									>
										{ boot.types[ row.type ]?.label ||
											row.type }
									</span>
								</span>
								<span>
									<span className="ts-cell-ip">
										{ row.ip }
									</span>{ ' ' }
									{ row.country && (
										<span className="ts-cell-cc">
											{ row.country }
										</span>
									) }
								</span>
								{ isAdv && (
									<span className="ts-cell-rule">
										{ row.ruleId }
									</span>
								) }
								<span>
									<StatusPill
										tone={
											row.action === 'blocked'
												? 'bad'
												: 'warn'
										}
										label={
											row.action === 'blocked'
												? __( 'Blocked', 'teksecurity' )
												: __( 'Logged', 'teksecurity' )
										}
									/>
								</span>
							</button>
						) ) }
					</div>
				</div>
			) }

			{ data && data.rows.length === 0 && (
				<EmptyState
					icon="ph-funnel-x"
					title={
						isFiltered
							? __(
									'No requests match these filters',
									'teksecurity'
							  )
							: __( 'Nothing has been logged yet', 'teksecurity' )
					}
					desc={
						isFiltered
							? __(
									'Try a different IP, path or attack type.',
									'teksecurity'
							  )
							: __(
									'Blocked and logged requests will appear here as they happen.',
									'teksecurity'
							  )
					}
				>
					{ isFiltered && (
						<button
							type="button"
							className="ts-button"
							style={ { marginTop: 10 } }
							onClick={ reset }
						>
							{ __( 'Reset filters', 'teksecurity' ) }
						</button>
					) }
				</EmptyState>
			) }

			{ data && data.total > 0 && (
				<div className="ts-pagination">
					<span>
						{ sprintf(
							/* translators: 1: first row, 2: last row, 3: total rows. */
							__( '%1$d–%2$d of %3$d requests', 'teksecurity' ),
							page * PER_PAGE + 1,
							Math.min( data.total, ( page + 1 ) * PER_PAGE ),
							data.total
						) }
					</span>
					<div className="ts-pagination__buttons">
						<button
							type="button"
							className="ts-button ts-button--small"
							disabled={ page === 0 }
							aria-label={ __( 'Previous page', 'teksecurity' ) }
							onClick={ () => setPage( Math.max( 0, page - 1 ) ) }
						>
							<Icon name="caret-left" />
						</button>
						<button
							type="button"
							className="ts-button ts-button--small"
							disabled={ page >= data.totalPages - 1 }
							aria-label={ __( 'Next page', 'teksecurity' ) }
							onClick={ () => setPage( page + 1 ) }
						>
							<Icon name="caret-right" />
						</button>
					</div>
				</div>
			) }
		</div>
	);
}
