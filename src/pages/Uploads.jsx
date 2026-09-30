/**
 * File uploads screen.
 */

import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

import { api } from '../lib/api';
import { useResource } from '../lib/useResource';
import { timeAgo } from '../lib/format';
import {
	Card,
	Loading,
	ModuleHeader,
	SettingRow,
	Switch,
} from '../components/primitives';
import Icon from '../components/Icon';

/**
 * Upload filtering rules and the recent rejections.
 *
 * @param {Object}   props           Component props.
 * @param {boolean}  props.isAdv     Whether advanced view is on.
 * @param {Function} props.openEvent Open the request drawer.
 * @param {Function} props.toast     Show a toast.
 * @param {Function} props.refresh   Refresh the shell's badges.
 * @return {JSX.Element} The screen.
 */
export default function Uploads( { isAdv, openEvent, toast, refresh } ) {
	const { data, save, mutate } = useResource( '/uploads', {
		toast,
		refresh,
	} );
	const [ newExt, setNewExt ] = useState( '' );
	const [ extError, setExtError ] = useState( '' );

	if ( ! data ) {
		return <Loading />;
	}

	// The extension field reports its own errors beside the input, so this one
	// opts out of the toast.
	const addExtension = async () => {
		try {
			await mutate(
				() => api.post( '/uploads/extensions', { ext: newExt } ),
				{
					inline: true,
				}
			);
			setNewExt( '' );
			setExtError( '' );
		} catch ( error ) {
			setExtError( error.message );
		}
	};

	const removeExtension = ( ext ) =>
		mutate( () => api.del( '/uploads/extensions', { ext } ) );

	return (
		<div className="ts-stack">
			<ModuleHeader
				icon="upload-simple"
				name={ __( 'File-upload protection', 'teksecurity' ) }
				stopped={ data.stopped }
				enabled={ data.enabled }
				onToggle={ ( enabled ) =>
					save(
						{ enabled },
						enabled
							? __(
									'File-upload protection turned on',
									'teksecurity'
							  )
							: __(
									'File-upload protection turned off',
									'teksecurity'
							  )
					)
				}
			/>

			<Card title={ __( 'Blocked file types', 'teksecurity' ) } flush>
				<div className="ts-card__body">
					<p className="ts-row__desc" style={ { marginTop: 0 } }>
						{ __(
							'Checked on the real extension, including double extensions like invoice.pdf.php.',
							'teksecurity'
						) }
					</p>
					<div className="ts-ext-list" style={ { marginTop: 12 } }>
						{ data.extensions.map( ( ext ) => (
							<span className="ts-ext" key={ ext }>
								.{ ext }
								{ isAdv && (
									<button
										type="button"
										aria-label={ `Remove .${ ext }` }
										onClick={ () => removeExtension( ext ) }
									>
										<Icon name="x" weight="bold" />
									</button>
								) }
							</span>
						) ) }
					</div>

					{ isAdv && (
						<div style={ { marginTop: 14 } }>
							<div className="ts-inline-form">
								<input
									className={ `ts-input${
										extError ? ' ts-input--error' : ''
									}` }
									value={ newExt }
									placeholder={ __(
										'Add extension, e.g. pht',
										'teksecurity'
									) }
									aria-label={ __(
										'Add a blocked extension',
										'teksecurity'
									) }
									onChange={ ( event ) => {
										setNewExt( event.target.value );
										setExtError( '' );
									} }
									onKeyDown={ ( event ) => {
										if ( event.key === 'Enter' ) {
											addExtension();
										}
									} }
								/>
								<button
									type="button"
									className="ts-button"
									onClick={ addExtension }
								>
									{ __( 'Add', 'teksecurity' ) }
								</button>
							</div>
							{ extError && (
								<div className="ts-hint ts-hint--error ts-inline-error">
									{ extError }
								</div>
							) }
						</div>
					) }
				</div>

				<SettingRow
					title={ __( 'Scan file contents', 'teksecurity' ) }
					desc={ __(
						'Finds PHP hidden inside images and documents.',
						'teksecurity'
					) }
				>
					<Switch
						label={ __( 'Scan file contents', 'teksecurity' ) }
						checked={ data.scan }
						onChange={ ( scan ) => save( { scan } ) }
					/>
				</SettingRow>

				<SettingRow
					title={ __( 'Clean SVG uploads', 'teksecurity' ) }
					desc={ __(
						'Removes embedded code from SVG files before they are saved.',
						'teksecurity'
					) }
				>
					<Switch
						label={ __( 'Clean SVG uploads', 'teksecurity' ) }
						checked={ data.svg }
						onChange={ ( svg ) => save( { svg } ) }
					/>
				</SettingRow>

				<SettingRow
					title={ __(
						'Check form uploads from visitors',
						'teksecurity'
					) }
					desc={ __(
						'Applies these checks to files sent through contact and checkout forms.',
						'teksecurity'
					) }
				>
					<Switch
						label={ __(
							'Check form uploads from visitors',
							'teksecurity'
						) }
						checked={ data.guests }
						onChange={ ( guests ) => save( { guests } ) }
					/>
				</SettingRow>
			</Card>

			<Card
				title={ __( 'Recently blocked uploads', 'teksecurity' ) }
				flush
			>
				{ data.recent.length ? (
					data.recent.map( ( event ) => (
						<button
							type="button"
							key={ event.id }
							className="ts-list-button"
							onClick={ () => openEvent( event.id ) }
						>
							<Icon
								name="file-x"
								size={ 17 }
								style={ { color: 'var(--ts-bad-dot)' } }
							/>
							<span className="ts-row__grow">
								<span className="ts-list-button__primary">
									{ event.payload }
								</span>
								<span className="ts-list-button__time">
									{ event.ip } ·{ ' ' }
									{ timeAgo( event.createdAt ) }
								</span>
							</span>
							<Icon
								name="caret-right"
								className="ts-list-button__chevron"
							/>
						</button>
					) )
				) : (
					<div className="ts-inline-empty">
						{ __(
							'No uploads have been rejected yet.',
							'teksecurity'
						) }
					</div>
				) }
			</Card>
		</div>
	);
}
