/**
 * The three-step enrolment modal for the signed-in user.
 */

import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import QRCode from 'qrcode';

import { api } from '../lib/api';
import Icon from './Icon';

/**
 * The otpauth URI drawn as a scannable QR code.
 *
 * The secret never leaves the page as an image request: the code is rendered
 * locally to a data URL.
 *
 * @param {Object} props     Component props.
 * @param {string} props.uri otpauth:// URI.
 * @return {JSX.Element} The QR image.
 */
function QrCode( { uri } ) {
	const [ src, setSrc ] = useState( '' );

	useEffect( () => {
		let cancelled = false;

		QRCode.toDataURL( uri, {
			width: 336,
			margin: 1,
			errorCorrectionLevel: 'M',
		} )
			.then( ( url ) => {
				if ( ! cancelled ) {
					setSrc( url );
				}
			} )
			.catch( () => {} );

		return () => {
			cancelled = true;
		};
	}, [ uri ] );

	if ( ! src ) {
		return (
			<div className="ts-qr">
				<div
					style={ {
						width: 168,
						height: 168,
						display: 'flex',
						alignItems: 'center',
						justifyContent: 'center',
						color: '#646c73',
					} }
				>
					<Icon name="qr-code" size={ 44 } />
				</div>
			</div>
		);
	}

	return (
		<div className="ts-qr">
			<img src={ src } alt={ __( 'Two-factor QR code', 'teksecurity' ) } />
		</div>
	);
}

/**
 * The enrolment modal.
 *
 * @param {Object}   props           Component props.
 * @param {Object}   props.setup     Payload from POST /twofa/setup.
 * @param {Function} props.onClose   Close without finishing.
 * @param {Function} props.onDone    Called once enrolment is complete.
 * @param {Function} props.toast     Show a toast.
 * @return {JSX.Element} The modal.
 */
export default function TwoFactorModal( { setup, onClose, onDone, toast } ) {
	const [ step, setStep ] = useState( 1 );
	const [ code, setCode ] = useState( '' );
	const [ error, setError ] = useState( '' );
	const [ codes, setCodes ] = useState( [] );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		const onKey = ( event ) => {
			if ( event.key === 'Escape' ) {
				onClose();
			}
		};

		window.addEventListener( 'keydown', onKey );
		return () => window.removeEventListener( 'keydown', onKey );
	}, [ onClose ] );

	const titles = [
		__( 'Scan the QR code', 'teksecurity' ),
		__( 'Enter the code', 'teksecurity' ),
		__( 'Save your backup codes', 'teksecurity' ),
	];

	const verify = async () => {
		setBusy( true );

		try {
			await api.post( '/twofa/setup/verify', { code } );

			if ( setup.steps === 2 ) {
				onDone();
				return;
			}

			const result = await api.post( '/twofa/backup-codes' );
			setCodes( result.codes );
			setStep( 3 );
			setError( '' );
		} catch ( verifyError ) {
			setError( verifyError.message );
		} finally {
			setBusy( false );
		}
	};

	const primary = () => {
		if ( step === 1 ) {
			setStep( 2 );
			return;
		}

		if ( step === 2 ) {
			verify();
			return;
		}

		onDone();
	};

	const copyCodes = async () => {
		try {
			await navigator.clipboard.writeText( codes.join( '\n' ) );
			toast( __( 'Backup codes copied', 'teksecurity' ) );
		} catch ( copyError ) {
			toast(
				__(
					'Could not copy. Select the codes and copy them by hand.',
					'teksecurity'
				),
				'error'
			);
		}
	};

	return (
		<div className="ts-overlay">
			<button
				type="button"
				className="ts-overlay__scrim"
				aria-label={ __( 'Close', 'teksecurity' ) }
				onClick={ onClose }
			/>
			<div
				className="ts-modal"
				role="dialog"
				aria-modal="true"
				aria-label={ titles[ step - 1 ] }
			>
				<header className="ts-modal__head">
					<div>
						<div className="ts-modal__step">
							{ sprintf(
								/* translators: 1: current step, 2: total steps. */
								__( 'Step %1$d of %2$d', 'teksecurity' ),
								step,
								setup.steps
							) }
						</div>
						<div className="ts-modal__title">
							{ titles[ step - 1 ] }
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

				<div className="ts-modal__body">
					{ step === 1 && (
						<>
							<p className="ts-drawer__explain">
								{ __(
									'Open your authenticator app and scan this code.',
									'teksecurity'
								) }
							</p>
							<QrCode uri={ setup.uri } />
							<div
								className="ts-hint"
								style={ { textAlign: 'center' } }
							>
								{ __(
									'Can’t scan it? Enter this key in the app instead.',
									'teksecurity'
								) }
							</div>
							<div className="ts-secret">
								{ setup.prettySecret }
							</div>
						</>
					) }

					{ step === 2 && (
						<label className="ts-field">
							{ __(
								'6-digit code from your app',
								'teksecurity'
							) }
							<input
								className={ `ts-input${
									error ? ' ts-input--error' : ''
								}` }
								inputMode="numeric"
								autoComplete="one-time-code"
								placeholder="000000"
								value={ code }
								// eslint-disable-next-line jsx-a11y/no-autofocus
								autoFocus
								onChange={ ( event ) => {
									setCode(
										event.target.value
											.replace( /\D/g, '' )
											.slice( 0, 6 )
									);
									setError( '' );
								} }
								onKeyDown={ ( event ) => {
									if ( event.key === 'Enter' ) {
										verify();
									}
								} }
							/>
							<span
								className={ `ts-hint${
									error ? ' ts-hint--error' : ''
								}` }
							>
								{ error ||
									__(
										'The code refreshes every 30 seconds.',
										'teksecurity'
									) }
							</span>
						</label>
					) }

					{ step === 3 && (
						<>
							<p className="ts-drawer__explain">
								{ __(
									'Use one of these if you lose your phone. Each code works once. Keep them somewhere safe.',
									'teksecurity'
								) }
							</p>
							<div className="ts-codes">
								{ codes.map( ( backup ) => (
									<span key={ backup }>{ backup }</span>
								) ) }
							</div>
						</>
					) }
				</div>

				<footer className="ts-modal__foot">
					{ step === 2 && (
						<button
							type="button"
							className="ts-button"
							onClick={ () => {
								setStep( 1 );
								setError( '' );
							} }
						>
							{ __( 'Back', 'teksecurity' ) }
						</button>
					) }
					{ step === 3 && (
						<button
							type="button"
							className="ts-button"
							onClick={ copyCodes }
						>
							<Icon name="copy" />
							{ __( 'Copy codes', 'teksecurity' ) }
						</button>
					) }
					<button
						type="button"
						className="ts-button ts-button--primary"
						disabled={ busy }
						onClick={ primary }
					>
						{ step === 1
							? __( 'I’ve scanned it', 'teksecurity' )
							: step === 2
							? __( 'Verify', 'teksecurity' )
							: __( 'I’ve saved them', 'teksecurity' ) }
					</button>
				</footer>
			</div>
		</div>
	);
}
