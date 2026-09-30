/**
 * The only script TekSecurity loads on wp-login.php.
 *
 * It draws the enrolment QR code in the browser, so the shared secret is never
 * handed to a third-party image service.
 */

import QRCode from 'qrcode';

document.addEventListener( 'DOMContentLoaded', () => {
	document.querySelectorAll( '[data-teksec-otpauth]' ).forEach( ( node ) => {
		const uri = node.getAttribute( 'data-teksec-otpauth' );

		if ( ! uri ) {
			return;
		}

		QRCode.toDataURL( uri, {
			width: 360,
			margin: 1,
			errorCorrectionLevel: 'M',
		} )
			.then( ( src ) => {
				const img = document.createElement( 'img' );
				img.src = src;
				img.width = 180;
				img.height = 180;
				img.alt = '';
				node.appendChild( img );
			} )
			.catch( () => {
				// The manual entry key is printed underneath, so a failure
				// here leaves the user a way through.
			} );
	} );
} );
