/**
 * Mounts the TekSecurity admin app.
 */

import { createRoot } from '@wordpress/element';

import App from './app';
import './styles/admin.css';

const container = document.getElementById( 'teksecurity-root' );

if ( container ) {
	createRoot( container ).render( <App /> );
}
