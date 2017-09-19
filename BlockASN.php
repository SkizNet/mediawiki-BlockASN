<?php

// extending User lets us modify protected fields (yes, it's hacky as shit)
class BlockASN extends User {
	public static function onGetBlockedStatus( &$user ) {
		global $wgBlockedASNs, $wgBlockedUserTypes, $wgBAApiField;

		if ( $user->isAllowed( 'ipblock-exempt' ) ) {
			return true;
		}

		$ip = $user->getRequest()->getIP();
		$data = self::getData( $ip );

		if ( $data !== -1 ) {
			$ret = $data;
			$fragments = explode( '.', $wgBAApiField['type'] );

			foreach ( $fragments as $f ) {
				if ( !isset( $ret[$f] ) ) {
					$ret = -1;
					break;
				}

				$ret = $ret[$f];
			}

			if ( $ret !== -1 && in_array( $ret, $wgBlockedUserTypes ) ) {
				$user->mBlock = new Block( [
					'address' => $ip,
					'byText' => 'MediaWiki default',
					'reason' => wfMessage( 'usertypeblockreason', $ret )->text(),
					'allowUsertalk' => true,
					'createAccount' => true, // this BLOCKS account creation
					'systemBlock' => 'usertype-block'
				] );
				$user->mBlockedby = $user->mBlock->getByName();
				$user->mBlockreason = $user->mBlock->mReason;
				$user->mHideName = $user->mBlock->mHideName;
				$user->mAllowUsertalk = !$user->mBlock->prevents( 'editownusertalk' );
				return true;
			}

			$ret = $data;
			$fragments = explode( '.', $wgBAApiField['asn'] );

			foreach ( $fragments as $f ) {
				if ( !isset( $ret[$f] ) ) {
					$ret = -1;
					break;
				}

				$ret = $ret[$f];
			}

			if ( $ret !== -1 && in_array( $ret, $wgBlockedASNs ) ) {
				$user->mBlock = new Block( [
					'address' => $ip,
					'byText' => 'MediaWiki default',
					'reason' => wfMessage( 'asnblockreason' )->text(),
					'allowUsertalk' => true,
					'createAccount' => true, // this BLOCKS account creation
					'systemBlock' => 'asn-block'
				] );
				$user->mBlockedby = $user->mBlock->getByName();
				$user->mBlockreason = $user->mBlock->mReason;
				$user->mHideName = $user->mBlock->mHideName;
				$user->mAllowUsertalk = !$user->mBlock->prevents( 'editownusertalk' );
				return true;
			}
		}

		return true;
	}

	private static function getData( $ip ) {
		return self::get_cached_result( $ip, 'insights' );
	}

	private static function get_cached_result( $ip, $db = 'country', $cached_only = false ) {
		// increment this to recache everything
		$cache_epoch = 1;

		// sanitized $db - we only allow country or insights for now
		// rewrite omni to insights as it was renamed
		if ( !in_array( $db, array( 'country', 'city', 'insights' ) ) ) {
			return array( 'error' => 'UNKNOWN_DATABASE' );
		}
		// first check memcached for the (ip, db) combo
		// results are cached for 1 week
		$cache = new Memcached();
		$cache->setOption( Memcached::OPT_COMPRESSION, false ); // compression bugs out sometimes
		$cache->addServer( '127.0.0.1', 11211 );
		$cached_data = $cache->get( "geoip_{$db}_" . sha1( $ip ) );

		if ( $cached_data === false || !isset( $cached_data['cache_epoch'] ) || $cached_data['cache_epoch'] < $cache_epoch ) {
			if ( $cached_only ) {
				return array( 'error' => 'NOT_IN_CACHE' );
			}
			$data = self::geoip_request( $ip, $db );
			// don't cache errors
			if ( !isset( $data['error'] ) || $data['error'] == '' ) {
				$data['cached_at'] = time();
				$data['cache_epoch'] = $cache_epoch;
				$cache->set( "geoip_{$db}_" . sha1( $ip ), $data, 60 * 60 * 24 * 7 );
				$cached_data = $data;
			} else {
				// error
				return $data;
			}
		}

		// unset fields we don't want to expose
		unset( $cached_data['cache_epoch'] );
		unset( $cached_data['maxmind'] );

		return $cached_data;
	}

	private static function geoip_request( $ip, $db = 'country' ) {
		global $wgBAMMuser, $wgBAMMpass;
		$auth = array(
			'username' => $wgBAMMuser,
			'password' => $wgBAMMpass
		);

		if ( $db === 'omni') {
			$db = 'insights';
		}
		if ( !in_array( $db, array( 'country', 'city', 'insights' ) ) ) {
			return array( 'error' => 'UNKNOWN_DATABASE' );
		}

		$query = "https://geoip.maxmind.com/geoip/v2.1/{$db}/{$ip}";
		$ch = curl_init();
		curl_setopt_array( $ch, array(
			CURLOPT_URL => $query,
			CURLOPT_USERAGENT => 'MaxMindQuery/2.1 PHP/' . PHP_VERSION,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
			CURLOPT_USERPWD => $auth['username'] . ':' . $auth['password'] ) );
		$response = curl_exec( $ch );

		if ( curl_errno( $ch ) ) {
			return array( 'error' => 'CURL_ERROR' );
		}

		// 2.x returns a JSON document, so parse that and return
		return json_decode( $response, true );
	}
}
