<?php

use MediaWiki\Block\AbstractBlock;
use MediaWiki\Block\CompositeBlock;
use MediaWiki\Block\SystemBlock;
use MediaWiki\MediaWikiServices;

class BlockASN {
	/**
	 * @param User $user User to check blocks for
	 * @param string|null $ip User IP address, or null if we're not checking
	 * 		the global user or the user is ipblock-exempt.
	 * @param AbstractBlock|null &$block The block applying to the user
	 */
	public static function onGetUserBlock( User $user, $ip, &$block ) {
		if ( $ip === null ) {
			// user is ipblock-exempt or we aren't checking the user matching the request
			return;
		}

		$data = self::getData( $ip );
		$config = MediaWikiServices::getInstance()->getMainConfig();
		$apiField = $config->get( 'BAApiField' );
		$blockedASNs = $config->get( 'BlockedASNs' );
		$blockedUserTypes = $config->get( 'BlockedUserTypes' );
		$asnBlocks = [];

		if ( $data !== -1 ) {
			$ret = $data;
			$fragments = explode( '.', $apiField['type'] );

			foreach ( $fragments as $f ) {
				if ( !isset( $ret[$f] ) ) {
					$ret = -1;
					break;
				}

				$ret = $ret[$f];
			}

			if ( $ret !== -1 && in_array( $ret, $blockedUserTypes ) ) {
				$asnBlocks[] = self::getSystemBlock( $ip, 'blockasn-usertypeblockreason', $ret );
			}

			$ret = $data;
			$fragments = explode( '.', $apiField['asn'] );

			foreach ( $fragments as $f ) {
				if ( !isset( $ret[$f] ) ) {
					$ret = -1;
					break;
				}

				$ret = $ret[$f];
			}

			if ( $ret !== -1 && in_array( $ret, $blockedASNs ) ) {
				$asnBlocks[] = $asnBlocks[] = self::getSystemBlock( $ip, 'blockasn-asnblockreason', $ret );
			}

			$ret = $data;
			if ( !is_array( $apiField['proxy'] ) ) {
				$pfields = [ $apiField['proxy'] ];
			} else {
				$pfields = $apiField['proxy'];
			}

			foreach ( $pfields as $field ) {
				$fragments = explode( '.', $field );

				foreach ( $fragments as $f ) {
					if ( !isset( $ret[$f] ) ) {
						$ret = false;
						break;
					}

					$ret = $ret[$f];
				}

				if ( $ret === true ) {
					break;
				}
			}

			if ( $ret === true ) {
				$asnBlocks[] = $asnBlocks[] = self::getSystemBlock( $ip, 'blockasn-proxyblockreason', $ret );
			}
		}

		$numBlocks = count( $asnBlocks );
		if ( $numBlocks > 0 ) {
			if ( $block === null ) {
				if ( $numBlocks > 1 ) {
					$block = new CompositeBlock( [
						'address' => $ip,
						'reason' => new Message( 'blockedtext-composite-reason' ),
						'originalBlocks' => $asnBlocks,
					] );
				} else {
					$block = $asnBlocks[0];
				}
			} elseif ( $block instanceof CompositeBlock ) {
				$block = new CompositeBlock( [
					'address' => $ip,
					'reason' => new Message( 'blockedtext-composite-reason' ),
					'originalBlocks' => array_merge( $asnBlocks, $block->getOriginalBlocks() ),
				] );
			} else {
				$asnBlocks[] = $block;
				$block = new CompositeBlock( [
					'address' => $ip,
					'reason' => new Message( 'blockedtext-composite-reason' ),
					'originalBlocks' => $asnBlocks,
				] );
			}
		}
	}

	/**
	 * Get a SystemBlock instance
	 *
	 * @param string $ip IP to block
	 * @param string $message Message key
	 * @param mixed $param Message parameter
	 * @return SystemBlock
	 */
	private static function getSystemBlock( $ip, $message, $param ) {
		$block = new SystemBlock( [
			'address' => $ip,
			'reason' => new Message( $message, [ $param ] ),
			'systemBlock' => 'blockasn'
		] );

		$block->isCreateAccountBlocked( true );
		return $block;
	}

	/**
	 * Retrieve data for the given IP.
	 *
	 * @param string $ip
	 * @return array
	 */
	private static function getData( $ip ) {
		// first check cache for the (ip, db) combo
		// results are cached for 1 week
		$cache = ObjectCache::getLocalClusterInstance();
		$cached_data = $cache->get( "geoip_" . sha1( $ip ) );

		if ( $cached_data === false ) {
			$data = self::geoIPRequest( $ip, 'insights' );
			// don't cache errors
			if ( !isset( $data['error'] ) || $data['error'] == '' ) {
				$data['cached_at'] = time();
				$cache->set( "geoip_" . sha1( $ip ), $data, 60 * 60 * 24 * 7 );
				$cached_data = $data;
			} else {
				// error
				return $data;
			}
		}

		// unset fields we don't want to expose
		unset( $cached_data['maxmind'] );

		return $cached_data;
	}

	/**
	 * Perform a geoip request to MaxMind
	 *
	 * @param string $ip
	 * @param string $db
	 * @return array
	 */
	private static function geoIPRequest( $ip, $db = 'country' ) {
		if ( !in_array( $db, [ 'country', 'city', 'insights' ] ) ) {
			return [ 'error' => 'UNKNOWN_DATABASE' ];
		}

		$query = "https://geoip.maxmind.com/geoip/v2.1/{$db}/{$ip}";
		$config = MediaWikiServices::getInstance()->getMainConfig();
		$httpFactory = MediaWikiServices::getInstance()->getHttpRequestFactory();
		$response = $httpFactory->get( $query, [
			'userAgent' => 'MaxMindQuery/2.1 PHP/' . PHP_VERSION,
			'username' => $config->get( 'BAMMuser' ),
			'password' => $config->get( 'BAMMpass' )
		], __METHOD__ );

		if ( $response === null ) {
			return [ 'error' => 'REQUEST_ERROR' ];
		}

		// 2.x returns a JSON document, so parse that and return
		return json_decode( $response, true );
	}
}
