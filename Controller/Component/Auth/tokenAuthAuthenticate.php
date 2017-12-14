<?php
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

/**
 * An authentication adapter for AuthComponent.  Provides the ability to authenticate using a Json Web Token
 *
 * {{{
 *	$this->Auth->authenticate = [
 *		'tokenAuth.JwtToken' => [
 *			'fields' => [
 *				'username' => 'username',
 *			],
 *			'parameter' => '_token',
 *			'userModel' => 'User',
 *			'scope' => ['User.active' => 1]
 *		]
 *	]
 * }}}
 *
 * @author Ceeram, Florian Krämer, Ronald Chaplin, Federico Radeljak
 * @copyright Ceeram, Florian Krämer, Ronald Chaplin, Federico Radeljak
 * @license MIT
 * @link https://github.com/fradeljak/cakephp2-jwt-auth
 */

class tokenAuthAuthenticate extends BaseAuthenticate
{

/**
 * Settings for this object.
 *
 * - `fields` The fields to use to identify a user by.
 * - `parameter` The url parameter name of the token.
 * - `userModel` The model name of the User, defaults to User.
 * - `scope` Additional conditions to use when looking up and authenticating users,
 *    i.e. `array('User.is_active' => 1).`
 * - `contain` Extra models to contain and store in session.
 * - `key` The kay that clients would use to encrypt their token payload
 *
 * @var array
 */
    public $settings = [
        'fields' => [
            'username' => 'username'
        ],
        'parameter' => 'api_token',
        'header' => 'authorization',
        'prefix' => 'bearer',
        'userModel' => 'ApiToken',
        'queryDatasource' => true,
        'scope' => [],
        'contain' => null,
        'key' => null
    ];

    /**
     * Constructor
 *
 * @param ComponentCollection $collection The Component collection used on this request.
 * @param array $settings Array of settings to use.
 * @throws CakeException
 */
	public function __construct(ComponentCollection $collection, $settings) {
		parent::__construct($collection, $settings);
		if (empty($this->settings['parameter']) && empty($this->settings['header'])) {
			throw new CakeException(__d('token_auth', 'You need to specify token parameter and/or header'));
		}
	}

/**
 * Unused since this a stateless authentication
 *
 * @param CakeRequest $request The request object
 * @param CakeResponse $response response object.
 * @return mixed.  Always false
 */
	public function authenticate(CakeRequest $request, CakeResponse $response) {
		return false;
	}

/**
 * Get token information from the request.
 *
 * @param CakeRequest $request Request object.
 * @return mixed Either false or an array of user information
 */
	public function getUser(CakeRequest $request) {
        $token = $this->getToken($request);
        if (empty($token)) {
            return false;
        }

		$user = $this->_findUser($token);
		if (!$user) {
            return false;
        }
        return $user;
	}

	/**
	 * @param CakeRequest $request
	 * @return mixed
	 */
	private function getToken(CakeRequest $request)
	{
	    $settings = $this->settings;
		if (!empty($settings['header'])) {
			$header = $request->header($settings['header']);
			if ($header) {
			    return str_ireplace($settings['prefix'].' ', '', $header);
            }
		}

		if (!empty($settings['parameter']) && !empty($request->query[$settings['parameter']])) {
			return $request->query[$settings['parameter']];
		}
		return false;

	}

    /**
     * Find a user record.
     *
     * @param string $id
     * @param string $password
     * @return Mixed Either false on failure, or an array of user data.
     */
    public function _findUser($id, $password = null)
    {
        $tokenModel = $this->settings['tokenModel'];
		list($plugin, $model) = pluginSplit($tokenModel);

        if (isset($this->settings['fields']['username']) &&
            !empty($this->settings['fields']['username'])) {
            $conditions = [
                $model . '.' . $this->settings['fields']['username'] => $id
            ];
        } else {
            $conditions = [
                $model . '.id' => $id
            ];
        }

        if (!empty($this->settings['scope'])) {
			$conditions = array_merge($conditions, $this->settings['scope']);
		}

		$result = ClassRegistry::init($tokenModel)->find('first', array(
			'conditions' => $conditions,
			'contain' => $this->settings['contain'],
		));

		if (empty($result) || empty($result[$model])) {
			return false;
		}

		$user = $result[$model];
		unset($result[$model]);

		return array_merge($user, $result);
	}

    /**
     * Handles an unauthenticated access attempt by sending appropriate login headers
     *
     * @param CakeRequest $request A request object.
     * @param CakeResponse $response A response object.
     * @return void
     * @throws UnauthorizedException
     */
    public function unauthenticated(CakeRequest $request, CakeResponse $response) {
        $Exception = new UnauthorizedException();
        throw $Exception;
    }
}
