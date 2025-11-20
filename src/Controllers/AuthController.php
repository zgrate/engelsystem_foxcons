<?php

declare(strict_types=1);

namespace Engelsystem\Controllers;

use Carbon\Carbon;
use Engelsystem\Config\Config;
use Engelsystem\Helpers\Authenticator;
use Engelsystem\Models\OAuth;
use Engelsystem\Services\FoxconsClient;
use Engelsystem\Models\Group;
use Engelsystem\Http\Redirector;
use Engelsystem\Http\Request;
use Engelsystem\Http\Response;
use Engelsystem\Models\User\User;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class AuthController extends BaseController
{
    use HasUserNotifications;

    /** @var array<string, string> */
    protected array $permissions = [
        'login'     => 'login',
        'postLogin' => 'login',
        'postFoxconsLogin' => 'login',
        'loginFoxcons' => 'login',
    ];

    public function __construct(
        protected Response $response,
        protected SessionInterface $session,
        protected Redirector $redirect,
        protected Config $config,
        protected Authenticator $auth
    ) {
    }

    public function login(): Response
    {
        return $this->showLogin();
    }

    protected function showLogin(): Response
    {
        return $this->response->withView('pages/login');
    }

    protected function showFoxconsLogin(): Response
    {
        return $this->response->withView('pages/login_foxcons');
    }

    /**
     * Posted login form
     */
    public function postLogin(Request $request): Response
    {
        $data = $this->validate($request, [
            'login'    => 'required',
            'password' => 'required',
        ]);

        $user = $this->auth->authenticate($data['login'], $data['password']);

        if (!$user instanceof User) {
            $this->addNotification('auth.not-found', NotificationType::ERROR);

            return $this->showLogin();
        }

        return $this->loginUser($user);
    }

    /**
     * Login against Foxcons using email/username and password and create/link local user.
     */
    public function postFoxconsLogin(Request $request): Response
    {
        $data = $this->validate($request, [
            'login'    => 'required',
            'password' => 'required',
        ]);

        $login = $data['login'];
        $password = $data['password'];

    $foxcons = new FoxconsClient($this->config->get('foxcons')['url'] ?? '');
    $tokens = $foxcons->login($login, $password);
        if (empty($tokens) || empty($tokens['token'])) {
            $this->addNotification('auth.not-found', NotificationType::ERROR);
            return $this->showFoxconsLogin();
        }

        $profile = $foxcons->profile((string) $tokens['token']);
        if (empty($profile) || empty($profile['id'])) {
            $this->addNotification('auth.not-found', NotificationType::ERROR);
            return $this->showFoxconsLogin();
        }

        $profilePower = $profile['power'] ?? null;
        if ($profilePower !== null) {
            if (!$this->isPowerAllowed((string) $profilePower)) {
                $this->addNotification('auth.not_allowed_by_power', NotificationType::ERROR);
                return $this->showFoxconsLogin();
            }
        }
        // Try to find an existing OAuth link
        $identifier = (string) $profile['id'];
        $provider = 'foxcons';

        $oauth = OAuth::whereProvider($provider)->whereIdentifier($identifier)->first();

        if ($oauth && $oauth->user) {
            $user = $oauth->user;
            // Update tokens
            $oauth->access_token = $tokens['token'];
            $oauth->refresh_token = $tokens['refreshToken'] ?? null;
            $oauth->save();

            // Prefer checking the Foxcons-provided power level when available
            $profilePower = $profile['power'] ?? null;
            if ($profilePower !== null) {
                if (!$this->isPowerAllowed((string) $profilePower)) {
                    $this->addNotification('auth.not_allowed_by_power', NotificationType::ERROR);
                    return $this->showLogin();
                }
            } else {
                // Fallback to checking local group membership
                if (!$this->isUserAllowedByPower($user)) {
                    $this->addNotification('auth.not_allowed_by_power', NotificationType::ERROR);
                    return $this->showLogin();
                }
            }

            return $this->loginUser($user);
        }

        // No oauth link - try to find user by email (login value)
        $user = \Engelsystem\Models\User\User::whereEmail($login)->first();

        if ($user) {
            // Link oauth to existing user
            $oauth = new OAuth([
                'provider' => $provider,
                'identifier' => $identifier,
                'access_token' => $tokens['token'],
                'refresh_token' => $tokens['refreshToken'] ?? null,
            ]);
            $oauth->user()->associate($user);
            $oauth->save();

            if (!$this->isUserAllowedByPower($user)) {
                $this->addNotification('auth.not_allowed_by_power', NotificationType::ERROR);
                return $this->showLogin();
            }

            return $this->loginUser($user);
        }

        // No local user: follow existing OAuth flow - set session data and redirect to registration
        // so required fields are collected via the normal registration process.
    $username = preg_replace('/[^a-zA-Z0-9.-_]/', '', substr($profile['displayName'] ?? ($profile['firstName'] ?? $login), 0, 24));
    $this->session->set('form-data-username', $username);
    $this->session->set('form-data-email', $login);
    $this->session->set('form-data-firstname', $profile['firstName'] ?? null);
    $this->session->set('form-data-lastname', $profile['lastName'] ?? null);
    // Preserve Foxcons provided power level (if present) for registration and policy checks
    $this->session->set('form-data-power', $profile['power'] ?? null);
    $this->session->set('oauth2_power', $profile['power'] ?? null);
    // Preselect email preferences for oauth-created accounts
    $this->session->set('form-data-email_system', true);
    $this->session->set('form-data-email_by_human_allowed', true);

        $this->session->set('oauth2_groups', []);
        $this->session->set('oauth2_connect_provider', $provider);
        $this->session->set('oauth2_user_id', $identifier);
        $this->session->set('oauth2_access_token', $tokens['token']);
        $this->session->set('oauth2_refresh_token', $tokens['refreshToken'] ?? null);
        $this->session->set('oauth2_expires_at', null);
        $this->session->set('oauth2_enable_password', false);
        $this->session->set('oauth2_allow_registration', null);

        return $this->redirect->to('/register');
    }

    /**
     * Show the Foxcons-only login page (email + password form).
     */
    public function loginFoxcons(): Response
    {
        return $this->response->withView('pages/login_foxcons');
    }

    public function loginUser(User $user): Response
    {
        $previousPage = $this->session->get('previous_page');

        $this->session->invalidate();
        $this->session->set('user_id', $user->id);
        $this->session->set('locale', $user->settings->language);

        $user->last_login_at = new Carbon();
        $user->save(['touch' => false]);

        // Ensure session is persisted before redirecting to avoid race conditions
        try {
            $this->session->save();
        } catch (\Throwable) {
            // ignore save errors - user is still logged in, but session persistence may be handled on shutdown
        }

        return $this->redirect->to($previousPage ?: $this->config->get('home_site'));
    }

    public function logout(): Response
    {
        $this->session->invalidate();

        return $this->redirect->to('/');
    }

    /**
     * Determine whether the user is allowed based on configured allowed group names.
     * When the config 'auth.allowed_group_names' is empty, all users are allowed.
     */
    private function isUserAllowedByPower(User $user): bool
    {
        $allowed = $this->config->get('auth')['allowed_group_names'] ?? [];
        if (empty($allowed) || !is_array($allowed)) {
            return true; // no restriction configured
        }

        $allowedLower = array_map('strtolower', $allowed);

        $groupNames = $user->groups()->pluck('name')->toArray();
        foreach ($groupNames as $name) {
            if (in_array(strtolower((string) $name), $allowedLower, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check whether a Foxcons-provided power value is allowed by config.
     */
    private function isPowerAllowed(?string $power): bool
    {
        $allowed = $this->config->get('auth')['allowed_group_names'] ?? [];
        if (empty($allowed) || !is_array($allowed)) {
            return true;
        }

        if ($power === null) {
            return true; // Nothing to check here; caller should fall back to group-based checks
        }

        $allowedLower = array_map('strtolower', $allowed);

        return in_array(strtolower($power), $allowedLower, true);
    }
}
