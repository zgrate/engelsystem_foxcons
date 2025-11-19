<?php

declare(strict_types=1);

namespace Engelsystem\Controllers;

use Engelsystem\Config\Config;
use Engelsystem\Config\GoodieType;
use Engelsystem\Events\Listener\OAuth2;
use Engelsystem\Factories\User;
use Carbon\Carbon;
use Engelsystem\Helpers\Authenticator;
use Engelsystem\Http\Redirector;
use Engelsystem\Http\Request;
use Engelsystem\Http\Response;
use Engelsystem\Models\AngelType;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class RegistrationController extends BaseController
{
    use HasUserNotifications;

    public function __construct(
        private Config $config,
        private Response $response,
        private Redirector $redirect,
        private SessionInterface $session,
        private Authenticator $auth,
        private OAuth2 $oAuth,
        private User $userFactory,
        protected LoggerInterface $log,
    ) {
    }

    public function view(): Response
    {
        if ($this->determineRegistrationDisabled()) {
            return $this->notifySignUpDisabledAndRedirectToHome();
        }

        return $this->renderSignUpPage();
    }

    public function save(Request $request): Response
    {
        if ($this->determineRegistrationDisabled()) {
            return $this->notifySignUpDisabledAndRedirectToHome();
        }

        $rawData = $request->getParsedBody();
        try {
            $user = $this->userFactory->createFromData($rawData);
        } catch (\Throwable $e) {
            // Log and show user a friendly error message
            $this->log->error('Registration error: {message}', ['message' => $e->getMessage(), 'exception' => $e]);
            // Also write a fallback file log so we have a trace even if DB logging isn't working

            // Preserve submitted form data so the user doesn't lose their input
            $this->session->set('form-data-register-submit', '1');
            $this->addNotification('registration.error', NotificationType::ERROR);

            return $this->redirect->to('/register')->withInput($rawData);
        }

        if (!$this->auth->user()) {
            $this->addNotification('registration.successful');
        } else {
            $this->addNotification('registration.successful.supporter');
        }

        // If configured, allowlist only users in certain groups. When 'auth.allowed_group_names'
        // is non-empty, newly created users who do not belong to any of the allowed groups
        // will be removed and registration rejected.
        $allowed = $this->config->get('auth')['allowed_group_names'] ?? [];
        if (!empty($allowed) && is_array($allowed)) {
            $allowedLower = array_map('strtolower', $allowed);
            $userGroupNames = $user->groups()->pluck('name')->toArray();

            $isMemberOfAllowed = false;
            foreach ($userGroupNames as $gname) {
                if (in_array(strtolower((string) $gname), $allowedLower, true)) {
                    $isMemberOfAllowed = true;
                    break;
                }
            }

            if (!$isMemberOfAllowed) {
                // Remove the created user to avoid leaving disallowed accounts in the DB
                try {
                    $user->delete();
                } catch (\Throwable $t) {
                    $this->log->warning('Failed to delete not-allowed user after registration: {message}', ['message' => $t->getMessage()]);
                }

                // Preserve submitted form data so the user doesn't lose their input
                $this->session->set('form-data-register-submit', '1');
                $this->addNotification('registration.not_allowed_by_power', NotificationType::ERROR);

                return $this->redirect->to('/register')->withInput($rawData);
            }
        }

        if ($this->config->get('welcome_msg')) {
            // Set a session marker to display the welcome message on the next page
            $this->session->set('show_welcome', true);
        }

        if ($user->oauth?->count() > 0) {
            // User has OAuth configured. If the provider is a configured OAuth provider
            // we redirect to the provider flow, otherwise (e.g. Foxcons) we log the
            // user in directly to avoid attempting to initiate an unknown OAuth flow.
            $provider = $user->oauth->first();
            $providerName = $provider->provider;

            $oauthConfig = $this->config->get('oauth')[$providerName] ?? null;
            if ($oauthConfig) {
                return $this->redirect->to('/oauth/' . $providerName);
            }

            // Non-standard provider (not present in oauth config) - perform direct login.
            $previousPage = $this->session->get('previous_page');

            // Invalidate any old session and set the new user id and locale.
            $this->session->invalidate();
            $this->session->set('user_id', $user->id);
            $this->session->set('locale', $user->settings->language);

            $user->last_login_at = new Carbon();
            $user->save(['touch' => false]);

            try {
                $this->session->save();
            } catch (\Throwable) {
                // ignore
            }

            return $this->redirect->to($previousPage ?: $this->config->get('home_site'));
        }

        if ($this->auth->user()) {
            // User is already logged in - that means a supporter has registered an angel. Return to register page.
            return $this->redirect->to('/register');
        }

        return $this->redirect->to('/');
    }

    private function notifySignUpDisabledAndRedirectToHome(): Response
    {
        $this->addNotification('registration.disabled', NotificationType::INFORMATION);
        return $this->redirect->to('/');
    }

    private function renderSignUpPage(): Response
    {
        $goodieType = GoodieType::from($this->config->get('goodie_type'));
        $preselectedAngelTypes = $this->determinePreselectedAngelTypes();
        $requiredFields = $this->config->get('required_user_fields');

        // form-data-register-submit is a marker, that the form was submitted.
        // It will be used for instance to use the default angel types or the user selected ones.
        // Clear it before render to reset the marker state.
        $this->session->remove('form-data-register-submit');

        return $this->response->withView(
            'pages/registration',
            [
                'minPasswordLength' => $this->config->get('password_min_length'),
                'tShirtSizes' => $this->config->get('tshirt_sizes'),
                'tShirtLink' => $this->config->get('tshirt_link'),
                'angelTypes' => AngelType::whereHideRegister(false)->get(),
                'preselectedAngelTypes' => $preselectedAngelTypes,
                'buildUpStartDate' => $this->userFactory->determineBuildUpStartDate()->format('Y-m-d'),
                'tearDownEndDate' => $this->config->get('teardown_end')?->format('Y-m-d'),
                'isPasswordEnabled' => $this->userFactory->determineIsPasswordEnabled(),
                'isDECTEnabled' => $this->config->get('enable_dect'),
                'isShowMobileEnabled' => $this->config->get('enable_mobile_show'),
                'isGoodieEnabled' => $goodieType !== GoodieType::None && config('enable_email_goodie'),
                'isGoodieTShirt' => $goodieType === GoodieType::Tshirt,
                'isPronounEnabled' => $this->config->get('enable_pronoun'),
                'isFullNameEnabled' => $this->config->get('enable_full_name'),
                'isPlannedArrivalDateEnabled' => $this->config->get('enable_planned_arrival'),
                'isPronounRequired' => $requiredFields['pronoun'],
                'isFirstnameRequired' => $requiredFields['firstname'],
                'isLastnameRequired' => $requiredFields['lastname'],
                'isTShirtSizeRequired' => $requiredFields['tshirt_size'],
                'isMobileRequired' => $requiredFields['mobile'],
                'isDectRequired' => $requiredFields['dect'],
                'isTelegramRequired' => $requiredFields['telegram'],
                // Whether this registration originates from an OAuth provider redirect
                'isOauthRegistration' => $this->session->has('oauth2_connect_provider'),
            ],
        );
    }

    /**
     * @return Array<string, 1> Checkbox field name/id →  1
     */
    private function determinePreselectedAngelTypes(): array
    {
        if ($this->session->has('form-data-register-submit')) {
            // form-data-register-submit means a user just submitted the page.
            // Preselect the angel types from the persisted session form data.
            return $this->loadAngelTypesFromSessionFormData();
        }

        $preselectedAngelTypes = [];

        if ($this->session->has('oauth2_connect_provider')) {
            $preselectedAngelTypes = $this->loadAngelTypesFromSessionOAuthGroups();
        }

        foreach (AngelType::whereRestricted(false)->whereHideRegister(false)->get() as $angelType) {
            // preselect every angel type without restriction
            $preselectedAngelTypes['angel_types_' . $angelType->id] = 1;
        }

        return $preselectedAngelTypes;
    }

    /**
     * @return Array<string, 1>
     */
    private function loadAngelTypesFromSessionOAuthGroups(): array
    {
        $oAuthAngelTypes = [];
        $ssoTeams = $this->oAuth->getSsoTeams($this->session->get('oauth2_connect_provider'));
        $oAuth2Groups = $this->session->get('oauth2_groups');

        foreach ($ssoTeams as $name => $team) {
            if (in_array($name, $oAuth2Groups)) {
                // preselect angel type from oauth
                $oAuthAngelTypes['angel_types_' . $team['id']] = 1;
            }
        }

        return $oAuthAngelTypes;
    }

    /**
     * @return Array<string, 1>
     */
    private function loadAngelTypesFromSessionFormData(): array
    {
        $angelTypes = AngelType::whereHideRegister(false)->get();
        $selectedAngelTypes = [];

        foreach ($angelTypes as $angelType) {
            $sessionKey = 'form-data-angel_types_' . $angelType->id;

            if ($this->session->has($sessionKey)) {
                $selectedAngelTypes['angel_types_' . $angelType->id] = 1;
                // remove from session so that it doesn't stay there forever
                $this->session->remove($sessionKey);
            }
        }

        return $selectedAngelTypes;
    }

    private function determineRegistrationDisabled(): bool
    {
        $authUser = $this->auth->user();
        $isOAuth = $this->session->get('oauth2_connect_provider');
        $isPasswordEnabled = $this->userFactory->determineIsPasswordEnabled();

        // Disable registration when:
        // - the current actor doesn't have register permissions (supporter/admin flows only), OR
        // - the actor is anonymous and the registration is not originating from an OAuth/SSO flow
        //   (we only allow OAuth-originated registrations, e.g. via Foxcons), OR
        // - password-based registration is disabled and there is no OAuth flow
        return !auth()->can('register')
            || (
                !$authUser
                // Only allow anonymous registration when originating from an OAuth provider (Foxcons)
                && !$isOAuth
            )
            // Password disabled and not oauth
            || (!$authUser && !$isPasswordEnabled && !$isOAuth);
    }
}
