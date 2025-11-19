<?php

declare(strict_types=1);

namespace Engelsystem\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Minimal client to talk to the Foxcons JSON API used for authentication.
 */
class FoxconsClient
{
    public function __construct(protected string $baseUrl = '')
    {
        if (empty($this->baseUrl)) {
            // Fallback to the well-known dev host - requests will include /app in the path
            $this->baseUrl = 'https://dev.foxcons.pl';
        }

        // Ensure baseUrl contains only scheme+host(+port) so we always include /app in request paths
        $parts = parse_url($this->baseUrl);
        if ($parts === false || empty($parts['scheme']) || empty($parts['host'])) {
            $this->baseUrl = 'https://dev.foxcons.pl';
        } else {
            $this->baseUrl = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        }
    }

    /**
     * Login to foxcons with username/password and return token array or null on failure.
     *
     * @return array|null ['token' => string, 'refreshToken' => string] | null
     */
    public function login(string $username, string $password): ?array
    {
        $client = new Client(['base_uri' => $this->baseUrl, 'timeout' => 5.0]);
        try {
            // POST to the provider's /auth/login endpoint (baseUrl already contains /app when configured)
            // Ensure '/app' is part of the request path as required by the provider
            $resp = $client->post('/app/auth/login', [
                'json' => [
                    'username' => $username,
                    'password' => $password,
                ],
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
            ]);
            

            $body = (string) $resp->getBody();
            $data = json_decode($body, true);

            if (!is_array($data) || empty($data['token'])) {
                return null;
            }

            return [
                'token' => (string) $data['token'],
                'refreshToken' => $data['refreshToken'] ?? null,
            ];
        } catch (GuzzleException $e) {
            // On errors return null so caller can handle auth failure
            return null;
        }
    }

    /**
     * Fetch event profile for the current token.
     * Returns assoc array or null on failure.
     */
    public function profile(string $token): ?array
    {
        $client = new Client(['base_uri' => $this->baseUrl, 'timeout' => 5.0]);

        try {
            // Ensure '/app' is part of the request path as required by the provider
            $resp = $client->get('/app/event/profile', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Accept' => 'application/json',
                ],
            ]);

            $body = (string) $resp->getBody();
            $data = json_decode($body, true);
            if (!is_array($data) || empty($data['id'])) {
                return null;
            }

            return $data;
        } catch (GuzzleException $e) {
            return null;
        }
    }
}
