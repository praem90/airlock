<?php

namespace Laravel\Airlock;

use Illuminate\Auth\DatabaseUserProvider;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class Guard
{
    /**
     * The authentication factory implementation.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * The number of minutes tokens should be allowed to remain valid.
     *
     * @var int
     */
    protected $expiration;

    /**
     * Create a new guard instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  int  $expiration
     * @return void
     */
    public function __construct(AuthFactory $auth, $expiration = null)
    {
        $this->auth = $auth;
        $this->expiration = $expiration;
    }

    /**
     * Retrieve the authenticated user for the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    public function __invoke(Request $request, $provider = null)
    {
        if ($user = $this->auth->guard('web')->user()) {
            return $this->supportsTokens($user)
                ? $user->withAccessToken(new TransientToken)
                : $user;
        }

        if ($token = $request->bearerToken()) {
            $model = Airlock::$personalAccessTokenModel;

            $accessToken = $model::where('token', hash('sha256', $token))->first();

            if (
                !$accessToken ||
                ($this->expiration &&
                    $accessToken->created_at->lte(now()->subMinutes($this->expiration)))
            ) {
                return;
            }

            $tokenable =  $this->supportsTokens($accessToken->tokenable) ? $accessToken->tokenable->withAccessToken(
                tap($accessToken->forceFill(['last_used_at' => now()]))->save()
            ) : null;

            if ($tokenable && $provider) {
                return $this->validateAgainstProvider($tokenable, $provider);
            }

            return $tokenable;
        }
    }

    /**
     * Determine if the tokenable model supports API tokens.
     *
     * @param  mixed  $tokenable
     * @return bool
     */
    protected function supportsTokens($tokenable = null)
    {
        return in_array(HasApiTokens::class, class_uses_recursive(
            $tokenable ? get_class($tokenable) : null
        ));
    }

    /**
     * Validate tokenable against user provider
     *
     * @param Authenticatable $tokenable
     * @param UserProvider $provider
     * @return bool
     */
    protected function validateAgainstProvider(Authenticatable $tokenable, UserProvider $provider)
    {
        if ($provider instanceof EloquentUserProvider) {
            return $provider->getModel() === get_class($tokenable);
        }

        $model = $provider->retrieveById($tokenable->getAuthIdentifier());

        return ($model &&
            get_class($model) === get_class($tokenable) &&
            $model->getAuthIdentifier() === $tokenable->getAuthIdentifier()) ? $tokenable :  null;
    }
}
