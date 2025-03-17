package vault

import (
	"context"
	"fmt"
	"sync"

	"github.com/3scale/aws-cvpn-pki-manager/pkg/config"
	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

// AuthenticatedClient represents an authenticated
// client that can talk to the vault server
type AuthenticatedClient interface {
	GetClient(logr.Logger) (*api.Client, error)
}

// TokenAuthenticatedClient is the config
// object required to create a token based authenticated
// Vault client
type TokenAuthenticatedClient struct {
	Address string
	Token   string
	client  *api.Client
	sync.Mutex
}

// GetClient creates a new authenticated client to
// interact with a vault server's API. A token is directly passed
// for authentication
// Does not implement token renewal
func (tac *TokenAuthenticatedClient) GetClient(logr.Logger) (*api.Client, error) {

	if tac.client == nil {
		tac.Lock()
		defer tac.Unlock()
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return nil, err
		}
		client.SetAddress(tac.Address)
		client.SetToken(tac.Token)
		client.SetClientTimeout(config.VaultApiTimeout)
		tac.client = client
	}
	return tac.client, nil
}

// ApproleAuthenticatedClient is the config
// object required to create a Vault client that
// authenticates using Vault's Approle auth backend
type ApproleAuthenticatedClient struct {
	Address     string
	SecretID    string
	RoleID      string
	BackendPath string
	client      *api.Client
	sync.Mutex
}

// GetClient uses the Approle auth backend to obtain a token
// Implements token renewal
// approleSecretID string, approleRoleID string,
func (aac *ApproleAuthenticatedClient) GetClient(logger logr.Logger) (*api.Client, error) {

	// client is already configured
	if aac.client != nil {
		return aac.client, nil
	}

	// client still not initialized
	aac.Lock()
	defer aac.Unlock()

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	client.SetAddress(aac.Address)
	client.SetClientTimeout(config.VaultApiTimeout)

	// start the token lease renewal process
	go func() {
		for {
			vaultLoginResp, err := aac.login(context.Background(), logger)
			if err != nil {
				logger.Error(err, "unable to authenticate to Vault")
			}
			tokenErr := aac.manageTokenLifecycle(vaultLoginResp, logger)
			if tokenErr != nil {
				logger.Error(tokenErr, "unable to start managing token lifecycle")
			}
		}
	}()

	// Update the client in the shared object
	aac.client = client

	return aac.client, nil
}

func (aac *ApproleAuthenticatedClient) login(ctx context.Context, logger logr.Logger) (*api.Secret, error) {

	// request a new token using approle auth backend
	// with configured options
	appRoleAuth, err := auth.NewAppRoleAuth(
		aac.RoleID,
		&auth.SecretID{FromString: aac.SecretID},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := aac.client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}
	logger.V(1).Info("Successfully logged into Vault using AppRole auth")

	return authInfo, nil
}

// Starts token lifecycle management. Returns only fatal errors as errors,
// otherwise returns nil so we can attempt login again.
func (aac *ApproleAuthenticatedClient) manageTokenLifecycle(token *api.Secret, logger logr.Logger) error {
	renew := token.Auth.Renewable
	if !renew {
		logger.V(1).Info("Token is not configured to be renewable. Re-attempting login.")
		return nil
	}

	watcher, err := aac.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret:    token,
		Increment: 3600,
	})
	if err != nil {
		return fmt.Errorf("unable to initialize new lifetime watcher for renewing auth token: %w", err)
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		// `DoneCh` will return if renewal fails, or if the remaining lease
		// duration is under a built-in threshold and either renewing is not
		// extending it or renewing is disabled. In any case, the caller
		// needs to attempt to log in again.
		case err := <-watcher.DoneCh():
			if err != nil {
				logger.Error(err, "failed to renew token, re-attempting login")
				return nil
			}
			// This occurs once the token has reached max TTL.
			logger.V(1).Info("token can no longer be renewed, re-attempting login")
			return nil

		// Successfully completed renewal
		case renewal := <-watcher.RenewCh():
			logger.V(1).Info(fmt.Sprintf("Successfully renewed: %#v", renewal))
		}
	}
}
