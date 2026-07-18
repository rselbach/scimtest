package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	GitHubAuthorizeURL = "https://github.com/login/oauth/authorize"
	GitHubTokenURL     = "https://github.com/login/oauth/access_token"
	GitHubUserURL      = "https://api.github.com/user"
)

type GitHubClient struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	TokenURL     string
	UserURL      string
}

type GitHubUser struct {
	Login string `json:"login"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (c GitHubClient) ExchangeWebCode(ctx context.Context, code, redirectURI string) (TokenResponse, error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return TokenResponse{}, errors.New("github client id and secret are required")
	}

	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code", code)
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}

	var token TokenResponse
	if err := c.postForm(ctx, c.tokenEndpoint(), form, &token); err != nil {
		return TokenResponse{}, err
	}
	if token.Error != "" {
		if token.Description != "" {
			return TokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.Description)
		}
		return TokenResponse{}, errors.New(token.Error)
	}
	if token.AccessToken == "" {
		return TokenResponse{}, errors.New("github returned an empty access token")
	}
	return token, nil
}

func (c GitHubClient) User(ctx context.Context, token string) (GitHubUser, error) {
	if token == "" {
		return GitHubUser{}, errors.New("github access token is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userEndpoint(), nil)
	if err != nil {
		return GitHubUser{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "scimtest-server")

	resp, err := c.client().Do(req)
	if err != nil {
		return GitHubUser{}, err
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		closeErr := resp.Body.Close()
		statusErr := fmt.Errorf("github user request failed: %s: %s", resp.Status, bytes.TrimSpace(body))
		return GitHubUser{}, errors.Join(statusErr, readErr, closeErr)
	}

	var user GitHubUser
	decodeErr := json.NewDecoder(resp.Body).Decode(&user)
	closeErr := resp.Body.Close()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return GitHubUser{}, err
	}
	if user.Login == "" {
		return GitHubUser{}, errors.New("github returned an empty login")
	}
	return user, nil
}

func (c GitHubClient) AuthorizeURL(state, redirectURI string) string {
	query := url.Values{}
	query.Set("client_id", c.ClientID)
	query.Set("scope", "read:user")
	query.Set("state", state)
	if redirectURI != "" {
		query.Set("redirect_uri", redirectURI)
	}
	return GitHubAuthorizeURL + "?" + query.Encode()
}

func (c GitHubClient) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "scimtest-server")

	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		closeErr := resp.Body.Close()
		statusErr := fmt.Errorf("github request failed: %s: %s", resp.Status, bytes.TrimSpace(body))
		return errors.Join(statusErr, readErr, closeErr)
	}

	decodeErr := json.NewDecoder(resp.Body).Decode(out)
	return errors.Join(decodeErr, resp.Body.Close())
}

func (c GitHubClient) tokenEndpoint() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return GitHubTokenURL
}

func (c GitHubClient) userEndpoint() string {
	if c.UserURL != "" {
		return c.UserURL
	}
	return GitHubUserURL
}

func (c GitHubClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
