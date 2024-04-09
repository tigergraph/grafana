package clientmiddleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
)

// NewOAuthTokenMiddleware creates a new plugins.ClientMiddleware that will
// set OAuth token headers on outgoing plugins.Client requests if the
// datasource has enabled Forward OAuth Identity (oauthPassThru).
func NewOAuthTokenMiddleware(oAuthTokenService oauthtoken.OAuthTokenService) plugins.ClientMiddleware {
	return plugins.ClientMiddlewareFunc(func(next plugins.Client) plugins.Client {
		return &OAuthTokenMiddleware{
			next:              next,
			oAuthTokenService: oAuthTokenService,
			log:               log.New("oauth_token_middleware"),
		}
	})
}

const (
	tokenHeaderName   = "Authorization"
	idTokenHeaderName = "X-ID-Token"
)

type OAuthTokenMiddleware struct {
	oAuthTokenService oauthtoken.OAuthTokenService
	next              plugins.Client
	log               log.Logger
}

func (m *OAuthTokenMiddleware) applyToken(ctx context.Context, pCtx backend.PluginContext, req interface{}) error {
	reqCtx := contexthandler.FromContext(ctx)
	// if request not for a datasource or no HTTP request context skip middleware
	if req == nil || pCtx.DataSourceInstanceSettings == nil || reqCtx == nil || reqCtx.Req == nil {
		return nil
	}

	settings := pCtx.DataSourceInstanceSettings
	jsonDataBytes, err := simplejson.NewJson(settings.JSONData)
	if err != nil {
		return err
	}

	ds := &datasources.DataSource{
		ID:       settings.ID,
		OrgID:    pCtx.OrgID,
		JsonData: jsonDataBytes,
		Updated:  settings.Updated,
	}

	if m.oAuthTokenService.IsOAuthPassThruEnabled(ds) {
		authorizationHeader, idTokenHeader := m.getAuthTokenHeader(ctx, reqCtx)

		switch t := req.(type) {
		case *backend.QueryDataRequest:
			t.Headers[tokenHeaderName] = authorizationHeader
			if idTokenHeader != "" {
				t.Headers[idTokenHeaderName] = idTokenHeader
			}
		case *backend.CheckHealthRequest:
			t.Headers[tokenHeaderName] = authorizationHeader
			if idTokenHeader != "" {
				t.Headers[idTokenHeaderName] = idTokenHeader
			}
		case *backend.CallResourceRequest:
			t.Headers[tokenHeaderName] = []string{authorizationHeader}
			if idTokenHeader != "" {
				t.Headers[idTokenHeaderName] = []string{idTokenHeader}
			}
		}
	}

	return nil
}

func (m *OAuthTokenMiddleware) getAuthTokenHeader(ctx context.Context, reqCtx *contextmodel.ReqContext) (authorizationHeader, idTokenHeader string) {
	authorizationHeader = ""
	idTokenHeader = ""

	if reqCtx.SignedInUser != nil && reqCtx.SignedInUser.AuthenticatedBy == login.JWTModule {
		m.log.Debug("try to get oauth token from jwt")
		jwtToken := reqCtx.Req.Header.Get("Authorization")
		m.log.Debug("jwt token:%v", jwtToken)
		// Strip the 'Bearer' prefix if it exists.
		jwtToken = strings.TrimPrefix(jwtToken, "Bearer ")
		authorizationHeader = jwtToken
		idTokenHeader = jwtToken
		return
	}

	if token := m.oAuthTokenService.GetCurrentOAuthToken(ctx, reqCtx.SignedInUser); token != nil {
		authorizationHeader = fmt.Sprintf("%s %s", token.Type(), token.AccessToken)
		idToken, ok := token.Extra("id_token").(string)
		if ok && idToken != "" {
			idTokenHeader = idToken
		}
	}

	return
}

func (m *OAuthTokenMiddleware) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if req == nil {
		return m.next.QueryData(ctx, req)
	}

	err := m.applyToken(ctx, req.PluginContext, req)
	if err != nil {
		return nil, err
	}

	return m.next.QueryData(ctx, req)
}

func (m *OAuthTokenMiddleware) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req == nil {
		return m.next.CallResource(ctx, req, sender)
	}

	err := m.applyToken(ctx, req.PluginContext, req)
	if err != nil {
		return err
	}

	return m.next.CallResource(ctx, req, sender)
}

func (m *OAuthTokenMiddleware) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if req == nil {
		return m.next.CheckHealth(ctx, req)
	}

	err := m.applyToken(ctx, req.PluginContext, req)
	if err != nil {
		return nil, err
	}

	return m.next.CheckHealth(ctx, req)
}

func (m *OAuthTokenMiddleware) CollectMetrics(ctx context.Context, req *backend.CollectMetricsRequest) (*backend.CollectMetricsResult, error) {
	return m.next.CollectMetrics(ctx, req)
}

func (m *OAuthTokenMiddleware) SubscribeStream(ctx context.Context, req *backend.SubscribeStreamRequest) (*backend.SubscribeStreamResponse, error) {
	return m.next.SubscribeStream(ctx, req)
}

func (m *OAuthTokenMiddleware) PublishStream(ctx context.Context, req *backend.PublishStreamRequest) (*backend.PublishStreamResponse, error) {
	return m.next.PublishStream(ctx, req)
}

func (m *OAuthTokenMiddleware) RunStream(ctx context.Context, req *backend.RunStreamRequest, sender *backend.StreamSender) error {
	return m.next.RunStream(ctx, req, sender)
}
