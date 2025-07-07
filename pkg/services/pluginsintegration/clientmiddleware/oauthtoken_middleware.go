package clientmiddleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
)

// NewOAuthTokenMiddleware creates a new backend.HandlerMiddleware that will
// set OAuth token headers on outgoing backend.Handler requests if the
// datasource has enabled Forward OAuth Identity (oauthPassThru).
func NewOAuthTokenMiddleware(oAuthTokenService oauthtoken.OAuthTokenService) backend.HandlerMiddleware {
	return backend.HandlerMiddlewareFunc(func(next backend.Handler) backend.Handler {
		return &OAuthTokenMiddleware{
			BaseHandler:       backend.NewBaseHandler(next),
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
	backend.BaseHandler
	oAuthTokenService oauthtoken.OAuthTokenService
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
		// Strip the 'Bearer' prefix if it exists.
		jwtToken = strings.TrimPrefix(jwtToken, "Bearer ")
		authorizationHeader = jwtToken
		idTokenHeader = jwtToken
		return
	}

	if token := m.oAuthTokenService.GetCurrentOAuthToken(ctx, reqCtx.SignedInUser, reqCtx.UserToken); token != nil {
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
		return m.BaseHandler.QueryData(ctx, req)
	}

	err := m.applyToken(ctx, req.PluginContext, req)
	if err != nil {
		return nil, err
	}

	return m.BaseHandler.QueryData(ctx, req)
}

func (m *OAuthTokenMiddleware) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req == nil {
		return m.BaseHandler.CallResource(ctx, req, sender)
	}

	err := m.applyToken(ctx, req.PluginContext, req)
	if err != nil {
		return err
	}

	return m.BaseHandler.CallResource(ctx, req, sender)
}

func (m *OAuthTokenMiddleware) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if req == nil {
		return m.BaseHandler.CheckHealth(ctx, req)
	}

	err := m.applyToken(ctx, req.PluginContext, req)
	if err != nil {
		return nil, err
	}

	return m.BaseHandler.CheckHealth(ctx, req)
}
