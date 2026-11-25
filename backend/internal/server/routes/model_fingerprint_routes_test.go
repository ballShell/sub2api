//go:build unit

package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/modelfp"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestModelFingerprintRoutesRegisteredAndAdminProtected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handlers := &handler.Handlers{Admin: &handler.AdminHandlers{
		ModelFP: modelfp.NewAdminHandler(nil),
	}}
	adminAuth := servermiddleware.AdminAuthMiddleware(func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			servermiddleware.AbortWithError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authorization required")
			return
		}
		servermiddleware.AbortWithError(c, http.StatusForbidden, "FORBIDDEN", "Admin access required")
	})
	auditLog := servermiddleware.AuditLogMiddleware(func(c *gin.Context) { c.Next() })
	stepUp := servermiddleware.StepUpAuthMiddleware(func(c *gin.Context) { c.Next() })
	RegisterAdminRoutes(router.Group("/api/v1"), handlers, adminAuth, auditLog, stepUp, nil, nil)

	registered := make(map[string]struct{})
	for _, rt := range router.Routes() {
		registered[rt.Method+" "+rt.Path] = struct{}{}
	}

	expectedRoutes := []string{
		"POST /api/v1/admin/model-fingerprint/discover-models",
		"POST /api/v1/admin/model-fingerprint/runs",
		"GET /api/v1/admin/model-fingerprint/runs",
		"GET /api/v1/admin/model-fingerprint/runs/:id",
		"POST /api/v1/admin/model-fingerprint/runs/:id/cancel",
		"DELETE /api/v1/admin/model-fingerprint/runs/:id",
		"GET /api/v1/admin/model-fingerprint/baselines",
		"POST /api/v1/admin/model-fingerprint/baselines/capture",
		"GET /api/v1/admin/model-fingerprint/baselines/capture/:job_id",
		"POST /api/v1/admin/model-fingerprint/baselines/confusion-matrix",
		"GET /api/v1/admin/model-fingerprint/baselines/export",
		"POST /api/v1/admin/model-fingerprint/baselines/import",
		"PUT /api/v1/admin/model-fingerprint/baselines/:id",
		"DELETE /api/v1/admin/model-fingerprint/baselines/:id",
		"GET /api/v1/admin/model-fingerprint/suites",
		"POST /api/v1/admin/model-fingerprint/suites",
		"PUT /api/v1/admin/model-fingerprint/suites/:id/status",
		"GET /api/v1/admin/model-fingerprint/families",
		"PUT /api/v1/admin/model-fingerprint/families/:canonical_model",
		"DELETE /api/v1/admin/model-fingerprint/families/:canonical_model",
	}
	for _, routeKey := range expectedRoutes {
		_, ok := registered[routeKey]
		require.Truef(t, ok, "missing expected route %s", routeKey)
	}

	for _, tc := range []struct {
		name       string
		auth       string
		wantStatus int
	}{
		{name: "unauthenticated", wantStatus: http.StatusUnauthorized},
		{name: "non-admin", auth: "Bearer user-token", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/model-fingerprint/runs", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			router.ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code)
		})
	}
}
