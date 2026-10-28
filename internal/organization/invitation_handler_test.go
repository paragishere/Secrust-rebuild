package organization

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
	"github.com/paragishere/secrust/internal/database"
	"golang.org/x/crypto/bcrypt"
)

const invitationTestPassword = "Correct-Horse-42!"

func setupInvitationRouteTest(
	t *testing.T,
	role string,
) (*gin.Engine, string) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "invitation-routes.db")

	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-test', 'Test Organization', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(invitationTestPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (
			id, name, email, password_hash, status, created_at
		)
		VALUES (
			'user-test', 'Test User', 'test@example.com', ?, 'active', ?
		)
	`, string(passwordHash), now)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (
			organization_id, user_id, role, created_at
		)
		VALUES ('org-test', 'user-test', ?, ?)
	`, role, now)
	if err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	authService := auth.NewService(auth.NewRepository(db), time.Hour)

	login, err := authService.Login(
		ctx,
		"test@example.com",
		invitationTestPassword,
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	organizationService := NewService(NewRepository(db))
	invitationRepo := NewInvitationRepository(db)

	// Listing invitations does not send email, so no mailer is needed here.
	invitationService := NewInvitationService(
		invitationRepo,
		nil,
		"https://example.com",
		72*time.Hour,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	authHandler := auth.NewHandler(authService, false)
	organizationHandler := NewHandlerWithInvitations(
		organizationService,
		invitationService,
	)
	organizationHandler.RegisterRoutes(router, authHandler)

	return router, login.Token
}

func invitationRequest(
	router http.Handler,
	method string,
	path string,
	sessionToken string,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)

	if sessionToken != "" {
		req.AddCookie(&http.Cookie{
			Name:  "secrust_session",
			Value: sessionToken,
			Path:  "/",
		})
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	return recorder
}

func TestRegisteredInvitationRouteRoleRestrictions(t *testing.T) {
	tests := []struct {
		name           string
		role           string
		expectedStatus int
	}{
		{
			name:           "super admin can list invitations",
			role:           "SUPER_ADMIN",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "manager cannot list invitations",
			role:           "MANAGER",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "analyst cannot list invitations",
			role:           "ANALYST",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "viewer cannot list invitations",
			role:           "VIEWER",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, sessionToken := setupInvitationRouteTest(t, tt.role)

			recorder := invitationRequest(
				router,
				http.MethodGet,
				"/api/organization/invitations",
				sessionToken,
			)

			if recorder.Code != tt.expectedStatus {
				t.Fatalf(
					"expected status %d for role %s, got %d; body: %s",
					tt.expectedStatus,
					tt.role,
					recorder.Code,
					recorder.Body.String(),
				)
			}
		})
	}
}

func TestRegisteredInvitationRoutesRequireAuthentication(t *testing.T) {
	router, _ := setupInvitationRouteTest(t, "SUPER_ADMIN")

	recorder := invitationRequest(
		router,
		http.MethodGet,
		"/api/organization/invitations",
		"",
	)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf(
			"expected unauthenticated request to redirect with 303, got %d",
			recorder.Code,
		)
	}
}

func TestRegisteredInvitationCreateRequiresCSRF(t *testing.T) {
	router, sessionToken := setupInvitationRouteTest(t, "SUPER_ADMIN")

	recorder := invitationRequest(
		router,
		http.MethodPost,
		"/api/organization/invitations",
		sessionToken,
	)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf(
			"expected missing CSRF token to return 403, got %d; body: %s",
			recorder.Code,
			recorder.Body.String(),
		)
	}
}

// Compile-time check that the test database uses the expected SQL abstraction.
var _ *sql.DB

func TestRegisteredInvitationMutationsRequireCSRF(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "create invitation",
			method: http.MethodPost,
			path:   "/api/organization/invitations",
		},
		{
			name:   "revoke invitation",
			method: http.MethodDelete,
			path:   "/api/organization/invitations/inv-test",
		},
		{
			name:   "resend invitation",
			method: http.MethodPost,
			path:   "/api/organization/invitations/inv-test/resend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, sessionToken := setupInvitationRouteTest(
				t,
				"SUPER_ADMIN",
			)

			recorder := invitationRequest(
				router,
				tt.method,
				tt.path,
				sessionToken,
			)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf(
					"expected missing CSRF token to return 403, got %d; body: %s",
					recorder.Code,
					recorder.Body.String(),
				)
			}
		})
	}
}

func TestRegisteredInvitationMutationsRejectManager(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "create invitation",
			method: http.MethodPost,
			path:   "/api/organization/invitations",
		},
		{
			name:   "revoke invitation",
			method: http.MethodDelete,
			path:   "/api/organization/invitations/inv-test",
		},
		{
			name:   "resend invitation",
			method: http.MethodPost,
			path:   "/api/organization/invitations/inv-test/resend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, sessionToken := setupInvitationRouteTest(
				t,
				"MANAGER",
			)

			recorder := invitationRequest(
				router,
				tt.method,
				tt.path,
				sessionToken,
			)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf(
					"expected manager request to return 403, got %d; body: %s",
					recorder.Code,
					recorder.Body.String(),
				)
			}
		})
	}
}
