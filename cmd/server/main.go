package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/paragishere/secrust/internal/alerts"
	"github.com/paragishere/secrust/internal/audit"
	"github.com/paragishere/secrust/internal/auth"
	"github.com/paragishere/secrust/internal/config"
	"github.com/paragishere/secrust/internal/database"
	"github.com/paragishere/secrust/internal/ingest"
	"github.com/paragishere/secrust/internal/mailer"
	"github.com/paragishere/secrust/internal/organization"
	"github.com/paragishere/secrust/internal/setup"
	"github.com/paragishere/secrust/internal/website"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file loaded; using existing environment variables")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	db, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	startupCtx, cancelStartup := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer cancelStartup()

	if err := database.Migrate(startupCtx, db); err != nil {
		return err
	}

	// Initialize the alert detection engine.
	alertRepo := alerts.NewRepository(db)

	detector, err := alerts.NewDetector(alertRepo, alerts.DetectorConfig{
		Window:                  cfg.DetectionWindow,
		MinimumCount:            cfg.DetectionMinErrors,
		BruteForceMinimumCount:  cfg.DetectionMinAuthFailures,
		NotFoundMinimumCount:    cfg.DetectionMinNotFound,
		SuppressFor:             cfg.DetectionSuppressFor,
		RequestRateMinimumCount: cfg.DetectionMinRequestsPerIP,
	})
	if err != nil {
		return err
	}

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.LoadHTMLGlob("templates/**/*.html")
	router.Static("/static", "./static")

	authRepo := auth.NewRepository(db)
	authService := auth.NewService(authRepo, 8*time.Hour)
	authHandler := auth.NewHandler(
		authService,
		cfg.Environment == "production",
	)
	authHandler.RegisterRoutes(router)

	protected := router.Group("/")
	protected.Use(authHandler.RequireAuth())

	protected.GET("/dashboard", func(c *gin.Context) {
		csrfToken, err := authHandler.NewDashboardCSRFToken(c)
		if err != nil {
			c.String(
				http.StatusInternalServerError,
				"Unable to prepare dashboard",
			)
			return
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"Name":      c.GetString("userID"),
			"CSRFToken": csrfToken,
		})
	})

	setupService := setup.NewService(db)
	setupHandler := setup.NewHandler(
		setupService,
		cfg.Environment == "production",
	)
	setupHandler.RegisterRoutes(router)

	websiteRepo := website.NewRepository(db)
	websiteService := website.NewService(websiteRepo)
	websiteHandler := website.NewHandler(websiteService)
	websiteHandler.RegisterRoutes(router, authHandler)

	// Log ingestion: authenticated with a website API key.
	ingestRepo := ingest.NewRepository(db)
	ingestHandler := ingest.NewHandler(ingestRepo)

	ingestRoutes := router.Group("/api")
	ingestRoutes.Use(ingest.APIKeyAuth(ingestRepo))
	ingestRoutes.POST("/logs", ingestHandler.Ingest)

	// Alert API: organization-scoped access with RBAC.

	alertHandler := alerts.NewHandler(alertRepo)

	alertRoutes := router.Group("/api/alerts")
	alertRoutes.Use(authHandler.RequireAuth())

	// All authenticated roles can view alerts in their own organization.
	alertRoutes.GET(
		"",
		auth.RequireRoles(
			auth.RoleSuperAdmin,
			auth.RoleManager,
			auth.RoleAnalyst,
			auth.RoleViewer,
		),
		alertHandler.List,
	)

	// Only privileged operational roles can change alert status.
	alertRoutes.PATCH(
		"/:alertID/acknowledge",
		auth.RequireRoles(
			auth.RoleSuperAdmin,
			auth.RoleManager,
			auth.RoleAnalyst,
		),
		authHandler.RequireCSRFHeader(),
		alertHandler.Acknowledge,
	)

	alertRoutes.PATCH(
		"/:alertID/resolve",
		auth.RequireRoles(
			auth.RoleSuperAdmin,
			auth.RoleManager,
			auth.RoleAnalyst,
		),
		authHandler.RequireCSRFHeader(),
		alertHandler.Resolve,
	)

	// Log Explorer API: authenticated with a user session and RBAC.
	router.GET(
		"/api/logs",
		authHandler.RequireAuth(),
		auth.RequireRoles(
			auth.RoleSuperAdmin,
			auth.RoleManager,
			auth.RoleAnalyst,
			auth.RoleViewer,
		),
		ingestHandler.List,
	)

	organizationRepo := organization.NewRepository(db)
	organizationService := organization.NewService(organizationRepo)

	invitationRepo := organization.NewInvitationRepository(db)
	invitationMailer := mailer.New(mailer.SMTPConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	})

	invitationService := organization.NewInvitationService(
		invitationRepo,
		invitationMailer,
		cfg.AppBaseURL,
		72*time.Hour,
	)

	organizationHandler := organization.NewHandlerWithInvitations(
		organizationService,
		invitationService,
	)
	organizationHandler.RegisterRoutes(router, authHandler)
	acceptanceHandler := organization.NewInvitationAcceptanceHandler(
		invitationService,
	)
	acceptanceHandler.RegisterRoutes(router, authHandler)

	// Website assignment with atomic audit logging.
	assignmentRepo := website.NewAssignmentRepository(db)
	auditRepo := audit.NewRepository(db)
	assignmentService := website.NewAssignmentServiceWithAudit(
		db,
		assignmentRepo,
		auditRepo,
	)
	assignmentHandler := website.NewAssignmentHandler(assignmentService)

	assignmentRoutes := router.Group("/api/websites")
	assignmentRoutes.Use(authHandler.RequireAuth())
	assignmentRoutes.Use(auth.RequireRoles(
		auth.RoleSuperAdmin,
		auth.RoleManager,
	))

	assignmentRoutes.PUT(
		"/:websiteID/users/:userID",
		assignmentHandler.Assign,
	)
	assignmentRoutes.DELETE(
		"/:websiteID/users/:userID",
		assignmentHandler.Unassign,
	)

	router.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(
			c.Request.Context(),
			2*time.Second,
		)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start the detector and retain its completion signal for shutdown.
	schedulerCtx, cancelScheduler := context.WithCancel(context.Background())
	schedulerDone := make(chan struct{})

	scheduler := alerts.NewScheduler(
		detector,
		cfg.DetectionInterval,
		logger,
	)

	go func() {
		defer close(schedulerDone)
		scheduler.Run(schedulerCtx)
	}()

	serverErrors := make(chan error, 1)

	go func() {
		logger.Info("server starting", "port", cfg.Port)
		serverErrors <- server.ListenAndServe()
	}()

	signalCtx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	select {
	case err := <-serverErrors:
		cancelScheduler()
		<-schedulerDone

		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-signalCtx.Done():
		logger.Info("shutdown signal received")
	}

	// Stop background detection before the database is closed.
	cancelScheduler()

	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancelShutdown()

	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		<-schedulerDone
		return err
	}

	if err := <-serverErrors; err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		<-schedulerDone
		return err
	}

	<-schedulerDone

	logger.Info("server stopped gracefully")
	return nil
}
