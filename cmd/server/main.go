package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/paragishere/secrust/internal/auth"
	"github.com/paragishere/secrust/internal/config"
	"github.com/paragishere/secrust/internal/database"
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

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.LoadHTMLGlob("templates/**/*.html")

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
			c.String(http.StatusInternalServerError, "Unable to prepare dashboard")
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
	websiteHandler.RegisterRoutes(router)
	organizationRepo := organization.NewRepository(db)
	organizationService := organization.NewService(organizationRepo)
	organizationHandler := organization.NewHandler(organizationService)
	organizationHandler.RegisterRoutes(router)

	router.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
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
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-signalCtx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancelShutdown()

	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return err
	}

	if err := <-serverErrors; err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return err
	}

	logger.Info("server stopped gracefully")
	return nil
}
