package httpd

import (
	"net/http"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// GetHTTPRouter returns the configured HTTP handler
func GetHTTPRouter() http.Handler {
	return router
}

func initializeRouter(staticFilesPath string, profiler bool) {
	router = chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(logger.NewStructuredLogger(logger.GetLogger()))
	router.Use(middleware.Recoverer)

	if profiler {
		logger.InfoToConsole("enabling the built-in profiler")
		logger.Info(logSender, "", "enabling the built-in profiler")
		router.Mount(pprofBasePath, middleware.Profiler())
	}

	router.NotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
	}))

	router.MethodNotAllowed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendAPIResponse(w, r, nil, "Method not allowed", http.StatusMethodNotAllowed)
	}))

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, webUsersPath, http.StatusMovedPermanently)
	})

	router.Group(func(router chi.Router) {
		router.Use(checkAuth)

		router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, webUsersPath, http.StatusMovedPermanently)
		})

		router.Handle(metricsPath, promhttp.Handler())

		router.Get(versionPath, func(w http.ResponseWriter, r *http.Request) {
			render.JSON(w, r, utils.GetAppVersion())
		})

		router.Get(providerStatusPath, func(w http.ResponseWriter, r *http.Request) {
			err := dataprovider.GetProviderStatus(dataProvider)
			if err != nil {
				sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
			} else {
				sendAPIResponse(w, r, err, "Alive", http.StatusOK)
			}
		})

		router.Get(activeConnectionsPath, func(w http.ResponseWriter, r *http.Request) {
			render.JSON(w, r, sftpd.GetConnectionsStats())
		})

		router.Delete(activeConnectionsPath+"/{connectionID}", func(w http.ResponseWriter, r *http.Request) {
			handleCloseConnection(w, r)
		})

		router.Get(quotaScanPath, func(w http.ResponseWriter, r *http.Request) {
			getQuotaScans(w, r)
		})

		router.Post(quotaScanPath, func(w http.ResponseWriter, r *http.Request) {
			startQuotaScan(w, r)
		})

		router.Get(userPath, func(w http.ResponseWriter, r *http.Request) {
			getUsers(w, r)
		})

		router.Post(userPath, func(w http.ResponseWriter, r *http.Request) {
			addUser(w, r)
		})

		router.Get(userPath+"/{userID}", func(w http.ResponseWriter, r *http.Request) {
			getUserByID(w, r)
		})

		router.Put(userPath+"/{userID}", func(w http.ResponseWriter, r *http.Request) {
			updateUser(w, r)
		})

		router.Delete(userPath+"/{userID}", func(w http.ResponseWriter, r *http.Request) {
			deleteUser(w, r)
		})

		router.Get(dumpDataPath, func(w http.ResponseWriter, r *http.Request) {
			dumpData(w, r)
		})

		router.Get(loadDataPath, func(w http.ResponseWriter, r *http.Request) {
			loadData(w, r)
		})

		router.Get(webUsersPath, func(w http.ResponseWriter, r *http.Request) {
			handleGetWebUsers(w, r)
		})

		router.Get(webUserPath, func(w http.ResponseWriter, r *http.Request) {
			handleWebAddUserGet(w, r)
		})

		router.Get(webUserPath+"/{userID}", func(w http.ResponseWriter, r *http.Request) {
			handleWebUpdateUserGet(chi.URLParam(r, "userID"), w, r)
		})

		router.Post(webUserPath, func(w http.ResponseWriter, r *http.Request) {
			handleWebAddUserPost(w, r)
		})

		router.Post(webUserPath+"/{userID}", func(w http.ResponseWriter, r *http.Request) {
			handleWebUpdateUserPost(chi.URLParam(r, "userID"), w, r)
		})

		router.Get(webConnectionsPath, func(w http.ResponseWriter, r *http.Request) {
			handleWebGetConnections(w, r)
		})
	})

	router.Group(func(router chi.Router) {
		compressor := middleware.NewCompressor(5)
		router.Use(compressor.Handler)
		fileServer(router, webStaticFilesPath, http.Dir(staticFilesPath))
	})
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	connectionID := chi.URLParam(r, "connectionID")
	if connectionID == "" {
		sendAPIResponse(w, r, nil, "connectionID is mandatory", http.StatusBadRequest)
		return
	}
	if sftpd.CloseActiveConnection(connectionID) {
		sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
	} else {
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
	}
}

func fileServer(r chi.Router, path string, root http.FileSystem) {
	fs := http.StripPrefix(path, http.FileServer(root))

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}
