//go:build !noserver

package cmd

import (
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
	"heckel.io/ntfy/v2/log"
	"heckel.io/ntfy/v2/server"
	"heckel.io/ntfy/v2/user"
	"heckel.io/ntfy/v2/util"
	"io/fs"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func init() {
	commands = append(commands, cmdServe)
}

const (
	defaultServerConfigFile = "/etc/ntfy/server.yml"
)

var flagsServe = append(
	append([]cli.Flag{}, flagsDefault...),
	&cli.StringFlag{Name: "config", Aliases: []string{"c"}, EnvVars: []string{"NTFY_CONFIG_FILE"}, Value: defaultServerConfigFile, Usage: "config file"},
	altsrc.NewStringFlag(&cli.StringFlag{Name: "base-url", Aliases: []string{"base_url", "B"}, EnvVars: []string{"NTFY_BASE_URL"}, Usage: "externally visible base URL for this host (e.g. https://ntfy.sh)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "listen-http", Aliases: []string{"listen_http", "l"}, EnvVars: []string{"NTFY_LISTEN_HTTP"}, Value: server.DefaultListenHTTP, Usage: "ip:port used as HTTP listen address"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "listen-unix", Aliases: []string{"listen_unix", "U"}, EnvVars: []string{"NTFY_LISTEN_UNIX"}, Usage: "listen on unix socket path"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "listen-unix-mode", Aliases: []string{"listen_unix_mode"}, EnvVars: []string{"NTFY_LISTEN_UNIX_MODE"}, DefaultText: "system default", Usage: "file permissions of unix socket, e.g. 0700"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "cache-file", Aliases: []string{"cache_file", "C"}, EnvVars: []string{"NTFY_CACHE_FILE"}, Usage: "cache file used for message caching"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "cache-duration", Aliases: []string{"cache_duration", "b"}, EnvVars: []string{"NTFY_CACHE_DURATION"}, Value: util.FormatDuration(server.DefaultCacheDuration), Usage: "buffer messages for this time to allow `since` requests"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "cache-batch-size", Aliases: []string{"cache_batch_size"}, EnvVars: []string{"NTFY_BATCH_SIZE"}, Usage: "max size of messages to batch together when writing to message cache (if zero, writes are synchronous)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "cache-batch-timeout", Aliases: []string{"cache_batch_timeout"}, EnvVars: []string{"NTFY_CACHE_BATCH_TIMEOUT"}, Value: util.FormatDuration(server.DefaultCacheBatchTimeout), Usage: "timeout for batched async writes to the message cache (if zero, writes are synchronous)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "cache-startup-queries", Aliases: []string{"cache_startup_queries"}, EnvVars: []string{"NTFY_CACHE_STARTUP_QUERIES"}, Usage: "queries run when the cache database is initialized"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "auth-file", Aliases: []string{"auth_file", "H"}, EnvVars: []string{"NTFY_AUTH_FILE"}, Usage: "auth database file used for access control"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "auth-startup-queries", Aliases: []string{"auth_startup_queries"}, EnvVars: []string{"NTFY_AUTH_STARTUP_QUERIES"}, Usage: "queries run when the auth database is initialized"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "auth-default-access", Aliases: []string{"auth_default_access", "p"}, EnvVars: []string{"NTFY_AUTH_DEFAULT_ACCESS"}, Value: "read-write", Usage: "default permissions if no matching entries in the auth database are found"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "attachment-cache-dir", Aliases: []string{"attachment_cache_dir"}, EnvVars: []string{"NTFY_ATTACHMENT_CACHE_DIR"}, Usage: "cache directory for attached files"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "attachment-total-size-limit", Aliases: []string{"attachment_total_size_limit", "A"}, EnvVars: []string{"NTFY_ATTACHMENT_TOTAL_SIZE_LIMIT"}, Value: util.FormatSize(server.DefaultAttachmentTotalSizeLimit), Usage: "limit of the on-disk attachment cache"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "attachment-file-size-limit", Aliases: []string{"attachment_file_size_limit", "Y"}, EnvVars: []string{"NTFY_ATTACHMENT_FILE_SIZE_LIMIT"}, Value: util.FormatSize(server.DefaultAttachmentFileSizeLimit), Usage: "per-file attachment size limit (e.g. 300k, 2M, 100M)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "attachment-expiry-duration", Aliases: []string{"attachment_expiry_duration", "X"}, EnvVars: []string{"NTFY_ATTACHMENT_EXPIRY_DURATION"}, Value: util.FormatDuration(server.DefaultAttachmentExpiryDuration), Usage: "duration after which uploaded attachments will be deleted (e.g. 3h, 20h)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "keepalive-interval", Aliases: []string{"keepalive_interval", "k"}, EnvVars: []string{"NTFY_KEEPALIVE_INTERVAL"}, Value: util.FormatDuration(server.DefaultKeepaliveInterval), Usage: "interval of keepalive messages"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "manager-interval", Aliases: []string{"manager_interval", "m"}, EnvVars: []string{"NTFY_MANAGER_INTERVAL"}, Value: util.FormatDuration(server.DefaultManagerInterval), Usage: "interval of for message pruning and stats printing"}),
	altsrc.NewStringSliceFlag(&cli.StringSliceFlag{Name: "disallowed-topics", Aliases: []string{"disallowed_topics"}, EnvVars: []string{"NTFY_DISALLOWED_TOPICS"}, Usage: "topics that are not allowed to be used"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "web-root", Aliases: []string{"web_root"}, EnvVars: []string{"NTFY_WEB_ROOT"}, Value: "/", Usage: "sets root of the web app (e.g. /, or /app), or disables it (disable)"}),
	altsrc.NewBoolFlag(&cli.BoolFlag{Name: "enable-signup", Aliases: []string{"enable_signup"}, EnvVars: []string{"NTFY_ENABLE_SIGNUP"}, Value: false, Usage: "allows users to sign up via the web app, or API"}),
	altsrc.NewBoolFlag(&cli.BoolFlag{Name: "enable-login", Aliases: []string{"enable_login"}, EnvVars: []string{"NTFY_ENABLE_LOGIN"}, Value: false, Usage: "allows users to log in via the web app, or API"}),
	altsrc.NewBoolFlag(&cli.BoolFlag{Name: "enable-reservations", Aliases: []string{"enable_reservations"}, EnvVars: []string{"NTFY_ENABLE_RESERVATIONS"}, Value: false, Usage: "allows users to reserve topics (if their tier allows it)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "message-size-limit", Aliases: []string{"message_size_limit"}, EnvVars: []string{"NTFY_MESSAGE_SIZE_LIMIT"}, Value: util.FormatSize(server.DefaultMessageSizeLimit), Usage: "size limit for the message (see docs for limitations)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "message-delay-limit", Aliases: []string{"message_delay_limit"}, EnvVars: []string{"NTFY_MESSAGE_DELAY_LIMIT"}, Value: util.FormatDuration(server.DefaultMessageDelayMax), Usage: "max duration a message can be scheduled into the future"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "global-topic-limit", Aliases: []string{"global_topic_limit", "T"}, EnvVars: []string{"NTFY_GLOBAL_TOPIC_LIMIT"}, Value: server.DefaultTotalTopicLimit, Usage: "total number of topics allowed"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "visitor-subscription-limit", Aliases: []string{"visitor_subscription_limit"}, EnvVars: []string{"NTFY_VISITOR_SUBSCRIPTION_LIMIT"}, Value: server.DefaultVisitorSubscriptionLimit, Usage: "number of subscriptions per visitor"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "visitor-attachment-total-size-limit", Aliases: []string{"visitor_attachment_total_size_limit"}, EnvVars: []string{"NTFY_VISITOR_ATTACHMENT_TOTAL_SIZE_LIMIT"}, Value: util.FormatSize(server.DefaultVisitorAttachmentTotalSizeLimit), Usage: "total storage limit used for attachments per visitor"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "visitor-attachment-daily-bandwidth-limit", Aliases: []string{"visitor_attachment_daily_bandwidth_limit"}, EnvVars: []string{"NTFY_VISITOR_ATTACHMENT_DAILY_BANDWIDTH_LIMIT"}, Value: "500M", Usage: "total daily attachment download/upload bandwidth limit per visitor"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "visitor-request-limit-burst", Aliases: []string{"visitor_request_limit_burst"}, EnvVars: []string{"NTFY_VISITOR_REQUEST_LIMIT_BURST"}, Value: server.DefaultVisitorRequestLimitBurst, Usage: "initial limit of requests per visitor"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "visitor-request-limit-replenish", Aliases: []string{"visitor_request_limit_replenish"}, EnvVars: []string{"NTFY_VISITOR_REQUEST_LIMIT_REPLENISH"}, Value: util.FormatDuration(server.DefaultVisitorRequestLimitReplenish), Usage: "interval at which burst limit is replenished (one per x)"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "visitor-request-limit-exempt-hosts", Aliases: []string{"visitor_request_limit_exempt_hosts"}, EnvVars: []string{"NTFY_VISITOR_REQUEST_LIMIT_EXEMPT_HOSTS"}, Value: "", Usage: "hostnames and/or IP addresses of hosts that will be exempt from the visitor request limit"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "visitor-message-daily-limit", Aliases: []string{"visitor_message_daily_limit"}, EnvVars: []string{"NTFY_VISITOR_MESSAGE_DAILY_LIMIT"}, Value: server.DefaultVisitorMessageDailyLimit, Usage: "max messages per visitor per day, derived from request limit if unset"}),
	altsrc.NewIntFlag(&cli.IntFlag{Name: "visitor-email-limit-burst", Aliases: []string{"visitor_email_limit_burst"}, EnvVars: []string{"NTFY_VISITOR_EMAIL_LIMIT_BURST"}, Value: server.DefaultVisitorEmailLimitBurst, Usage: "initial limit of e-mails per visitor"}),
	altsrc.NewStringFlag(&cli.StringFlag{Name: "visitor-email-limit-replenish", Aliases: []string{"visitor_email_limit_replenish"}, EnvVars: []string{"NTFY_VISITOR_EMAIL_LIMIT_REPLENISH"}, Value: util.FormatDuration(server.DefaultVisitorEmailLimitReplenish), Usage: "interval at which burst limit is replenished (one per x)"}),
	altsrc.NewBoolFlag(&cli.BoolFlag{Name: "visitor-subscriber-rate-limiting", Aliases: []string{"visitor_subscriber_rate_limiting"}, EnvVars: []string{"NTFY_VISITOR_SUBSCRIBER_RATE_LIMITING"}, Value: false, Usage: "enables subscriber-based rate limiting"}),
	altsrc.NewBoolFlag(&cli.BoolFlag{Name: "behind-proxy", Aliases: []string{"behind_proxy", "P"}, EnvVars: []string{"NTFY_BEHIND_PROXY"}, Value: false, Usage: "if set, use X-Forwarded-For header to determine visitor IP address (for rate limiting)"}),
)

var cmdServe = &cli.Command{
	Name:      "serve",
	Usage:     "Run the ntfy server",
	UsageText: "ntfy serve [OPTIONS..]",
	Action:    execServe,
	Category:  categoryServer,
	Flags:     flagsServe,
	Before:    initConfigFileInputSourceFunc("config", flagsServe, initLogFunc),
	Description: `Run the ntfy server and listen for incoming requests

The command will load the configuration from /etc/ntfy/server.yml. Config options can 
be overridden using the command line options.

Examples:
  ntfy serve                      # Starts server in the foreground (on port 80)
  ntfy serve --listen-http :8080  # Starts server with alternate port`,
}

func execServe(c *cli.Context) error {
	if c.NArg() > 0 {
		return errors.New("no arguments expected, see 'ntfy serve --help' for help")
	}

	// Read all the options
	config := c.String("config")
	baseURL := strings.TrimSuffix(c.String("base-url"), "/")
	listenHTTP := c.String("listen-http")
	listenUnix := c.String("listen-unix")
	listenUnixMode := c.Int("listen-unix-mode")
	cacheFile := c.String("cache-file")
	cacheDurationStr := c.String("cache-duration")
	cacheStartupQueries := c.String("cache-startup-queries")
	cacheBatchSize := c.Int("cache-batch-size")
	cacheBatchTimeoutStr := c.String("cache-batch-timeout")
	authFile := c.String("auth-file")
	authStartupQueries := c.String("auth-startup-queries")
	authDefaultAccess := c.String("auth-default-access")
	attachmentCacheDir := c.String("attachment-cache-dir")
	attachmentTotalSizeLimitStr := c.String("attachment-total-size-limit")
	attachmentFileSizeLimitStr := c.String("attachment-file-size-limit")
	attachmentExpiryDurationStr := c.String("attachment-expiry-duration")
	keepaliveIntervalStr := c.String("keepalive-interval")
	managerIntervalStr := c.String("manager-interval")
	disallowedTopics := c.StringSlice("disallowed-topics")
	webRoot := c.String("web-root")
	enableSignup := c.Bool("enable-signup")
	enableLogin := c.Bool("enable-login")
	enableReservations := c.Bool("enable-reservations")
	messageSizeLimitStr := c.String("message-size-limit")
	messageDelayLimitStr := c.String("message-delay-limit")
	totalTopicLimit := c.Int("global-topic-limit")
	visitorSubscriptionLimit := c.Int("visitor-subscription-limit")
	visitorSubscriberRateLimiting := c.Bool("visitor-subscriber-rate-limiting")
	visitorAttachmentTotalSizeLimitStr := c.String("visitor-attachment-total-size-limit")
	visitorAttachmentDailyBandwidthLimitStr := c.String("visitor-attachment-daily-bandwidth-limit")
	visitorRequestLimitBurst := c.Int("visitor-request-limit-burst")
	visitorRequestLimitReplenishStr := c.String("visitor-request-limit-replenish")
	visitorRequestLimitExemptHosts := util.SplitNoEmpty(c.String("visitor-request-limit-exempt-hosts"), ",")
	visitorMessageDailyLimit := c.Int("visitor-message-daily-limit")
	visitorEmailLimitBurst := c.Int("visitor-email-limit-burst")
	visitorEmailLimitReplenishStr := c.String("visitor-email-limit-replenish")
	behindProxy := c.Bool("behind-proxy")

	// Convert durations
	cacheDuration, err := util.ParseDuration(cacheDurationStr)
	if err != nil {
		return fmt.Errorf("invalid cache duration: %s", cacheDurationStr)
	}
	cacheBatchTimeout, err := util.ParseDuration(cacheBatchTimeoutStr)
	if err != nil {
		return fmt.Errorf("invalid cache batch timeout: %s", cacheBatchTimeoutStr)
	}
	attachmentExpiryDuration, err := util.ParseDuration(attachmentExpiryDurationStr)
	if err != nil {
		return fmt.Errorf("invalid attachment expiry duration: %s", attachmentExpiryDurationStr)
	}
	keepaliveInterval, err := util.ParseDuration(keepaliveIntervalStr)
	if err != nil {
		return fmt.Errorf("invalid keepalive interval: %s", keepaliveIntervalStr)
	}
	managerInterval, err := util.ParseDuration(managerIntervalStr)
	if err != nil {
		return fmt.Errorf("invalid manager interval: %s", managerIntervalStr)
	}
	messageDelayLimit, err := util.ParseDuration(messageDelayLimitStr)
	if err != nil {
		return fmt.Errorf("invalid message delay limit: %s", messageDelayLimitStr)
	}
	visitorRequestLimitReplenish, err := util.ParseDuration(visitorRequestLimitReplenishStr)
	if err != nil {
		return fmt.Errorf("invalid visitor request limit replenish: %s", visitorRequestLimitReplenishStr)
	}
	visitorEmailLimitReplenish, err := util.ParseDuration(visitorEmailLimitReplenishStr)
	if err != nil {
		return fmt.Errorf("invalid visitor email limit replenish: %s", visitorEmailLimitReplenishStr)
	}

	// Convert sizes to bytes
	messageSizeLimit, err := util.ParseSize(messageSizeLimitStr)
	if err != nil {
		return fmt.Errorf("invalid message size limit: %s", messageSizeLimitStr)
	}
	attachmentTotalSizeLimit, err := util.ParseSize(attachmentTotalSizeLimitStr)
	if err != nil {
		return fmt.Errorf("invalid attachment total size limit: %s", attachmentTotalSizeLimitStr)
	}
	attachmentFileSizeLimit, err := util.ParseSize(attachmentFileSizeLimitStr)
	if err != nil {
		return fmt.Errorf("invalid attachment file size limit: %s", attachmentFileSizeLimitStr)
	}
	visitorAttachmentTotalSizeLimit, err := util.ParseSize(visitorAttachmentTotalSizeLimitStr)
	if err != nil {
		return fmt.Errorf("invalid visitor attachment total size limit: %s", visitorAttachmentTotalSizeLimitStr)
	}
	visitorAttachmentDailyBandwidthLimit, err := util.ParseSize(visitorAttachmentDailyBandwidthLimitStr)
	if err != nil {
		return fmt.Errorf("invalid visitor attachment daily bandwidth limit: %s", visitorAttachmentDailyBandwidthLimitStr)
	} else if visitorAttachmentDailyBandwidthLimit > math.MaxInt {
		return fmt.Errorf("config option visitor-attachment-daily-bandwidth-limit must be lower than %d", math.MaxInt)
	}

	// Check values
	if keepaliveInterval < 5*time.Second {
		return errors.New("keepalive interval cannot be lower than five seconds")
	} else if managerInterval < 5*time.Second {
		return errors.New("manager interval cannot be lower than five seconds")
	} else if cacheDuration > 0 && cacheDuration < managerInterval {
		return errors.New("cache duration cannot be lower than manager interval")
	} else if attachmentCacheDir != "" && baseURL == "" {
		return errors.New("if attachment-cache-dir is set, base-url must also be set")
	} else if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err != nil {
			return fmt.Errorf("if set, base-url must be a valid URL, e.g. https://ntfy.mydomain.com: %v", err)
		} else if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("if set, base-url must be a valid URL starting with http:// or https://, e.g. https://ntfy.mydomain.com")
		} else if u.Path != "" {
			return fmt.Errorf("if set, base-url must not have a path (%s), as hosting ntfy on a sub-path is not supported, e.g. https://ntfy.mydomain.com", u.Path)
		}
	} else if enableSignup && !enableLogin {
		return errors.New("cannot set enable-signup without also setting enable-login")
	}

	// Backwards compatibility
	if webRoot == "app" {
		webRoot = "/"
	} else if webRoot == "home" {
		webRoot = "/app"
	} else if webRoot == "disable" {
		webRoot = ""
	} else if !strings.HasPrefix(webRoot, "/") {
		webRoot = "/" + webRoot
	}

	// Default auth permissions
	authDefault, err := user.ParsePermission(authDefaultAccess)
	if err != nil {
		return errors.New("if set, auth-default-access must start set to 'read-write', 'read-only', 'write-only' or 'deny-all'")
	}

	// Special case: Unset default
	if listenHTTP == "-" {
		listenHTTP = ""
	}

	// Resolve hosts
	visitorRequestLimitExemptIPs := make([]netip.Prefix, 0)
	for _, host := range visitorRequestLimitExemptHosts {
		ips, err := parseIPHostPrefix(host)
		if err != nil {
			log.Warn("cannot resolve host %s: %s, ignoring visitor request exemption", host, err.Error())
			continue
		}
		visitorRequestLimitExemptIPs = append(visitorRequestLimitExemptIPs, ips...)
	}

	// Add default forbidden topics
	disallowedTopics = append(disallowedTopics, server.DefaultDisallowedTopics...)

	// Run server
	conf := server.NewConfig()
	conf.File = config
	conf.BaseURL = baseURL
	conf.ListenHTTP = listenHTTP
	conf.ListenUnix = listenUnix
	conf.ListenUnixMode = fs.FileMode(listenUnixMode)
	conf.CacheFile = cacheFile
	conf.CacheDuration = cacheDuration
	conf.CacheStartupQueries = cacheStartupQueries
	conf.CacheBatchSize = cacheBatchSize
	conf.CacheBatchTimeout = cacheBatchTimeout
	conf.AuthFile = authFile
	conf.AuthStartupQueries = authStartupQueries
	conf.AuthDefault = authDefault
	conf.AttachmentCacheDir = attachmentCacheDir
	conf.AttachmentTotalSizeLimit = attachmentTotalSizeLimit
	conf.AttachmentFileSizeLimit = attachmentFileSizeLimit
	conf.AttachmentExpiryDuration = attachmentExpiryDuration
	conf.KeepaliveInterval = keepaliveInterval
	conf.ManagerInterval = managerInterval
	conf.DisallowedTopics = disallowedTopics
	conf.WebRoot = webRoot
	conf.MessageSizeLimit = int(messageSizeLimit)
	conf.MessageDelayMax = messageDelayLimit
	conf.TotalTopicLimit = totalTopicLimit
	conf.VisitorSubscriptionLimit = visitorSubscriptionLimit
	conf.VisitorAttachmentTotalSizeLimit = visitorAttachmentTotalSizeLimit
	conf.VisitorAttachmentDailyBandwidthLimit = visitorAttachmentDailyBandwidthLimit
	conf.VisitorRequestLimitBurst = visitorRequestLimitBurst
	conf.VisitorRequestLimitReplenish = visitorRequestLimitReplenish
	conf.VisitorRequestExemptIPAddrs = visitorRequestLimitExemptIPs
	conf.VisitorMessageDailyLimit = visitorMessageDailyLimit
	conf.VisitorEmailLimitBurst = visitorEmailLimitBurst
	conf.VisitorEmailLimitReplenish = visitorEmailLimitReplenish
	conf.VisitorSubscriberRateLimiting = visitorSubscriberRateLimiting
	conf.BehindProxy = behindProxy
	conf.EnableSignup = enableSignup
	conf.EnableLogin = enableLogin
	conf.EnableReservations = enableReservations
	conf.Version = c.App.Version

	// Set up hot-reloading of config
	go sigHandlerConfigReload(config)

	// Run server
	s, err := server.New(conf)
	if err != nil {
		log.Fatal(err.Error())
	} else if err := s.Run(); err != nil {
		log.Fatal(err.Error())
	}
	log.Info("Exiting.")
	return nil
}

func sigHandlerConfigReload(config string) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	for range sigs {
		log.Info("Partially hot reloading configuration ...")
		inputSource, err := newYamlSourceFromFile(config, flagsServe)
		if err != nil {
			log.Warn("Hot reload failed: %s", err.Error())
			continue
		}
		if err := reloadLogLevel(inputSource); err != nil {
			log.Warn("Reloading log level failed: %s", err.Error())
		}
	}
}

func parseIPHostPrefix(host string) (prefixes []netip.Prefix, err error) {
	// Try parsing as prefix, e.g. 10.0.1.0/24
	prefix, err := netip.ParsePrefix(host)
	if err == nil {
		prefixes = append(prefixes, prefix.Masked())
		return prefixes, nil
	}
	// Not a prefix, parse as host or IP (LookupHost passes through an IP as is)
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	for _, ipStr := range ips {
		ip, err := netip.ParseAddr(ipStr)
		if err == nil {
			prefix, err := ip.Prefix(ip.BitLen())
			if err != nil {
				return nil, fmt.Errorf("%s successfully parsed but unable to make prefix: %s", ip.String(), err.Error())
			}
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return
}

func reloadLogLevel(inputSource altsrc.InputSourceContext) error {
	newLevelStr, err := inputSource.String("log-level")
	if err != nil {
		return fmt.Errorf("cannot load log level: %s", err.Error())
	}
	overrides, err := inputSource.StringSlice("log-level-overrides")
	if err != nil {
		return fmt.Errorf("cannot load log level overrides (1): %s", err.Error())
	}
	log.ResetLevelOverrides()
	if err := applyLogLevelOverrides(overrides); err != nil {
		return fmt.Errorf("cannot load log level overrides (2): %s", err.Error())
	}
	log.SetLevel(log.ToLevel(newLevelStr))
	if len(overrides) > 0 {
		log.Info("Log level is %v, %d override(s) in place", strings.ToUpper(newLevelStr), len(overrides))
	} else {
		log.Info("Log level is %v", strings.ToUpper(newLevelStr))
	}
	return nil
}
