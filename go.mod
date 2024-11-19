module heckel.io/ntfy/v2

go 1.22

toolchain go1.22.1

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/gabriel-vasile/mimetype v1.4.5
	github.com/gorilla/websocket v1.5.3
	github.com/mattn/go-sqlite3 v1.14.23
	github.com/olebedev/when v1.0.0
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/urfave/cli/v2 v2.27.4
	golang.org/x/crypto v0.27.0
	golang.org/x/sync v0.8.0
	golang.org/x/term v0.24.0
	golang.org/x/time v0.6.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/emersion/go-smtp => github.com/emersion/go-smtp v0.17.0 // Pin version due to breaking changes, see #839

require github.com/pkg/errors v0.9.1 // indirect

require github.com/SherClockHolmes/webpush-go v1.3.0

require (
	github.com/AlekSi/pointer v1.2.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
