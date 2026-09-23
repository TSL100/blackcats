module evilgophish

go 1.22

require (
	evilgophish/shared v0.0.0
	github.com/gophish/gophish v0.0.0
	github.com/gorilla/csrf v1.6.2
	github.com/jinzhu/gorm v1.9.12
	github.com/kgretzky/evilginx2 v0.0.0
)

require (
	bitbucket.org/liamstask/goose v0.0.0-20150115234039-8488cc47d90c // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/PuerkitoBio/goquery v1.5.0 // indirect
	github.com/andybalholm/cascadia v1.0.0 // indirect
	github.com/caddyserver/certmagic v0.20.0 // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/elazarl/goproxy v0.0.0-20220529153421-8ea89ba92021 // indirect
	github.com/emersion/go-imap v1.0.4 // indirect
	github.com/emersion/go-message v0.12.0 // indirect
	github.com/emersion/go-sasl v0.0.0-20191210011802-430746ea8b9b // indirect
	github.com/emersion/go-textwrapper v0.0.0-20160606182133-d0e65e56babe // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-acme/lego/v3 v3.1.0 // indirect
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/gophish/gomail v0.0.0-20200818021916-1f6d0dfd512e // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/handlers v1.4.2 // indirect
	github.com/gorilla/mux v1.7.3 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.2.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/go-vhost v0.0.0-20160627193104-06d84117953b // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jordan-wright/email v4.0.1-0.20200824153738-3f5bafa1cd84+incompatible // indirect
	github.com/jordan-wright/unindexed v0.0.0-20181209214434-78fa79113c0f // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/kylelemons/go-gypsy v0.0.0-20160905020020-08cad365cd28 // indirect
	github.com/lib/pq v1.1.1 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/miekg/dns v1.1.58 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/mwitkow/go-http-dialer v0.0.0-20161116154839-378f744fb2b8 // indirect
	github.com/oschwald/maxminddb-golang v1.6.0 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	github.com/spf13/afero v1.8.1 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.10.1 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tidwall/btree v0.0.0-20170113224114-9876f1454cf0 // indirect
	github.com/tidwall/buntdb v1.1.0 // indirect
	github.com/tidwall/gjson v1.14.0 // indirect
	github.com/tidwall/grect v0.0.0-20161006141115-ba9a043346eb // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/rtree v0.0.0-20180113144539-6cd427091e0e // indirect
	github.com/tidwall/tinyqueue v0.0.0-20180302190814-1e39f5511563 // indirect
	github.com/twilio/twilio-go v0.26.0 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	github.com/ziutek/mymysql v1.5.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.20.0 // indirect
	golang.org/x/mod v0.15.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	golang.org/x/tools v0.18.0 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace (
	evilgophish/shared => ./shared
	github.com/gophish/gophish => ./gophish
	github.com/kgretzky/evilginx2 => ./evilginx3
)
