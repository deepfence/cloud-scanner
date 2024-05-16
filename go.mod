module github.com/deepfence/cloud-scanner

go 1.21

replace github.com/deepfence/golang_deepfence_sdk/client => ./golang_deepfence_sdk/client

replace github.com/deepfence/golang_deepfence_sdk/utils => ./golang_deepfence_sdk/utils

require (
	github.com/Jeffail/tunny v0.1.4
	github.com/aws/aws-sdk-go v1.50.19
	github.com/deepfence/ThreatMapper/deepfence_utils v0.0.0-20240418094410-eadc88e3d9f5
	github.com/deepfence/golang_deepfence_sdk/client v0.0.0-00010101000000-000000000000
	github.com/deepfence/golang_deepfence_sdk/utils v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.5.0
	github.com/lib/pq v1.10.9
	github.com/rs/zerolog v1.31.0
)

require (
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.5 // indirect
	github.com/hibiken/asynq v0.24.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.4 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.0.18 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pierrec/lz4/v4 v4.1.19 // indirect
	github.com/redis/go-redis/v9 v9.4.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/twmb/franz-go v1.15.4 // indirect
	github.com/twmb/franz-go/pkg/kadm v1.10.0 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.7.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)
