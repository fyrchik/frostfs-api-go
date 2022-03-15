module github.com/nspcc-dev/neofs-api-go/v2

go 1.16

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/nspcc-dev/neofs-crypto v0.3.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f // indirect
	golang.org/x/sys v0.0.0-20211019181941-9d821ace8654 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/grpc v1.41.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

// This version uses broken NeoFS API with incompatible signature
// definitions. See fix in https://github.com/nspcc-dev/neofs-api/pull/203
retract v2.12.0
