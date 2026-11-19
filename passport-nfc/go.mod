module github.com/vaultys/vaultysid/passport-nfc

go 1.26.10

require (
	github.com/ebfe/scard v0.0.0-20241214075232-7af069cabc25
	github.com/gmrtd/gmrtd v1.10.0
)

require (
	github.com/RyuaNerin/elliptic2 v1.3.0 // indirect
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1 // indirect
	github.com/fxamacker/cbor/v2 v2.10.0 // indirect
	github.com/osanderson/brainpool v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)

replace github.com/osanderson/brainpool => ./internal/brainpool
