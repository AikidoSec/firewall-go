package providers

type Usage struct {
	Provider, Model string
	Input, Output   int64
	CacheRead       int64
	CacheWrite      int64
}
