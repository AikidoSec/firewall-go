package aikido_types

type HandlerFunction func(map[string]interface{}) string

type Method struct {
	ClassName  string
	MethodName string
}
