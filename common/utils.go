package common

const (
	LOCALHOST_REGEX        = `^((?P<protocol>http[s]?)://)?(?P<host>(localhost|(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))(:(?P<port>(\d+|__\w+__)))?$`
	LOCALHOST_REGEX_PREFIX = `^((?P<protocol>http[s]?)://)?(?P<host>(localhost|(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}))(:(?P<port>(\d+|__\w+__))).*`
)

type UrlMatchResult struct {
	Protocol string `regroup:"protocol"`
	Host     string `regroup:"host"`
	Port     int    `regroup:"port"`
}

func MergeMaps[M ~map[K]V, K comparable, V any](src ...M) M {
	merged := make(M)
	for _, m := range src {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}
