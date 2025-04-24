package utils

import (
	"github.com/gorilla/sessions"
)

var Store = sessions.NewCookieStore([]byte("test-secret"))
