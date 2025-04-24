package db

import (
	"auth_go/dbcommon"
)

type Db struct {
	Queries *dbcommon.Queries
}

func NewDb(queries *dbcommon.Queries) *Db {
	return &Db{
		Queries: queries,
	}
}
