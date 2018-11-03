package provider

import (
	"github.com/globbie/gauth/pkg/auth/ctx"
)

type IdentityProvider interface {
	Login(ctx *ctx.Ctx)
	Logout(ctx *ctx.Ctx)
	Register(ctx *ctx.Ctx)
	Callback(ctx *ctx.Ctx)
}
