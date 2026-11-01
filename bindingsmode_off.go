//go:build !bindings

package main

// runningForBindings is false in every build a user can run; see
// bindingsmode_on.go for the bindings-generation build the Wails CLI makes.
func runningForBindings() bool { return false }
