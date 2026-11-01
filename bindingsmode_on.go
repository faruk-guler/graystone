//go:build bindings

package main

// runningForBindings reports that this process was started by the Wails CLI to
// dump the JS bindings, not by a user. `wails build` compiles this same main
// package with the "bindings" tag and runs the result on the build machine, so
// anything that touches the real user profile has to step aside: on a build
// server or a developer's second machine that work would move files nobody ever
// asked it to move.
func runningForBindings() bool { return true }
