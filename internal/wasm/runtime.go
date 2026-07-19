// Package wasm hosts DarkObscura's plugin system. Plugins are sandboxed
// WebAssembly modules (compilable from Go, Rust, C++, TinyGo, etc.) run on the
// pure-Go wazero runtime — no CGO, memory-isolated, and time-bounded.
//
// # Host ABI
//
// The host exports these functions in the "dobscura" module namespace:
//
//	log(ptr, len)             — write a UTF-8 log line
//	emit_finding(ptr, len)    — report a JSON finding back to the host
//
// A plugin must export:
//
//	memory                    — its linear memory
//	alloc(size) -> ptr        — allocate `size` bytes, return pointer
//	analyze(ptr, len)         — entry point; receives a JSON flow at [ptr,ptr+len)
package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Finding is what a plugin emits back to the host.
type Finding struct {
	Plugin   string `json:"plugin"`
	Class    string `json:"class"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// Runtime compiles and runs WASM plugins.
type Runtime struct {
	rt      wazero.Runtime
	timeout time.Duration
}

// invocation carries per-call state (collected findings, logs) via context.
type invocation struct {
	plugin   string
	findings []Finding
	logs     []string
}

type ctxKey struct{}

// NewRuntime creates a wazero runtime with the DarkObscura host module installed.
func NewRuntime(ctx context.Context) (*Runtime, error) {
	rt := wazero.NewRuntime(ctx)
	r := &Runtime{rt: rt, timeout: 5 * time.Second}

	// Go-compiled wasip1 plugins import the WASI preview1 module for runtime init.
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	_, err := rt.NewHostModuleBuilder("dobscura").
		NewFunctionBuilder().WithFunc(hostLog).Export("log").
		NewFunctionBuilder().WithFunc(hostEmitFinding).Export("emit_finding").
		Instantiate(ctx)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("wasm: install host module: %w", err)
	}
	return r, nil
}

// Close releases the runtime.
func (r *Runtime) Close(ctx context.Context) error { return r.rt.Close(ctx) }

// Run instantiates the given plugin module bytes, feeds it flowJSON via the ABI,
// and returns any findings it emits. Execution is bounded by the runtime timeout.
func (r *Runtime) Run(ctx context.Context, pluginName string, module []byte, flowJSON []byte) ([]Finding, []string, error) {
	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	inv := &invocation{plugin: pluginName}
	runCtx = context.WithValue(runCtx, ctxKey{}, inv)

	compiled, err := r.rt.CompileModule(runCtx, module)
	if err != nil {
		return nil, nil, fmt.Errorf("wasm: compile %s: %w", pluginName, err)
	}
	defer compiled.Close(runCtx)

	mod, err := r.rt.InstantiateModule(runCtx, compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, nil, fmt.Errorf("wasm: instantiate %s: %w", pluginName, err)
	}
	defer mod.Close(runCtx)

	alloc := mod.ExportedFunction("alloc")
	analyze := mod.ExportedFunction("analyze")
	if alloc == nil || analyze == nil || mod.Memory() == nil {
		return nil, nil, fmt.Errorf("wasm: plugin %s missing required exports (alloc/analyze/memory)", pluginName)
	}

	// Allocate guest memory and copy the flow JSON in.
	res, err := alloc.Call(runCtx, uint64(len(flowJSON)))
	if err != nil {
		return nil, nil, fmt.Errorf("wasm: alloc failed: %w", err)
	}
	ptr := uint32(res[0])
	if !mod.Memory().Write(ptr, flowJSON) {
		return nil, nil, fmt.Errorf("wasm: failed to write flow into guest memory")
	}

	if _, err := analyze.Call(runCtx, uint64(ptr), uint64(len(flowJSON))); err != nil {
		return nil, nil, fmt.Errorf("wasm: analyze failed: %w", err)
	}
	return inv.findings, inv.logs, nil
}

// hostLog implements dobscura.log(ptr, len).
func hostLog(ctx context.Context, m api.Module, ptr, length uint32) {
	inv, _ := ctx.Value(ctxKey{}).(*invocation)
	data, ok := m.Memory().Read(ptr, length)
	if !ok || inv == nil {
		return
	}
	inv.logs = append(inv.logs, string(data))
}

// hostEmitFinding implements dobscura.emit_finding(ptr, len). The payload is a
// JSON Finding.
func hostEmitFinding(ctx context.Context, m api.Module, ptr, length uint32) {
	inv, _ := ctx.Value(ctxKey{}).(*invocation)
	data, ok := m.Memory().Read(ptr, length)
	if !ok || inv == nil {
		return
	}
	var f Finding
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	f.Plugin = inv.plugin
	inv.findings = append(inv.findings, f)
}
