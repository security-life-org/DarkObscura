//go:build linux

package ebpf

import (
	"context"
	"errors"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// socketFilterProgType is the BPF program type we probe for kernel support.
const socketFilterProgType = ebpf.SocketFilter

// linuxObserver attaches eBPF programs for kernel-level flow visibility.
//
// The compiled BPF object is produced out-of-band by bpf2go (`go generate`) from
// a small C program in this directory; until it is generated, Start reports that
// the compiled program is absent while Available() still reflects genuine kernel
// and privilege support. This keeps the Go core building everywhere without a
// clang toolchain, and lets an operator enable the fast path where supported.
type linuxObserver struct{}

// NewObserver returns the Linux eBPF-backed Observer.
func NewObserver() Observer { return &linuxObserver{} }

// Available reports true only when the process can actually load BPF programs:
// running as root (or with CAP_BPF) and on a kernel that supports the socket
// filter program type.
func (o *linuxObserver) Available() bool {
	if os.Geteuid() != 0 {
		// A finer CAP_BPF check is possible; euid==0 is the common case.
		return false
	}
	if err := features.HaveProgramType(socketFilterProgType); err != nil {
		return false
	}
	return true
}

func (o *linuxObserver) Start(ctx context.Context) (<-chan KernelEvent, error) {
	if !o.Available() {
		return nil, errors.New("ebpf: kernel BPF unavailable or insufficient privileges (need root/CAP_BPF)")
	}
	// Raise the RLIMIT_MEMLOCK so BPF maps can be created on older kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	// The compiled BPF object + ring-buffer reader are wired here once generated
	// via `go generate ./internal/ebpf`. Until then, fail closed rather than
	// silently pretend the fast path is active.
	return nil, errors.New("ebpf: compiled BPF object not bundled; run `go generate ./internal/ebpf` (bpf2go) to enable the kernel fast path")
}

func (o *linuxObserver) Close() error { return nil }
