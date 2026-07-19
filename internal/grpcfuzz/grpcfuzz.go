// Package grpcfuzz probes gRPC services — a surface HTTP scanners cannot touch.
// Using gRPC server reflection it enumerates the exposed services and methods
// (no .proto files needed), then invokes each unary method with a dynamically
// constructed empty message to observe the returned status code. Two things are
// reported deterministically: reflection being enabled at all (an information-
// disclosure finding, analogous to GraphQL introspection), and methods that
// answer an unauthenticated, empty request with OK — a strong signal of missing
// authentication/input validation. Per the platform's rule, only deterministic
// observations are labeled confirmed; method-invocation results are recon.
package grpcfuzz

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Method is one RPC method on a service.
type Method struct {
	Name         string
	FullName     string
	ClientStream bool
	ServerStream bool
	InvokeStatus string // gRPC status code observed when invoked with an empty message ("" = not invoked)
}

// Service is a reflected gRPC service.
type Service struct {
	Name    string
	Methods []Method
}

// Finding is a confirmed/possible gRPC issue.
type Finding struct {
	Class      string
	Confidence string // "confirmed" | "possible"
	Detail     string
	Evidence   []string
}

// Result is the outcome of a gRPC probe.
type Result struct {
	Services []Service
	Findings []Finding
}

// dialer opens a gRPC connection (plaintext, or TLS when useTLS is set).
func dial(target string, useTLS bool) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if useTLS {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	} else {
		creds = insecure.NewCredentials()
	}
	return grpc.NewClient(target, grpc.WithTransportCredentials(creds))
}

// Enumerate lists the services and methods exposed via server reflection.
func Enumerate(ctx context.Context, target string, useTLS bool) (*Result, error) {
	conn, err := dial(target, useTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return enumerate(ctx, conn)
}

func enumerate(ctx context.Context, conn *grpc.ClientConn) (*Result, error) {
	rc := grpcreflect.NewClientAuto(ctx, conn)
	defer rc.Reset()

	svcNames, err := rc.ListServices()
	if err != nil {
		return nil, fmt.Errorf("reflection unavailable: %w", err)
	}
	res := &Result{}
	// Reflection responded → deterministic info-disclosure finding.
	res.Findings = append(res.Findings, Finding{
		Class: "grpc-reflection-enabled", Confidence: "confirmed",
		Detail: fmt.Sprintf("server reflection is enabled (%d services exposed)", len(svcNames)),
		Evidence: []string{
			"verified: the gRPC server answered a reflection request and disclosed its full service/method list",
			"an attacker can map the entire API without any .proto files",
		},
	})
	for _, sn := range svcNames {
		sd, err := rc.ResolveService(sn)
		if err != nil {
			continue
		}
		svc := Service{Name: sn}
		for _, md := range sd.GetMethods() {
			svc.Methods = append(svc.Methods, Method{
				Name:         md.GetName(),
				FullName:     md.GetFullyQualifiedName(),
				ClientStream: md.IsClientStreaming(),
				ServerStream: md.IsServerStreaming(),
			})
		}
		res.Services = append(res.Services, svc)
	}
	return res, nil
}

// Fuzz enumerates then invokes every unary method with an empty message,
// recording the status code and flagging methods that accept an unauthenticated
// empty request with OK.
func Fuzz(ctx context.Context, target string, useTLS bool) (*Result, error) {
	conn, err := dial(target, useTLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res, err := enumerate(ctx, conn)
	if err != nil {
		return nil, err
	}
	rc := grpcreflect.NewClientAuto(ctx, conn)
	defer rc.Reset()
	stub := grpcdynamic.NewStub(conn)

	for si := range res.Services {
		sd, err := rc.ResolveService(res.Services[si].Name)
		if err != nil {
			continue
		}
		for mi := range res.Services[si].Methods {
			m := &res.Services[si].Methods[mi]
			if m.ClientStream || m.ServerStream {
				m.InvokeStatus = "skipped (streaming)"
				continue
			}
			md := sd.FindMethodByName(m.Name)
			if md == nil {
				continue
			}
			code := invokeUnary(ctx, stub, md)
			m.InvokeStatus = code
			if code == "OK" {
				res.Findings = append(res.Findings, Finding{
					Class: "grpc-unauthenticated-method", Confidence: "possible",
					Detail: "method " + m.FullName + " returned OK for an unauthenticated empty request",
					Evidence: []string{
						"an empty, unauthenticated invocation succeeded (status OK)",
						"possible missing authentication / input validation — verify the method should require auth",
					},
				})
			}
		}
	}
	return res, nil
}

// invokeUnary calls a unary method with an empty dynamic message and returns the
// gRPC status code as a string.
func invokeUnary(ctx context.Context, stub grpcdynamic.Stub, md *desc.MethodDescriptor) string {
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req := dynamic.NewMessage(md.GetInputType())
	_, err := stub.InvokeRpc(callCtx, md, req)
	if err == nil {
		return "OK"
	}
	if st, ok := status.FromError(err); ok {
		return st.Code().String()
	}
	return "error"
}
