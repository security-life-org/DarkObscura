package grpcfuzz

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func TestFuzz_ReflectionEnumerateInvoke(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	healthpb.RegisterHealthServer(s, health.NewServer())
	reflection.Register(s) // enable server reflection
	go s.Serve(lis)
	defer s.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := Fuzz(ctx, lis.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	// reflection-enabled confirmed finding
	var reflFinding bool
	for _, f := range res.Findings {
		if f.Class == "grpc-reflection-enabled" && f.Confidence == "confirmed" {
			reflFinding = true
		}
	}
	if !reflFinding {
		t.Error("expected confirmed grpc-reflection-enabled finding")
	}
	// health service + Check method discovered and invoked
	var foundHealth, invokedCheck bool
	for _, svc := range res.Services {
		if svc.Name == "grpc.health.v1.Health" {
			foundHealth = true
			for _, m := range svc.Methods {
				if m.Name == "Check" && m.InvokeStatus != "" {
					invokedCheck = true
				}
			}
		}
	}
	if !foundHealth {
		t.Errorf("expected grpc.health.v1.Health service via reflection; got %v", res.Services)
	}
	if !invokedCheck {
		t.Error("expected the unary Check method to be invoked with a status")
	}
}
