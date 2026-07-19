# ---- build stage ----
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
# CGO-free static binary (all deps are pure Go).
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/dobscura ./cmd/cli

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="DarkObscura" \
      org.opencontainers.image.description="Precision web security testing platform" \
      org.opencontainers.image.source="https://github.com/security-life-org/DarkObscura"
COPY --from=build /out/dobscura /usr/local/bin/dobscura
USER nonroot:nonroot
EXPOSE 8422
# Bind to all interfaces inside the container; auth token is required by default.
# Pass --scope to restrict the engagement, and provide --token via secret.
ENTRYPOINT ["/usr/local/bin/dobscura"]
CMD ["--gui", "--gui-addr", "0.0.0.0:8422", "--no-open"]
