# syntax=docker/dockerfile:1

# Stage 1: build the binary (static, no CGO — modernc.org/sqlite is pure Go)
FROM golang:1.26.3-bookworm AS builder

WORKDIR /src

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build a static binary (CGO_ENABLED=0, strip symbols, no debug info)
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/keyvault ./cmd/keyvault

# Stage 2: minimal runtime image (Alpine, dedicated non-root user)
FROM alpine:3.21

# Create a dedicated non-root user/group for the application
RUN addgroup -S keyvault && adduser -S -G keyvault keyvault

# data/ volume mounted at /data at runtime (persistent database)
WORKDIR /data
USER keyvault

# Copy the static binary from the builder stage
COPY --from=builder /bin/keyvault /usr/local/bin/keyvault

ENTRYPOINT ["/usr/local/bin/keyvault"]
# amendment 13: the container binds 0.0.0.0:8080 internally
CMD ["-addr", "0.0.0.0:8080", "-data-dir", "/data"]
