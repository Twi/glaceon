FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN --network=none go build -o /go/bin/glaceon ./cmd/glaceon

FROM alpine:latest
COPY --from=builder /go/bin/glaceon /usr/bin/glaceon
ENTRYPOINT ["/usr/bin/glaceon"]