# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/gosamba ./cmd/gosamba

FROM scratch
COPY --from=build /out/gosamba /usr/local/bin/gosamba

# The numeric identity also works in scratch, which has no /etc/passwd.
USER 65532:65532

# Publish host port 445 to this unprivileged container port.
EXPOSE 1445

ENTRYPOINT ["/usr/local/bin/gosamba"]
CMD ["--listen", ":1445", "--mdns=false"]
