FROM golang:1.25-alpine as builder

RUN apk -U --no-cache add curl ca-certificates python3

WORKDIR /app

COPY . /app/

# test first, so that a failing test stops the image from being built at all
RUN go test ./... && go build -o microproxy ./cmd/microproxy

FROM alpine:3.23 as final

COPY --from=builder /app/microproxy /usr/local/bin/

RUN apk -U --no-cache add ca-certificates

CMD [ "microproxy", "-config", "/usr/local/etc/microproxy.toml" ]
