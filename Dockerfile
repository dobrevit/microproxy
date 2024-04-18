FROM golang:1.22-alpine as builder

RUN apk -U --no-cache add curl ca-certificates python3

WORKDIR /app

COPY . /app/

RUN go test ./... && go build .

FROM alpine:3.19 as final

COPY --from=builder /app/microproxy /usr/local/bin/

RUN apk -U --no-cache add ca-certificates

CMD [ "microproxy", "-config", "/usr/local/etc/microproxy.toml" ]
