FROM golang:1.22-alpine as builder

WORKDIR /app

COPY . /app/

RUN go build .

FROM alpine:3.19 as final

COPY --from=builder /app/microproxy /usr/local/bin/

CMD [ "microproxy", "-config", "/usr/local/etc/microproxy.toml" ]
