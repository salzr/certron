FROM golang:alpine as builder
RUN apk update && apk add make
RUN mkdir /build
ADD . /build/
ENV CGO_ENABLED 0
WORKDIR /build
RUN make build

FROM alpine
RUN adduser -S -D -H -h /app certron
RUN mkdir /app
RUN chown -R certron /app
USER certron
COPY --from=builder /build/certron /app/
WORKDIR /app
ENTRYPOINT ["./certron"]