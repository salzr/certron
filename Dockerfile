FROM golang:alpine as builder
RUN mkdir /build
ADD . /build/
ENV CGO_ENABLED 0
WORKDIR /build
RUN go build -mod=vendor -trimpath -o certron .

FROM alpine
RUN adduser -S -D -H -h /app certron
USER certron
COPY --from=builder /build/certron /app/
WORKDIR /app
ENTRYPOINT ["./certron"]