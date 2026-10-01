FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wcdscan ./cmd/wcdscan

FROM alpine:3.20
RUN adduser -D -u 10001 wcdscan
USER wcdscan
COPY --from=build /out/wcdscan /usr/local/bin/wcdscan
ENTRYPOINT ["wcdscan"]
