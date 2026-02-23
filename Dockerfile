FROM golang:1.24-alpine AS build
RUN apk add --no-cache git
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o webhook -ldflags '-w -s' .

FROM --platform=linux/amd64 alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /workspace/webhook /usr/local/bin/webhook
USER 65534:65534
ENTRYPOINT ["webhook"]
