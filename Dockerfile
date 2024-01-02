FROM  --platform=linux/amd64 docker.io/golang:latest as builder

WORKDIR /app

COPY go.mod main.go go.sum ./

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-trivy-scanner .


FROM --platform=linux/amd64 busybox:latest

USER root
# Download trivy scanner binary
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.1; \
    chmod +x /usr/local/bin/trivy; \
    mkdir /root/.cache; \
    chown -R 1000:1000 /root/.cache

COPY --from=builder /app/go-trivy-scanner /usr/local/bin/go-trivy-scanner

USER 1000

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/go-trivy-scanner"]