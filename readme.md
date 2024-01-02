

#  Container Security Validator

## Description
This project implements a web service in Go, using Gin framework, that validates Kubernetes container images for security vulnerabilities. It leverages Trivy, a comprehensive vulnerability scanner, to check each container image for critical vulnerabilities and then decides whether to allow or reject these containers based on the scan results.

## Installation

### Prerequisites
- Go (version 1.21)
- Trivy installed on your system

### Setup with Docker

You can build the docker image using the Dockerfile provided in the project. To do so, run the following command:

```bash
docker build -t go-trivy-scanner .
```

Once the image is built, you can run the container with the following command:

```bash
docker run -p 8080:8080 go-trivy-scanner
```

### Steps for running the service locally

1. Build the project:
   ```
   go build
   ```

## Usage

Run the service:
```
./go-trivy-scanner
```

To validate a container image, send a POST request to `/validate` with the container image details in JSON format. For example:

```bash
curl -X POST http://localhost:8080/validate -d '{"uid":"1234","object":{"spec":{"containers":[{"image":"your-container-image"}]}}}'
```

The service will return a JSON response with the validation result. For example:

```json
{
    "uid": "1234",
    "allowed": true,
    "message": "Container image is allowed"
}
```

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Carlos Alvarado


## Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Google UUID](https://github.com/google/uuid)
