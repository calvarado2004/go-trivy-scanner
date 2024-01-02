package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os/exec"
)

type AdmissionReview struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Response   Response `json:"response"`
}

type Response struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Status  Status `json:"status"`
}

type Status struct {
	Message string `json:"message"`
}

type Container struct {
	Image string `json:"image"`
}

type AdmissionRequest struct {
	UID    string `json:"uid"`
	Object Object `json:"object"`
}

type Object struct {
	Spec Spec `json:"spec"`
}

type Spec struct {
	Containers []Container `json:"containers"`
}

func main() {
	r := gin.Default()

	r.POST("/validate", func(c *gin.Context) {
		var req AdmissionRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		insecureContainers := []string{}
		for _, container := range req.Object.Spec.Containers {
			if !isContainerSecure(container.Image) {
				insecureContainers = append(insecureContainers, container.Image)
			}
		}

		var response AdmissionReview
		if len(insecureContainers) == 0 {
			response = createAdmissionResponse(true, "All containers are secure")
		} else {
			message := fmt.Sprintf("More than 3 CRITICAL vulnerabilities, rejected: %v", insecureContainers)
			response = createAdmissionResponse(false, message)
		}
		c.JSON(http.StatusOK, response)
	})

	log.Fatal(r.Run(":8080"))
}

func isContainerSecure(image string) bool {
	cmd := exec.Command("/usr/local/bin/trivy", "image", "--scanners", "vuln", "--format", "json", "--severity", "CRITICAL", image)
	log.Printf("Running command: %s", cmd.String())
	output, err := cmd.Output()
	if err != nil {
		log.Println("Error running trivy:", err)
		return false
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		log.Println("Error unmarshalling JSON:", err)
		return false
	}

	count := countCriticalVulnerabilities(result)
	if count >= 3 {
		log.Printf("Found %d critical vulnerabilities in %s", count, image)
		return false
	}

	return true
}

func countCriticalVulnerabilities(data map[string]interface{}) int {
	vulns, ok := data["Results"].([]interface{})
	if !ok {
		return 0
	}

	count := 0
	for _, v := range vulns {
		if vuln, ok := v.(map[string]interface{}); ok {
			if vulnList, ok := vuln["Vulnerabilities"].([]interface{}); ok {
				for range vulnList {
					count++
				}
			}
		}
	}
	return count
}

func createAdmissionResponse(allowed bool, message string) AdmissionReview {
	return AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response: Response{
			UID:     uuid.New().String(),
			Allowed: allowed,
			Status:  Status{Message: message},
		},
	}
}
