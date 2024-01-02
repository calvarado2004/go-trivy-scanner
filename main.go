package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os/exec"
)

type ImageReviewRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       Spec   `json:"spec"`
}

type Spec struct {
	Containers  []Container       `json:"containers"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Namespace   string            `json:"namespace"`
}

type ImageReviewResponse struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     Status `json:"status"`
}

type Status struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type Container struct {
	Image string `json:"image"`
}

func main() {
	r := gin.Default()

	r.POST("/scan", func(c *gin.Context) {
		var req ImageReviewRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var insecureContainers []string
		for _, container := range req.Spec.Containers {
			if !isContainerSecure(container.Image) {
				insecureContainers = append(insecureContainers, container.Image)
			}
		}

		var response ImageReviewResponse
		if len(insecureContainers) == 0 {
			response = createImageReviewResponse(true, "No more than 3 CRITICAL vulnerabilities found, accepted")
		} else {
			message := fmt.Sprintf("More than 3 CRITICAL vulnerabilities, rejected: %v", insecureContainers)
			response = createImageReviewResponse(false, message)
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
	vulnerabilities, ok := data["Results"].([]interface{})
	if !ok {
		return 0
	}

	count := 0
	for _, v := range vulnerabilities {
		if vulnerable, ok := v.(map[string]interface{}); ok {
			if vulnerableList, ok := vulnerable["Vulnerabilities"].([]interface{}); ok {
				for range vulnerableList {
					count++
				}
			}
		}
	}
	return count
}

func createImageReviewResponse(allowed bool, reason string) ImageReviewResponse {
	return ImageReviewResponse{
		APIVersion: "imagepolicy.k8s.io/v1alpha1",
		Kind:       "ImageReview",
		Status:     Status{Allowed: allowed, Reason: reason},
	}
}
