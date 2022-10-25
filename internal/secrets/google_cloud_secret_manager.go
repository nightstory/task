package secrets

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/api/option"
	"hash/crc32"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// GoogleCloudSecretManager handles the Google Cloud auth,
// and allows to access and validate the secrets from Google Cloud Secrets Manager
type GoogleCloudSecretManager struct {
	client *secretmanager.Client
	ctx    context.Context

	defaultProject string
	defaultVersion string
}

// Close closes the client connection (gRPC, etc)
func (m *GoogleCloudSecretManager) Close() error {
	return m.client.Close()
}

// NewGoogleCloudSecretManager creates a new manager.
// If no credentials are available, the current environment auth will be used (gcloud auth, etc)
func NewGoogleCloudSecretManager() (*GoogleCloudSecretManager, error) {
	credentials := os.Getenv("TASK_GCP_CREDENTIALS_JSON")
	defaultProject := os.Getenv("TASK_GCP_DEFAULT_PROJECT")
	defaultVersion := os.Getenv("TASK_GCP_SECRET_DEFAULT_VERSION")

	if defaultVersion == "" {
		defaultVersion = "latest"
	}

	ctx := context.Background()
	options := make([]option.ClientOption, 0)

	if len(credentials) > 0 {
		options = append(options, option.WithCredentialsJSON([]byte(credentials)))
	}

	secretClient, err := secretmanager.NewClient(ctx, options...)
	if err != nil {
		return nil, err
	}

	return &GoogleCloudSecretManager{
		client:         secretClient,
		ctx:            ctx,
		defaultProject: defaultProject,
		defaultVersion: defaultVersion,
	}, nil
}

// GetValue returns the string value for a given secret ID.
// Supported id formats are:
// - projects/my-project/secrets/my-secret-id/versions/my-secret-version
// - projects/my-project/secrets/my-secret-id
// - my-secret-id (if the default project env variable is specified)
func (m *GoogleCloudSecretManager) GetValue(id string) (string, error) {
	ref, err := m.prepareReference(id)
	if err != nil {
		return "", err
	}

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: ref,
	}

	// Call the API.
	result, err := m.client.AccessSecretVersion(m.ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret version: %v", err)
	}

	// Verify the data checksum.
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(result.Payload.Data, crc32c))
	if checksum != *result.Payload.DataCrc32C {
		return "", errors.New("data corruption detected")
	}

	return string(result.Payload.Data), nil
}

// prepareReference unifies the secret ID from any supported input format
func (m *GoogleCloudSecretManager) prepareReference(id string) (string, error) {
	parts := strings.Split(id, "/")

	for _, part := range parts {
		if len(part) == 0 {
			return "", errors.New("broken gcp secret format")
		}
	}

	switch len(parts) {
	case 1:
		if m.defaultProject == "" {
			return "", errors.New("gcp default project is not set and project is not specified in secret")
		}

		return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", m.defaultProject, id, m.defaultVersion), nil
	case 4:
		return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", parts[1], parts[3], m.defaultVersion), nil
	case 6:
		return id, nil
	default:
		return "", errors.New("broken gcp secret format")
	}
}
