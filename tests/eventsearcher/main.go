package main

import (
	"encoding/json"
	"errors"

	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/eventsearcher"
)

var (
	errNotSupported = errors.New("unsupported parameter")
)

type fsEvent struct {
	ID                string `json:"id"`
	Timestamp         int64  `json:"timestamp"`
	Action            string `json:"action"`
	Username          string `json:"username"`
	FsPath            string `json:"fs_path"`
	FsTargetPath      string `json:"fs_target_path,omitempty"`
	VirtualPath       string `json:"virtual_path"`
	VirtualTargetPath string `json:"virtual_target_path,omitempty"`
	SSHCmd            string `json:"ssh_cmd,omitempty"`
	FileSize          int64  `json:"file_size,omitempty"`
	Elapsed           int64  `json:"elapsed,omitempty"`
	Status            int    `json:"status"`
	Protocol          string `json:"protocol"`
	IP                string `json:"ip,omitempty"`
	SessionID         string `json:"session_id"`
	FsProvider        int    `json:"fs_provider"`
	Bucket            string `json:"bucket,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	OpenFlags         int    `json:"open_flags,omitempty"`
	Role              string `json:"role,omitempty"`
	InstanceID        string `json:"instance_id,omitempty"`
}

type providerEvent struct {
	ID         string `json:"id" gorm:"primaryKey"`
	Timestamp  int64  `json:"timestamp"`
	Action     string `json:"action"`
	Username   string `json:"username"`
	IP         string `json:"ip,omitempty"`
	ObjectType string `json:"object_type"`
	ObjectName string `json:"object_name"`
	ObjectData []byte `json:"object_data,omitempty"`
	Role       string `json:"role,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
}

type logEvent struct {
	ID         string `json:"id" gorm:"primaryKey"`
	Timestamp  int64  `json:"timestamp"`
	Event      int    `json:"event"`
	Protocol   string `json:"protocol,omitempty"`
	Username   string `json:"username,omitempty"`
	IP         string `json:"ip,omitempty"`
	Message    string `json:"message,omitempty"`
	Role       string `json:"role,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
}

type Searcher struct{}

func (s *Searcher) SearchFsEvents(filters *eventsearcher.FsEventSearch) ([]byte, error) {
	if filters.StartTimestamp < 0 {
		return nil, errNotSupported
	}

	results := []fsEvent{
		{
			ID:                "1",
			Timestamp:         100,
			Action:            "upload",
			Username:          "username1",
			FsPath:            "/tmp/file.txt",
			FsTargetPath:      "/tmp/target.txt",
			VirtualPath:       "file.txt",
			VirtualTargetPath: "target.txt",
			SSHCmd:            "scp",
			FileSize:          123,
			Elapsed:           1250,
			Status:            1,
			Protocol:          "SFTP",
			IP:                "::1",
			SessionID:         "1234",
			InstanceID:        "instance1",
			FsProvider:        0,
			Bucket:            "bucket",
			Endpoint:          "endpoint",
			OpenFlags:         512,
			Role:              "role1",
		},
	}

	data, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *Searcher) SearchProviderEvents(filters *eventsearcher.ProviderEventSearch) ([]byte, error) {
	if filters.StartTimestamp < 0 {
		return nil, errNotSupported
	}

	var objectData []byte
	if !filters.OmitObjectData {
		objectData = []byte("data")
	}

	results := []providerEvent{
		{
			ID:         "1",
			Timestamp:  100,
			Action:     "add",
			Username:   "username1",
			IP:         "127.0.0.1",
			ObjectType: "api_key",
			ObjectName: "123",
			ObjectData: objectData,
			Role:       "role2",
			InstanceID: "instance1",
		},
	}

	data, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *Searcher) SearchLogEvents(filters *eventsearcher.LogEventSearch) ([]byte, error) {
	if filters.StartTimestamp < 0 {
		return nil, errNotSupported
	}

	results := []logEvent{
		{
			ID:         "1",
			Timestamp:  100,
			Event:      1,
			Protocol:   "SSH",
			IP:         "127.0.1.1",
			Message:    "Invalid credentials",
			Role:       "role3",
			InstanceID: "instance2",
		},
	}

	data, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: eventsearcher.Handshake,
		Plugins: map[string]plugin.Plugin{
			eventsearcher.PluginName: &eventsearcher.Plugin{Impl: &Searcher{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
