package sftpd

import (
	"io"
	"net"

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
)

type subsystemChannel struct {
	reader io.Reader
	writer io.Writer
}

func (s *subsystemChannel) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *subsystemChannel) Write(p []byte) (int, error) {
	return s.writer.Write(p)
}

func (s *subsystemChannel) Close() error {
	return nil
}

func newSubsystemChannel(reader io.Reader, writer io.Writer) *subsystemChannel {
	return &subsystemChannel{
		reader: reader,
		writer: writer,
	}
}

// ServeSubSystemConnection handles a connection as SSH subsystem
func ServeSubSystemConnection(user dataprovider.User, connectionID string, reader io.Reader, writer io.Writer) error {
	fs, err := user.GetFilesystem(connectionID)
	if err != nil {
		return err
	}
	fs.CheckRootPath(user.Username, user.GetUID(), user.GetGID())
	dataprovider.UpdateLastLogin(user) //nolint:errcheck

	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolSFTP, user, fs),
		ClientVersion:  "",
		RemoteAddr:     &net.IPAddr{},
		channel:        newSubsystemChannel(reader, writer),
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	server := sftp.NewRequestServer(connection.channel, sftp.Handlers{
		FileGet:  connection,
		FilePut:  connection,
		FileCmd:  connection,
		FileList: connection,
	}, sftp.WithRSAllocator())

	defer server.Close()
	return server.Serve()
}
