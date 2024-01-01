// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package sftpd

import (
	"io"
	"net"

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
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
func ServeSubSystemConnection(user *dataprovider.User, connectionID string, reader io.Reader, writer io.Writer) error {
	err := user.CheckFsRoot(connectionID)
	if err != nil {
		errClose := user.CloseFs()
		logger.Warn(logSender, connectionID, "unable to check fs root: %v close fs error: %v", err, errClose)
		return err
	}

	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connectionID, common.ProtocolSFTP, "", "", *user),
		ClientVersion:  "",
		RemoteAddr:     &net.IPAddr{},
		LocalAddr:      &net.IPAddr{},
		channel:        newSubsystemChannel(reader, writer),
	}
	err = common.Connections.Add(connection)
	if err != nil {
		errClose := user.CloseFs()
		logger.Warn(logSender, connectionID, "unable to add connection: %v close fs error: %v", err, errClose)
		return err
	}
	defer common.Connections.Remove(connection.GetID())

	dataprovider.UpdateLastLogin(user)
	sftp.SetSFTPExtensions(sftpExtensions...) //nolint:errcheck
	server := sftp.NewRequestServer(connection.channel, sftp.Handlers{
		FileGet:  connection,
		FilePut:  connection,
		FileCmd:  connection,
		FileList: connection,
	}, sftp.WithRSAllocator())

	defer server.Close()
	return server.Serve()
}
