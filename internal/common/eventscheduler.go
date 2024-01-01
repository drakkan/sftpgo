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

package common

import (
	"time"

	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	eventScheduler *cron.Cron
)

func stopEventScheduler() {
	if eventScheduler != nil {
		eventScheduler.Stop()
		eventScheduler = nil
	}
}

func startEventScheduler() {
	stopEventScheduler()

	eventScheduler = cron.New(cron.WithLocation(time.UTC), cron.WithLogger(cron.DiscardLogger))
	eventManager.loadRules()
	_, err := eventScheduler.AddFunc("@every 10m", eventManager.loadRules)
	util.PanicOnError(err)
	eventScheduler.Start()
}
