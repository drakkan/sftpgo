package plugin

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

// NotifierConfig defines configuration parameters for notifiers plugins
type NotifierConfig struct {
	FsEvents          []string `json:"fs_events" mapstructure:"fs_events"`
	ProviderEvents    []string `json:"provider_events" mapstructure:"provider_events"`
	ProviderObjects   []string `json:"provider_objects" mapstructure:"provider_objects"`
	RetryMaxTime      int      `json:"retry_max_time" mapstructure:"retry_max_time"`
	RetryQueueMaxSize int      `json:"retry_queue_max_size" mapstructure:"retry_queue_max_size"`
}

func (c *NotifierConfig) hasActions() bool {
	if len(c.FsEvents) > 0 {
		return true
	}
	if len(c.ProviderEvents) > 0 && len(c.ProviderObjects) > 0 {
		return true
	}
	return false
}

type eventsQueue struct {
	sync.RWMutex
	fsEvents       []*notifier.FsEvent
	providerEvents []*notifier.ProviderEvent
}

func (q *eventsQueue) addFsEvent(event *notifier.FsEvent) {
	q.Lock()
	defer q.Unlock()

	q.fsEvents = append(q.fsEvents, event)
}

func (q *eventsQueue) addProviderEvent(event *notifier.ProviderEvent) {
	q.Lock()
	defer q.Unlock()

	q.providerEvents = append(q.providerEvents, event)
}

func (q *eventsQueue) popFsEvent() *notifier.FsEvent {
	q.Lock()
	defer q.Unlock()

	if len(q.fsEvents) == 0 {
		return nil
	}
	truncLen := len(q.fsEvents) - 1
	ev := q.fsEvents[truncLen]
	q.fsEvents[truncLen] = nil
	q.fsEvents = q.fsEvents[:truncLen]

	return ev
}

func (q *eventsQueue) popProviderEvent() *notifier.ProviderEvent {
	q.Lock()
	defer q.Unlock()

	if len(q.providerEvents) == 0 {
		return nil
	}
	truncLen := len(q.providerEvents) - 1
	ev := q.providerEvents[truncLen]
	q.providerEvents[truncLen] = nil
	q.providerEvents = q.providerEvents[:truncLen]

	return ev
}

func (q *eventsQueue) getSize() int {
	q.RLock()
	defer q.RUnlock()

	return len(q.providerEvents) + len(q.fsEvents)
}

type notifierPlugin struct {
	config   Config
	notifier notifier.Notifier
	client   *plugin.Client
	queue    *eventsQueue
}

func newNotifierPlugin(config Config) (*notifierPlugin, error) {
	p := &notifierPlugin{
		config: config,
		queue:  &eventsQueue{},
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create notifier plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *notifierPlugin) exited() bool {
	return p.client.Exited()
}

func (p *notifierPlugin) cleanup() {
	p.client.Kill()
}

func (p *notifierPlugin) initialize() error {
	killProcess(p.config.Cmd)
	logger.Debug(logSender, "", "create new notifier plugin %#v", p.config.Cmd)
	if !p.config.NotifierOptions.hasActions() {
		return fmt.Errorf("no actions defined for the notifier plugin %#v", p.config.Cmd)
	}
	var secureConfig *plugin.SecureConfig
	if p.config.SHA256Sum != "" {
		secureConfig.Checksum = []byte(p.config.SHA256Sum)
		secureConfig.Hash = sha256.New()
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: notifier.Handshake,
		Plugins:         notifier.PluginMap,
		Cmd:             exec.Command(p.config.Cmd, p.config.Args...),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, notifier.PluginName),
				Level:       pluginsLogLevel,
				DisableTime: true,
			}),
		},
	})
	rpcClient, err := client.Client()
	if err != nil {
		logger.Debug(logSender, "", "unable to get rpc client for plugin %#v: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(notifier.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %#v: %v",
			notifier.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.notifier = raw.(notifier.Notifier)

	return nil
}

func (p *notifierPlugin) canQueueEvent(timestamp int64) bool {
	if p.config.NotifierOptions.RetryMaxTime == 0 {
		return false
	}
	if time.Now().After(time.Unix(0, timestamp).Add(time.Duration(p.config.NotifierOptions.RetryMaxTime) * time.Second)) {
		logger.Warn(logSender, "", "dropping too late event for plugin %v, event timestamp: %v",
			p.config.Cmd, time.Unix(0, timestamp))
		return false
	}
	if p.config.NotifierOptions.RetryQueueMaxSize > 0 {
		return p.queue.getSize() < p.config.NotifierOptions.RetryQueueMaxSize
	}
	return true
}

func (p *notifierPlugin) notifyFsAction(event *notifier.FsEvent) {
	if !util.IsStringInSlice(event.Action, p.config.NotifierOptions.FsEvents) {
		return
	}

	go func() {
		p.sendFsEvent(event)
	}()
}

func (p *notifierPlugin) notifyProviderAction(event *notifier.ProviderEvent, object Renderer) {
	if !util.IsStringInSlice(event.Action, p.config.NotifierOptions.ProviderEvents) ||
		!util.IsStringInSlice(event.ObjectType, p.config.NotifierOptions.ProviderObjects) {
		return
	}

	go func() {
		objectAsJSON, err := object.RenderAsJSON(event.Action != "delete")
		if err != nil {
			logger.Warn(logSender, "", "unable to render user as json for action %v: %v", event.Action, err)
			return
		}
		event.ObjectData = objectAsJSON
		p.sendProviderEvent(event)
	}()
}

func (p *notifierPlugin) sendFsEvent(event *notifier.FsEvent) {
	if err := p.notifier.NotifyFsEvent(event); err != nil {
		logger.Warn(logSender, "", "unable to send fs action notification to plugin %v: %v", p.config.Cmd, err)
		if p.canQueueEvent(event.Timestamp) {
			p.queue.addFsEvent(event)
		}
	}
}

func (p *notifierPlugin) sendProviderEvent(event *notifier.ProviderEvent) {
	if err := p.notifier.NotifyProviderEvent(event); err != nil {
		logger.Warn(logSender, "", "unable to send user action notification to plugin %v: %v", p.config.Cmd, err)
		if p.canQueueEvent(event.Timestamp) {
			p.queue.addProviderEvent(event)
		}
	}
}

func (p *notifierPlugin) sendQueuedEvents() {
	queueSize := p.queue.getSize()
	if queueSize == 0 {
		return
	}
	logger.Debug(logSender, "", "check queued events for notifier %#v, events size: %v", p.config.Cmd, queueSize)
	fsEv := p.queue.popFsEvent()
	for fsEv != nil {
		go func(ev *notifier.FsEvent) {
			p.sendFsEvent(ev)
		}(fsEv)
		fsEv = p.queue.popFsEvent()
	}

	providerEv := p.queue.popProviderEvent()
	for providerEv != nil {
		go func(ev *notifier.ProviderEvent) {
			p.sendProviderEvent(ev)
		}(providerEv)
		providerEv = p.queue.popProviderEvent()
	}
	logger.Debug(logSender, "", "queued events sent for notifier %#v, new events size: %v", p.config.Cmd, p.queue.getSize())
}
