// Copyright 2023 Vibtree, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"errors"
	"maps"
	"strings"

	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vibtreeofficial/protocol/media-router"
	"github.com/vibtreeofficial/protocol/logger"
	"github.com/vibtreeofficial/protocol/utils"
)

type RoomConfiguration media_router.RoomConfiguration

var tokenMarshaler = protojson.MarshalOptions{
	EmitDefaultValues: false,
}

var ErrSensitiveCredentials = errors.New("room configuration should not contain sensitive credentials")

func (c *RoomConfiguration) Clone() *RoomConfiguration {
	if c == nil {
		return nil
	}
	return (*RoomConfiguration)(utils.CloneProto((*media_router.RoomConfiguration)(c)))
}

func (c *RoomConfiguration) MarshalJSON() ([]byte, error) {
	return tokenMarshaler.Marshal((*media_router.RoomConfiguration)(c))
}

func (c *RoomConfiguration) UnmarshalJSON(data []byte) error {
	return protojson.Unmarshal(data, (*media_router.RoomConfiguration)(c))
}

// CheckCredentials checks if the room configuration contains sensitive credentials
// and returns an error if it does.
//
// This is used to prevent sensitive credentials from being leaked to the client.
// It is not used to validate the credentials themselves, as that is done by the
// egress service.
func (c *RoomConfiguration) CheckCredentials() error {
	if c.Egress == nil {
		return nil
	}

	if c.Egress.Participant != nil {
		for _, output := range c.Egress.Participant.FileOutputs {
			if err := checkOutputForCredentials(output.Output); err != nil {
				return err
			}
		}
		for _, output := range c.Egress.Participant.SegmentOutputs {
			if err := checkOutputForCredentials(output.Output); err != nil {
				return err
			}
		}
	}
	if c.Egress.Room != nil {
		for _, output := range c.Egress.Room.FileOutputs {
			if err := checkOutputForCredentials(output.Output); err != nil {
				return err
			}
		}
		for _, output := range c.Egress.Room.SegmentOutputs {
			if err := checkOutputForCredentials(output.Output); err != nil {
				return err
			}
		}
		for _, output := range c.Egress.Room.ImageOutputs {
			if err := checkOutputForCredentials(output.Output); err != nil {
				return err
			}
		}
		if len(c.Egress.Room.StreamOutputs) > 0 {
			// do not leak stream key
			return ErrSensitiveCredentials
		}
	}
	if c.Egress.Tracks != nil {
		if err := checkOutputForCredentials(c.Egress.Tracks.Output); err != nil {
			return err
		}
	}
	return nil
}

func checkOutputForCredentials(output any) error {
	if output == nil {
		return nil
	}

	switch msg := output.(type) {
	case *media_router.EncodedFileOutput_S3:
		if msg.S3.Secret != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.SegmentedFileOutput_S3:
		if msg.S3.Secret != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.AutoTrackEgress_S3:
		if msg.S3.Secret != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.EncodedFileOutput_Gcp:
		if msg.Gcp.Credentials != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.SegmentedFileOutput_Gcp:
		if msg.Gcp.Credentials != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.AutoTrackEgress_Gcp:
		if msg.Gcp.Credentials != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.EncodedFileOutput_Azure:
		if msg.Azure.AccountKey != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.SegmentedFileOutput_Azure:
		if msg.Azure.AccountKey != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.AutoTrackEgress_Azure:
		if msg.Azure.AccountKey != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.EncodedFileOutput_AliOSS:
		if msg.AliOSS.Secret != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.SegmentedFileOutput_AliOSS:
		if msg.AliOSS.Secret != "" {
			return ErrSensitiveCredentials
		}
	case *media_router.AutoTrackEgress_AliOSS:
		if msg.AliOSS.Secret != "" {
			return ErrSensitiveCredentials
		}
	}
	return nil
}

type ClaimGrants struct {
	Identity  string          `json:"identity,omitempty"`
	Name      string          `json:"name,omitempty"`
	Kind      string          `json:"kind,omitempty"`
	Video     *VideoGrant     `json:"video,omitempty"`
	SIP       *SIPGrant       `json:"sip,omitempty"`
	Agent     *AgentGrant     `json:"agent,omitempty"`
	Inference *InferenceGrant `json:"inference,omitempty"`
	// Room configuration to use if this participant initiates the room
	RoomConfig *RoomConfiguration `json:"roomConfig,omitempty"`
	// Cloud-only, config preset to use
	// when both room and roomPreset are set, parameters in room overrides the preset
	RoomPreset string `json:"roomPreset,omitempty"`
	// for verifying integrity of the message body
	Sha256   string `json:"sha256,omitempty"`
	Metadata string `json:"metadata,omitempty"`
	// Key/value attributes to attach to the participant
	Attributes map[string]string `json:"attributes,omitempty"`
}

func (c *ClaimGrants) SetParticipantKind(kind media_router.ParticipantInfo_Kind) {
	c.Kind = kindFromProto(kind)
}

func (c *ClaimGrants) GetParticipantKind() media_router.ParticipantInfo_Kind {
	return kindToProto(c.Kind)
}

func (c *ClaimGrants) GetRoomConfiguration() *media_router.RoomConfiguration {
	if c.RoomConfig == nil {
		return nil
	}
	return (*media_router.RoomConfiguration)(c.RoomConfig)
}

func (c *ClaimGrants) Clone() *ClaimGrants {
	if c == nil {
		return nil
	}

	clone := *c
	clone.Video = c.Video.Clone()
	clone.SIP = c.SIP.Clone()
	clone.Agent = c.Agent.Clone()
	clone.Inference = c.Inference.Clone()
	clone.Attributes = maps.Clone(c.Attributes)
	clone.RoomConfig = c.RoomConfig.Clone()

	return &clone
}

func (c *ClaimGrants) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if c == nil {
		return nil
	}

	e.AddString("Identity", c.Identity)
	e.AddString("Kind", c.Kind)
	e.AddObject("Video", c.Video)
	e.AddObject("SIP", c.SIP)
	e.AddObject("Agent", c.Agent)
	e.AddObject("Inference", c.Inference)
	e.AddObject("RoomConfig", logger.Proto((*media_router.RoomConfiguration)(c.RoomConfig)))
	e.AddString("RoomPreset", c.RoomPreset)
	return nil
}

// -------------------------------------------------------------

type VideoGrant struct {
	// actions on rooms
	RoomCreate bool `json:"roomCreate,omitempty"`
	RoomList   bool `json:"roomList,omitempty"`
	RoomRecord bool `json:"roomRecord,omitempty"`

	// actions on a particular room
	RoomAdmin bool   `json:"roomAdmin,omitempty"`
	RoomJoin  bool   `json:"roomJoin,omitempty"`
	Room      string `json:"room,omitempty"`

	// permissions within a room, if none of the permissions are set explicitly
	// it will be granted with all publish and subscribe permissions
	CanPublish     *bool `json:"canPublish,omitempty"`
	CanSubscribe   *bool `json:"canSubscribe,omitempty"`
	CanPublishData *bool `json:"canPublishData,omitempty"`
	// TrackSource types that a participant may publish.
	// When set, it supersedes CanPublish. Only sources explicitly set here can be published
	CanPublishSources []string `json:"canPublishSources,omitempty"` // keys keep track of each source
	// by default, a participant is not allowed to update its own metadata
	CanUpdateOwnMetadata *bool `json:"canUpdateOwnMetadata,omitempty"`

	// actions on ingresses
	IngressAdmin bool `json:"ingressAdmin,omitempty"` // applies to all ingress

	// participant is not visible to other participants
	Hidden bool `json:"hidden,omitempty"`
	// indicates to the room that current participant is a recorder
	Recorder bool `json:"recorder,omitempty"`
	// indicates that the holder can register as an Agent framework worker
	Agent bool `json:"agent,omitempty"`

	// if a participant can subscribe to metrics
	CanSubscribeMetrics *bool `json:"canSubscribeMetrics,omitempty"`

	// destination room which this participant can forward to
	DestinationRoom string `json:"destinationRoom,omitempty"`
}

func (v *VideoGrant) SetCanPublish(val bool) {
	v.CanPublish = &val
}

func (v *VideoGrant) SetCanPublishData(val bool) {
	v.CanPublishData = &val
}

func (v *VideoGrant) SetCanSubscribe(val bool) {
	v.CanSubscribe = &val
}

func (v *VideoGrant) SetCanPublishSources(sources []media_router.TrackSource) {
	v.CanPublishSources = make([]string, 0, len(sources))
	for _, s := range sources {
		v.CanPublishSources = append(v.CanPublishSources, sourceToString(s))
	}
}

func (v *VideoGrant) SetCanUpdateOwnMetadata(val bool) {
	v.CanUpdateOwnMetadata = &val
}

func (v *VideoGrant) SetCanSubscribeMetrics(val bool) {
	v.CanSubscribeMetrics = &val
}

func (v *VideoGrant) GetCanPublish() bool {
	if v.CanPublish == nil {
		return true
	}
	return *v.CanPublish
}

func (v *VideoGrant) GetCanPublishSource(source media_router.TrackSource) bool {
	if !v.GetCanPublish() {
		return false
	}
	// don't differentiate between nil and unset, since that distinction doesn't survive serialization
	if len(v.CanPublishSources) == 0 {
		return true
	}
	sourceStr := sourceToString(source)
	for _, s := range v.CanPublishSources {
		if s == sourceStr {
			return true
		}
	}
	return false
}

func (v *VideoGrant) GetCanPublishSources() []media_router.TrackSource {
	if len(v.CanPublishSources) == 0 {
		return nil
	}

	sources := make([]media_router.TrackSource, 0, len(v.CanPublishSources))
	for _, s := range v.CanPublishSources {
		sources = append(sources, sourceToProto(s))
	}
	return sources
}

func (v *VideoGrant) GetCanPublishData() bool {
	if v.CanPublishData == nil {
		return v.GetCanPublish()
	}
	return *v.CanPublishData
}

func (v *VideoGrant) GetCanSubscribe() bool {
	if v.CanSubscribe == nil {
		return true
	}
	return *v.CanSubscribe
}

func (v *VideoGrant) GetCanUpdateOwnMetadata() bool {
	if v.CanUpdateOwnMetadata == nil {
		return false
	}
	return *v.CanUpdateOwnMetadata
}

func (v *VideoGrant) GetCanSubscribeMetrics() bool {
	if v.CanSubscribeMetrics == nil {
		return false
	}
	return *v.CanSubscribeMetrics
}

func (v *VideoGrant) MatchesPermission(permission *media_router.ParticipantPermission) bool {
	if permission == nil {
		return false
	}

	if v.GetCanPublish() != permission.CanPublish {
		return false
	}
	if v.GetCanPublishData() != permission.CanPublishData {
		return false
	}
	if v.GetCanSubscribe() != permission.CanSubscribe {
		return false
	}
	if v.GetCanUpdateOwnMetadata() != permission.CanUpdateMetadata {
		return false
	}
	if v.Hidden != permission.Hidden {
		return false
	}
	if v.Recorder != permission.Recorder {
		return false
	}
	if v.Agent != permission.Agent {
		return false
	}
	if !slices.Equal(v.GetCanPublishSources(), permission.CanPublishSources) {
		return false
	}
	if v.GetCanSubscribeMetrics() != permission.CanSubscribeMetrics {
		return false
	}

	return true
}

func (v *VideoGrant) UpdateFromPermission(permission *media_router.ParticipantPermission) {
	if permission == nil {
		return
	}

	v.SetCanPublish(permission.CanPublish)
	v.SetCanPublishData(permission.CanPublishData)
	v.SetCanPublishSources(permission.CanPublishSources)
	v.SetCanSubscribe(permission.CanSubscribe)
	v.SetCanUpdateOwnMetadata(permission.CanUpdateMetadata)
	v.Hidden = permission.Hidden
	v.Recorder = permission.Recorder
	v.Agent = permission.Agent
	v.SetCanSubscribeMetrics(permission.CanSubscribeMetrics)
}

func (v *VideoGrant) ToPermission() *media_router.ParticipantPermission {
	return &media_router.ParticipantPermission{
		CanPublish:          v.GetCanPublish(),
		CanPublishData:      v.GetCanPublishData(),
		CanSubscribe:        v.GetCanSubscribe(),
		CanPublishSources:   v.GetCanPublishSources(),
		CanUpdateMetadata:   v.GetCanUpdateOwnMetadata(),
		Hidden:              v.Hidden,
		Recorder:            v.Recorder,
		Agent:               v.Agent,
		CanSubscribeMetrics: v.GetCanSubscribeMetrics(),
	}
}

func (v *VideoGrant) Clone() *VideoGrant {
	if v == nil {
		return nil
	}

	clone := *v

	if v.CanPublish != nil {
		canPublish := *v.CanPublish
		clone.CanPublish = &canPublish
	}

	if v.CanSubscribe != nil {
		canSubscribe := *v.CanSubscribe
		clone.CanSubscribe = &canSubscribe
	}

	if v.CanPublishData != nil {
		canPublishData := *v.CanPublishData
		clone.CanPublishData = &canPublishData
	}

	if v.CanPublishSources != nil {
		clone.CanPublishSources = make([]string, len(v.CanPublishSources))
		copy(clone.CanPublishSources, v.CanPublishSources)
	}

	if v.CanUpdateOwnMetadata != nil {
		canUpdateOwnMetadata := *v.CanUpdateOwnMetadata
		clone.CanUpdateOwnMetadata = &canUpdateOwnMetadata
	}

	return &clone
}

func (v *VideoGrant) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if v == nil {
		return nil
	}

	logBoolPtr := func(prop string, val *bool) {
		if val == nil {
			e.AddString(prop, "not-set")
		} else {
			e.AddBool(prop, *val)
		}
	}

	logBoolPtr("RoomCreate", &v.RoomCreate)
	logBoolPtr("RoomList", &v.RoomList)
	logBoolPtr("RoomRecord", &v.RoomRecord)

	logBoolPtr("RoomAdmin", &v.RoomAdmin)
	logBoolPtr("RoomJoin", &v.RoomJoin)
	e.AddString("Room", v.Room)

	logBoolPtr("CanPublish", v.CanPublish)
	logBoolPtr("CanSubscribe", v.CanSubscribe)
	logBoolPtr("CanPublishData", v.CanPublishData)
	e.AddArray("CanPublishSources", logger.StringSlice(v.CanPublishSources))
	logBoolPtr("CanUpdateOwnMetadata", v.CanUpdateOwnMetadata)

	logBoolPtr("IngressAdmin", &v.IngressAdmin)

	logBoolPtr("Hidden", &v.Hidden)
	logBoolPtr("Recorder", &v.Recorder)
	logBoolPtr("Agent", &v.Agent)

	logBoolPtr("CanSubscribeMetrics", v.CanSubscribeMetrics)
	e.AddString("DestinationRoom", v.DestinationRoom)
	return nil
}

// ----------------------------------------------------------------

type SIPGrant struct {
	// Admin grants access to all SIP features.
	Admin bool `json:"admin,omitempty"`

	// Call allows making outbound SIP calls.
	Call bool `json:"call,omitempty"`
}

func (s *SIPGrant) Clone() *SIPGrant {
	if s == nil {
		return nil
	}

	clone := *s

	return &clone
}

func (s *SIPGrant) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if s == nil {
		return nil
	}

	e.AddBool("Admin", s.Admin)
	e.AddBool("Call", s.Call)
	return nil
}

// ------------------------------------------------------------------

// ------------------------------------------------------------------

type AgentGrant struct {
	// Admin grants to create/update/delete Cloud Agents.
	Admin bool `json:"admin,omitempty"`
}

func (s *AgentGrant) Clone() *AgentGrant {
	if s == nil {
		return nil
	}

	clone := *s

	return &clone
}

func (s *AgentGrant) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if s == nil {
		return nil
	}

	e.AddBool("Admin", s.Admin)
	return nil
}

// ------------------------------------------------------------------

type InferenceGrant struct {
	// Admin grants to all inference features (LLM, STT, TTS)
	Perform bool `json:"perform,omitempty"`
}

func (s *InferenceGrant) Clone() *InferenceGrant {
	if s == nil {
		return nil
	}

	clone := *s

	return &clone
}

func (s *InferenceGrant) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if s == nil {
		return nil
	}

	e.AddBool("Perform", s.Perform)
	return nil
}

// ------------------------------------------------------------------

func sourceToString(source media_router.TrackSource) string {
	return strings.ToLower(source.String())
}

func sourceToProto(sourceStr string) media_router.TrackSource {
	switch strings.ToLower(sourceStr) {
	case "camera":
		return media_router.TrackSource_CAMERA
	case "microphone":
		return media_router.TrackSource_MICROPHONE
	case "screen_share":
		return media_router.TrackSource_SCREEN_SHARE
	case "screen_share_audio":
		return media_router.TrackSource_SCREEN_SHARE_AUDIO
	default:
		return media_router.TrackSource_UNKNOWN
	}
}

func kindFromProto(source media_router.ParticipantInfo_Kind) string {
	return strings.ToLower(source.String())
}

func kindToProto(sourceStr string) media_router.ParticipantInfo_Kind {
	switch strings.ToLower(sourceStr) {
	case "", "standard":
		return media_router.ParticipantInfo_STANDARD
	case "ingress":
		return media_router.ParticipantInfo_INGRESS
	case "egress":
		return media_router.ParticipantInfo_EGRESS
	case "sip":
		return media_router.ParticipantInfo_SIP
	case "agent":
		return media_router.ParticipantInfo_AGENT
	default:
		return media_router.ParticipantInfo_STANDARD
	}
}
